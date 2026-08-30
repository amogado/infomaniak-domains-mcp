#!/usr/bin/env python3
"""Serveur MCP pour opérer ses domaines et ses zones DNS chez Infomaniak.

Stdlib uniquement : rien à installer, pas d'environnement virtuel, pas de
dépendance à tenir à jour. Un fichier, un `python3`.

Configuration, par variables d'environnement :

    INFOMANIAK_TOKEN       le jeton d'API
    INFOMANIAK_TOKEN_CMD   une commande qui l'imprime — à préférer : le secret
                           ne traîne alors dans aucun fichier de configuration.
                           Par exemple :
                             bw get password infomaniak-api --session "$BW_SESSION"
    INFOMANIAK_WRITE       « 1 » pour armer les outils qui écrivent. Absent,
                           le serveur est en lecture seule et le dit.
    INFOMANIAK_ACHAT       « 1 » pour armer l'enregistrement de domaine.
                           Distinct de INFOMANIAK_WRITE, exprès.
    INFOMANIAK_ACHAT_MAX   plafond en euros HT, 50 par défaut. Une valeur
                           illisible refuse au lieu de retomber sur le défaut.
    INFOMANIAK_ACCOUNT     le compte auquel ce serveur est **borné**. Voir plus
                           bas : c'est une frontière, pas un défaut.

Le jeton n'est jamais journalisé ni renvoyé dans une réponse d'outil.

Trois choix structurants, tenus exprès :

1. **Lecture seule par défaut.** Le DNS est un système vivant et visible de
   l'extérieur : un enregistrement de travers retire un site du réseau, et
   personne ne l'apprend avant que quelqu'un se plaigne. Écrire demande donc un
   armement explicite, pas un oubli de configuration.

2. **Dépenser est d'une autre nature qu'écrire.** Enregistrer un domaine a son
   propre armement, son propre plafond, et exige un montant que l'appelant a lu
   lui-même — jamais deviné par le serveur, sans quoi le contrôle
   `invalid_expected_amount` de l'API ne vaudrait rien. Le transfert, lui,
   n'est pas exposé du tout.

3. **`INFOMANIAK_ACCOUNT` est une frontière.** Un jeton voit souvent plusieurs
   comptes — les siens et ceux de ses clients. Épinglé, le serveur ne touche
   plus rien d'autre : l'argument `account` ne peut que répéter l'épinglage,
   jamais le franchir, et **tout domaine ou zone nommé est vérifié comme
   appartenant au compte**. Ce dernier point est le seul qui compte vraiment :
   les zones DNS sont adressées par nom, pas par compte, et c'est par là qu'on
   casserait le site de quelqu'un d'autre.
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "infomaniak-domains"
VERSION = "1.0.0"
PROTOCOL = "2025-06-18"
BASE = os.environ.get("INFOMANIAK_BASE", "https://api.infomaniak.com").rstrip("/")
TIMEOUT = 30

# L'API accepte 60 requêtes par minute, et ce plafond ne se relève pas. On le
# tient nous-mêmes : mieux vaut attendre une seconde que récolter un 429 au
# milieu d'une écriture de zone.
PLAFOND = int(os.environ.get("INFOMANIAK_RATE", "60"))
FENETRE = 60.0


def ecriture_armee():
    """Lue à chaque appel, pas au démarrage : on peut armer sans relancer."""
    return os.environ.get("INFOMANIAK_WRITE", "").strip() in ("1", "oui", "yes", "true")


class ErreurInfomaniak(Exception):
    """Une erreur montrable telle quelle à l'utilisateur."""


def jeton():
    """Le secret, cherché au plus tard et jamais gardé plus que nécessaire."""
    direct = os.environ.get("INFOMANIAK_TOKEN")
    if direct:
        return direct.strip()
    commande = os.environ.get("INFOMANIAK_TOKEN_CMD")
    if not commande:
        return ""
    try:
        out = subprocess.run(commande, shell=True, capture_output=True, text=True,
                             timeout=30)
        return out.stdout.strip()
    except Exception:
        return ""


class Cadence:
    """Une fenêtre glissante. Bloque le temps qu'il faut plutôt que d'essuyer
    un 429 — un refus au milieu d'une série d'écritures laisse la zone à
    moitié modifiée, ce qui est pire que lent."""

    def __init__(self, plafond, fenetre):
        self.plafond = max(1, plafond)
        self.fenetre = fenetre
        self.appels = []
        self.verrou = threading.Lock()

    def attendre(self, maintenant=None, dormir=time.sleep):
        with self.verrou:
            t = time.monotonic() if maintenant is None else maintenant
            self.appels = [a for a in self.appels if t - a < self.fenetre]
            if len(self.appels) >= self.plafond:
                repos = self.fenetre - (t - self.appels[0])
                if repos > 0:
                    dormir(repos)
                    t += repos
                    self.appels = [a for a in self.appels if t - a < self.fenetre]
            self.appels.append(t)


CADENCE = Cadence(PLAFOND, FENETRE)


def appel(chemin, params=None, corps=None, methode=None, _ouvre=None):
    """Un appel à l'API. Rend le contenu de `data`, ou lève ErreurInfomaniak
    avec une raison lisible — jamais une trace de pile dans le fil."""
    cle = jeton()
    if not cle:
        raise ErreurInfomaniak(
            "aucun jeton d'API. Renseigner INFOMANIAK_TOKEN, ou "
            "INFOMANIAK_TOKEN_CMD avec une commande qui l'imprime. Le jeton se "
            "crée sur https://manager.infomaniak.com/v3/infomaniak-api")

    url = BASE + chemin
    if params:
        propres = {k: v for k, v in params.items() if v is not None and v != ""}
        if propres:
            url += "?" + urllib.parse.urlencode(propres)

    data = None
    if corps is not None:
        data = json.dumps(corps).encode("utf-8")
    requete = urllib.request.Request(
        url, data=data, method=methode or ("POST" if data else "GET"))
    requete.add_header("Authorization", "Bearer " + cle)
    requete.add_header("Content-Type", "application/json")
    requete.add_header("Accept", "application/json")

    CADENCE.attendre()
    ouvre = _ouvre or urllib.request.urlopen
    try:
        with ouvre(requete, timeout=TIMEOUT) as reponse:
            brut = reponse.read().decode("utf-8", "replace")
            code = reponse.status
    except urllib.error.HTTPError as err:
        brut = err.read().decode("utf-8", "replace")
        code = err.code
    except urllib.error.URLError as err:
        raise ErreurInfomaniak("l'API Infomaniak est injoignable sur %s : %s"
                               % (BASE, err.reason))
    except OSError as err:
        raise ErreurInfomaniak("l'API Infomaniak est injoignable sur %s : %s"
                               % (BASE, err))

    if not brut.strip():
        if code >= 400:
            raise ErreurInfomaniak("l'API a répondu %d sans corps." % code)
        return None
    try:
        enveloppe = json.loads(brut)
    except ValueError:
        raise ErreurInfomaniak(
            "l'API a répondu autre chose que du JSON (HTTP %d). Début : %r"
            % (code, brut[:160]))

    if not isinstance(enveloppe, dict):
        raise ErreurInfomaniak("réponse inattendue : %r" % brut[:160])

    if enveloppe.get("result") != "success" or code >= 400:
        detail = enveloppe.get("error")
        if isinstance(detail, dict):
            raison = detail.get("description") or detail.get("code") or ""
            code_err = detail.get("code") or ""
            if code_err and code_err not in raison:
                raison = "%s (%s)" % (raison, code_err) if raison else code_err
        else:
            raison = str(detail or "")[:200]
        if code == 401:
            raise ErreurInfomaniak(
                "Infomaniak a refusé le jeton (401). Vérifier INFOMANIAK_TOKEN "
                "et ses portées : domain:read, dns:read, et dns:write pour "
                "modifier une zone.")
        if code == 403:
            raise ErreurInfomaniak(
                "Infomaniak a refusé l'accès (403) : %s. Le jeton est valide "
                "mais n'a pas la portée nécessaire pour ce geste." % (raison or "sans détail"))
        if code == 429:
            raise ErreurInfomaniak(
                "Infomaniak a répondu 429 : plafond de %d requêtes par minute "
                "atteint. Ce plafond ne se relève pas." % PLAFOND)
        raise ErreurInfomaniak("l'API a répondu %d : %s" % (code, raison or "sans détail"))

    return enveloppe.get("data")


# --------------------------------------------------------------------------
# comptes
# --------------------------------------------------------------------------

_COMPTE = {"valeur": None}


_DOMAINES_DU_COMPTE = {}


def compte_epingle():
    """Le compte auquel ce serveur est borné, ou None.

    `INFOMANIAK_ACCOUNT` n'est pas un défaut commode : c'est une **frontière**.
    Un jeton Infomaniak voit souvent plusieurs comptes — les siens et ceux de
    ses clients — et rien dans l'API ne rappelle lequel on visait. Épingler le
    compte fait de cette confusion une impossibilité plutôt qu'une vigilance.
    """
    return os.environ.get("INFOMANIAK_ACCOUNT", "").strip() or None


def domaines_du_compte():
    """Les noms de domaine du compte épinglé, retenus après la première lecture.

    Sert au contrôle d'appartenance. Sans lui, l'épinglage ne protégerait que
    les chemins qui portent un identifiant de compte — or les zones DNS sont
    adressées **par nom**, et c'est par là qu'on casse vraiment quelque chose.
    """
    epingle = compte_epingle()
    if not epingle:
        return None
    if epingle in _DOMAINES_DU_COMPTE:
        return _DOMAINES_DU_COMPTE[epingle]
    noms, page = [], 1
    while page <= 20:
        lot = appel("/2/domains/domains",
                    params={"account_id": epingle, "per_page": 100, "page": page}) or []
        noms += [d.get("customer_name") or d.get("name") for d in lot]
        if len(lot) < 100:
            break
        page += 1
    _DOMAINES_DU_COMPTE[epingle] = [n for n in noms if n]
    return _DOMAINES_DU_COMPTE[epingle]


def exige_appartenance(cible, quoi="ce nom"):
    """Refuse un domaine ou une zone qui ne relève pas du compte épinglé.

    La comparaison porte sur le **suffixe de domaine**, pas sur la chaîne :
    `interne.exemple.fr` relève de `exemple.fr`, mais `pasexemple.fr` non — et
    un test le vérifie, parce que c'est exactement le genre de garde qu'on
    écrit par mégarde avec un `endswith` nu.
    """
    epingle = compte_epingle()
    if not epingle:
        return
    nom = (cible or "").strip().lower().rstrip(".")
    for domaine in domaines_du_compte() or []:
        propre = str(domaine).strip().lower().rstrip(".")
        if propre and (nom == propre or nom.endswith("." + propre)):
            return
    raise ErreurInfomaniak(
        "%s (%r) ne relève pas du compte épinglé %s. Ce serveur est borné à ce "
        "compte par INFOMANIAK_ACCOUNT et ne touchera rien d'autre — ni en "
        "lecture, ni en écriture." % (quoi, cible, epingle))


def compte_par_defaut(donne=None):
    """L'identifiant de compte à employer. Certains chemins l'exigent — le
    contrôle de disponibilité, notamment, qui est indexé par compte parce que
    le prix dépend du contrat."""
    epingle = compte_epingle()
    if epingle:
        # L'argument ne franchit pas la frontière : il ne peut que la répéter.
        if donne and str(donne).strip() != epingle:
            raise ErreurInfomaniak(
                "compte %r demandé alors que ce serveur est épinglé sur %s. "
                "L'argument account ne peut pas franchir cette frontière ; pour "
                "viser un autre compte, il faut changer INFOMANIAK_ACCOUNT."
                % (str(donne).strip(), epingle))
        return epingle
    if donne:
        return donne
    if _COMPTE["valeur"]:
        return _COMPTE["valeur"]
    comptes = appel("/1/accounts") or []
    if not comptes:
        raise ErreurInfomaniak(
            "aucun compte visible avec ce jeton : impossible de deviner quel "
            "compte utiliser. Passer account, ou fixer INFOMANIAK_ACCOUNT.")

    # Un jeton peut voir plusieurs comptes — c'est le cas courant dès qu'on
    # gère les domaines de tiers. Prendre le premier serait tirer au sort
    # lequel sera facturé, et le tirage ne se verrait nulle part. Un contrôle
    # qui désigne une cible de dépense doit se fermer quand il ne sait pas.
    if len(comptes) > 1:
        liste = ", ".join(
            "%s (%s)" % (c.get("id") or c.get("account_id"), c.get("name") or "sans nom")
            for c in comptes)
        raise ErreurInfomaniak(
            "ce jeton voit plusieurs comptes et rien ne dit lequel employer : "
            "%s. Choisir explicitement — paramètre account, ou variable "
            "INFOMANIAK_ACCOUNT. Le serveur ne tranche pas à votre place : sur "
            "une commande, ce choix décide qui est facturé." % liste)

    seul = comptes[0]
    identifiant = seul.get("id") or seul.get("account_id")
    if identifiant is None:
        raise ErreurInfomaniak("le compte rendu par l'API n'a pas d'identifiant : %r"
                               % (seul,))
    _COMPTE["valeur"] = str(identifiant)
    return _COMPTE["valeur"]


# --------------------------------------------------------------------------
# l'achat — une classe à part
# --------------------------------------------------------------------------
#
# Commander un domaine dépense de l'argent et ne s'annule pas. Ce n'est donc
# pas une écriture de plus : c'est un geste d'une autre nature, avec son propre
# armement, son propre plafond et sa propre confirmation.
#
# Quatre garde-fous indépendants — il faut les franchir tous :
#
#   1. INFOMANIAK_ACHAT=1, **distinct** de INFOMANIAK_WRITE. Armer le DNS
#      n'arme pas la carte bancaire.
#   2. Un plafond en euros hors taxes, INFOMANIAK_ACHAT_MAX, 50 par défaut. Il
#      borne le dégât possible même quand tout le reste est armé.
#   3. Le montant attendu est obligatoire et **jamais deviné**. Le serveur
#      pourrait aller chercher le prix lui-même et le recopier dans la
#      commande — c'est précisément ce qu'il ne faut pas faire : le contrôle
#      `invalid_expected_amount` de l'API ne vaut que si le nombre vient de
#      quelqu'un qui l'a vu.
#   4. Une confirmation qui répète le nom du domaine, pour qu'une commande ne
#      puisse pas se tromper de cible.
#
# Et une conduite, qui n'est pas un garde-fou : **on ne rejoue jamais un achat
# dont l'issue est inconnue**. Un délai dépassé ne dit pas que la commande
# n'est pas partie.

ACHAT_MAX_DEFAUT = 50.0
PERIODE_MAX = 10


def achat_arme():
    return os.environ.get("INFOMANIAK_ACHAT", "").strip() in ("1", "oui", "yes", "true")


def plafond_achat():
    """Le plafond en euros hors taxes. Une valeur illisible **refuse** au lieu
    de retomber sur le défaut : un contrôle qui autorise une dépense doit se
    fermer quand il ne se comprend pas lui-même."""
    brut = os.environ.get("INFOMANIAK_ACHAT_MAX", "").strip()
    if not brut:
        return ACHAT_MAX_DEFAUT
    try:
        valeur = float(brut.replace(",", "."))
    except ValueError:
        raise ErreurInfomaniak(
            "INFOMANIAK_ACHAT_MAX vaut %r, qui n'est pas un nombre. Aucune "
            "commande n'est passée tant que le plafond est illisible." % brut)
    if valeur <= 0:
        raise ErreurInfomaniak(
            "INFOMANIAK_ACHAT_MAX vaut %s : un plafond nul ou négatif "
            "n'autorise aucune commande." % valeur)
    return valeur


def exige_ecriture(geste):
    if not ecriture_armee():
        raise ErreurInfomaniak(
            "le serveur est en lecture seule : %s n'a pas été fait. Pour "
            "l'autoriser, lancer le serveur avec INFOMANIAK_WRITE=1. C'est "
            "délibéré : une zone DNS est visible de tout le réseau, et une "
            "erreur d'écriture ne se voit qu'une fois le mal fait." % geste)


# --------------------------------------------------------------------------
# outils — lecture
# --------------------------------------------------------------------------

def outil_comptes(args):
    """Les comptes visibles avec ce jeton."""
    comptes = appel("/1/accounts") or []
    return {"comptes": comptes, "nombre": len(comptes)}


def outil_domaines(args):
    """Les domaines du compte. `search` filtre, `tld` restreint à une extension."""
    params = {
        "account_id": args.get("account") or compte_epingle(),
        "search": args.get("search"),
        "tld": args.get("tld"),
        "page": args.get("page"),
        "per_page": args.get("per_page") or 100,
    }
    domaines = appel("/2/domains/domains", params=params) or []
    return {"domaines": domaines, "nombre": len(domaines)}


def outil_domaine(args):
    """La fiche d'un domaine."""
    nom = (args.get("domain") or "").strip()
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain.")
    exige_appartenance(nom, "ce domaine")
    return appel("/2/domains/domains/" + urllib.parse.quote(nom, safe=""))


def outil_disponibilite(args):
    """Le domaine est-il libre, et à quel prix. C'est une lecture : elle
    n'engage rien et ne réserve rien."""
    nom = (args.get("domain") or "").strip().lower()
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain, par exemple « exemple.ch ».")
    if "." not in nom:
        raise ErreurInfomaniak(
            "« %s » n'a pas d'extension. Le contrôle porte sur un domaine "
            "complet, pas sur un radical." % nom)
    compte = compte_par_defaut(args.get("account"))
    corps = {"domain": nom, "with_option_prices": bool(args.get("with_option_prices"))}
    data = appel("/2/domains/accounts/%s/check" % urllib.parse.quote(str(compte), safe=""),
                 corps=corps, methode="POST")
    return resume_disponibilite(nom, data)


def resume_disponibilite(nom, data):
    """Dégager de la réponse ce sur quoi on décide, sans jeter le brut.

    Deux chiffres, pas un. Le prix affiché partout est celui de la **première
    période** — souvent promotionnel — tandis que le coût réel d'un domaine est
    son **renouvellement**, payé chaque année ensuite. Les rendre côte à côte
    est le seul moyen de ne pas comparer une promotion à un tarif plein.

    Et `is_premium` mérite son propre champ : un nom premium se facture parfois
    en centaines d'euros, sans que rien d'autre ne le signale.
    """
    if not isinstance(data, dict):
        return {"domaine": nom, "reponse": data}

    resume = {"domaine": nom,
              "libre": data.get("is_available"),
              "premium": data.get("is_premium"),
              "statut": data.get("status")}

    tarifs = ((data.get("action") or {}).get("pricing") or {})
    prix = tarifs.get("prices") or {}
    if tarifs.get("currency"):
        resume["devise"] = tarifs["currency"]
    inscription = prix.get("registration") or {}
    renouvellement = prix.get("renew") or {}
    if inscription.get("amount_excl_tax") is not None:
        resume["premiere_periode_ht"] = inscription["amount_excl_tax"]
        base = inscription.get("amount_base_excl_tax")
        if base is not None and base != inscription["amount_excl_tax"]:
            resume["prix_public_ht"] = base
    if renouvellement.get("amount_excl_tax") is not None:
        resume["renouvellement_ht"] = renouvellement["amount_excl_tax"]
    if tarifs.get("registration_periods"):
        resume["periodes_possibles"] = tarifs["registration_periods"]

    resume["reponse"] = data
    return resume


def outil_zones(args):
    """Les zones d'un domaine : la zone de base et les zones déléguées."""
    nom = (args.get("domain") or "").strip()
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain.")
    exige_appartenance(nom, "ce domaine")
    zones = appel("/2/domains/domains/%s/zones" % urllib.parse.quote(nom, safe="")) or []
    return {"zones": zones, "nombre": len(zones)}


def outil_enregistrements(args):
    """Les enregistrements DNS d'une zone."""
    zone = (args.get("zone") or "").strip()
    if not zone:
        raise ErreurInfomaniak("il faut une zone dans zone (le fqdn, par exemple « exemple.ch »).")
    exige_appartenance(zone, "cette zone")
    params = {"with": "records_description", "per_page": args.get("per_page") or 500,
              "page": args.get("page"), "search": args.get("search")}
    liste = appel("/2/zones/%s/records" % urllib.parse.quote(zone, safe=""),
                  params=params) or []
    type_voulu = (args.get("type") or "").strip().upper()
    if type_voulu:
        liste = [r for r in liste if str(r.get("type", "")).upper() == type_voulu]
    source_voulue = (args.get("source") or "").strip()
    if source_voulue:
        liste = [r for r in liste if str(r.get("source", "")) == source_voulue]
    return {"zone": zone, "enregistrements": liste, "nombre": len(liste)}


def outil_verifie_enregistrement(args):
    """L'enregistrement existe-t-il vraiment sur les serveurs de noms ? C'est la
    différence entre « écrit dans la zone » et « servi au réseau »."""
    zone = (args.get("zone") or "").strip()
    identifiant = args.get("record")
    if not zone or identifiant in (None, ""):
        raise ErreurInfomaniak("il faut zone et record (l'identifiant numérique).")
    exige_appartenance(zone, "cette zone")
    return appel("/2/zones/%s/records/%s/check"
                 % (urllib.parse.quote(zone, safe=""),
                    urllib.parse.quote(str(identifiant), safe="")))


def outil_dnssec(args):
    """L'état DNSSEC d'un domaine."""
    nom = (args.get("domain") or "").strip()
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain.")
    exige_appartenance(nom, "ce domaine")
    return appel("/2/domains/domains/%s/dnssec/check" % urllib.parse.quote(nom, safe=""))


# --------------------------------------------------------------------------
# outils — écriture (armés par INFOMANIAK_WRITE=1)
# --------------------------------------------------------------------------

TYPES = ("A", "AAAA", "CAA", "CNAME", "DNAME", "DS", "MX", "NS",
         "SMIMEA", "SRV", "SSHFP", "TLSA", "TXT")


def _ttl(valeur):
    ttl = int(valeur if valeur not in (None, "") else 3600)
    if not 60 <= ttl <= 86400:
        raise ErreurInfomaniak(
            "ttl doit tenir entre 60 et 86400 secondes ; reçu %d. C'est l'API "
            "qui l'impose, pas nous." % ttl)
    return ttl


def outil_ajoute_enregistrement(args):
    """Créer un enregistrement dans une zone."""
    zone = (args.get("zone") or "").strip()
    type_ = (args.get("type") or "").strip().upper()
    cible = args.get("target")
    if not zone:
        raise ErreurInfomaniak("il faut une zone dans zone.")
    if type_ not in TYPES:
        raise ErreurInfomaniak("type doit être l'un de : %s. Reçu %r."
                               % (", ".join(TYPES), args.get("type")))
    if cible in (None, ""):
        raise ErreurInfomaniak("il faut une cible dans target.")
    ttl = _ttl(args.get("ttl"))
    exige_ecriture("créer un %s dans %s" % (type_, zone))
    exige_appartenance(zone, "cette zone")
    corps = {"type": type_, "target": str(cible), "ttl": ttl}
    source = args.get("source")
    if source is not None:
        corps["source"] = source
    cree = appel("/2/zones/%s/records" % urllib.parse.quote(zone, safe=""),
                 params={"with": "records_description"}, corps=corps, methode="POST")
    return {"cree": cree}


def outil_modifie_enregistrement(args):
    """Modifier la cible ou le TTL d'un enregistrement. L'API ne permet pas d'en
    changer le type ni la source : pour ça, supprimer et recréer."""
    zone = (args.get("zone") or "").strip()
    identifiant = args.get("record")
    if not zone or identifiant in (None, ""):
        raise ErreurInfomaniak("il faut zone et record (l'identifiant numérique).")
    corps = {}
    if args.get("target") not in (None, ""):
        corps["target"] = str(args["target"])
    if args.get("ttl") not in (None, ""):
        corps["ttl"] = _ttl(args.get("ttl"))
    if not corps:
        raise ErreurInfomaniak("rien à modifier : donner target, ttl, ou les deux.")
    exige_ecriture("modifier l'enregistrement %s de %s" % (identifiant, zone))
    exige_appartenance(zone, "cette zone")
    modifie = appel("/2/zones/%s/records/%s"
                    % (urllib.parse.quote(zone, safe=""),
                       urllib.parse.quote(str(identifiant), safe="")),
                    params={"with": "records_description"}, corps=corps, methode="PUT")
    return {"modifie": modifie}


def outil_supprime_enregistrement(args):
    """Supprimer un enregistrement."""
    zone = (args.get("zone") or "").strip()
    identifiant = args.get("record")
    if not zone or identifiant in (None, ""):
        raise ErreurInfomaniak("il faut zone et record (l'identifiant numérique).")
    exige_ecriture("supprimer l'enregistrement %s de %s" % (identifiant, zone))
    exige_appartenance(zone, "cette zone")
    appel("/2/zones/%s/records/%s"
          % (urllib.parse.quote(zone, safe=""),
             urllib.parse.quote(str(identifiant), safe="")),
          methode="DELETE")
    return {"supprime": identifiant, "zone": zone}


def outil_contacts(args):
    """Les contacts déclarés du compte : propriétaire, administratif, technique,
    facturation. Leurs identifiants servent à renseigner une commande."""
    compte = compte_par_defaut(args.get("account"))
    liste = appel("/2/domains/accounts/%s/contacts"
                  % urllib.parse.quote(str(compte), safe="")) or []
    return {"contacts": liste, "nombre": len(liste)}


def outil_commande_domaine(args):
    """Enregistrer un domaine. Engage une dépense, et ne se défait pas.

    Rien n'est deviné ici. Le montant vient de l'appelant, pas d'un appel que ce
    serveur ferait à sa place : c'est ce qui donne sa valeur au contrôle
    `invalid_expected_amount` de l'API, qui rejette l'opération si le montant
    annoncé ne correspond pas au prix calculé.
    """
    nom = (args.get("domain") or "").strip().lower()
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain.")
    if "." not in nom:
        raise ErreurInfomaniak(
            "« %s » n'a pas d'extension : ce n'est pas un domaine enregistrable." % nom)

    # La cible d'abord : se tromper de nom est l'erreur la plus coûteuse,
    # puisqu'elle aboutit sans rien signaler.
    confirmation = (args.get("confirmation") or "").strip().lower()
    if confirmation != nom:
        raise ErreurInfomaniak(
            "confirmation doit répéter exactement le domaine visé. Attendu %r, "
            "reçu %r. Cette répétition existe pour qu'une opération ne puisse "
            "pas se tromper de nom." % (nom, args.get("confirmation")))

    # Le montant est fourni, jamais déduit.
    if args.get("amount_total_excl_tax") in (None, ""):
        raise ErreurInfomaniak(
            "il faut amount_total_excl_tax : le montant hors taxes attendu, en "
            "euros. Il n'est pas deviné — le lire avec l'outil disponibilite et "
            "le reporter ici. L'API rejette l'opération s'il ne correspond pas "
            "au prix calculé, et ce contrôle ne vaut que si le nombre a été vu.")
    try:
        montant = float(str(args["amount_total_excl_tax"]).replace(",", "."))
    except ValueError:
        raise ErreurInfomaniak("amount_total_excl_tax n'est pas un nombre : %r"
                               % args.get("amount_total_excl_tax"))
    if montant <= 0:
        raise ErreurInfomaniak(
            "amount_total_excl_tax vaut %s : un montant nul ou négatif ne "
            "correspond à aucune opération réelle." % montant)

    periode = args.get("registration_period")
    periode = 1 if periode in (None, "") else periode
    try:
        periode = int(periode)
    except (TypeError, ValueError):
        raise ErreurInfomaniak("registration_period n'est pas un entier : %r" % periode)
    if not 1 <= periode <= PERIODE_MAX:
        raise ErreurInfomaniak(
            "registration_period doit tenir entre 1 et %d ans ; reçu %d. Une "
            "période longue multiplie la dépense d'autant." % (PERIODE_MAX, periode))

    # L'armement, propre à cette classe de geste.
    if not achat_arme():
        raise ErreurInfomaniak(
            "non armé : %s n'a pas été enregistré, et aucune requête n'est "
            "partie. Pour l'autoriser, lancer le serveur avec "
            "INFOMANIAK_ACHAT=1 — un armement distinct de INFOMANIAK_WRITE, "
            "exprès : autoriser la modification d'une zone DNS n'autorise pas "
            "une dépense." % nom)

    # Le plafond porte sur le total, période comprise — sinon dix ans à 40 €
    # passeraient sous un plafond de 50.
    plafond = plafond_achat()
    total = montant * periode
    if total > plafond:
        raise ErreurInfomaniak(
            "refusé : %.2f € HT (%.2f × %d an(s)) dépasse le plafond de "
            "%.2f €. Relever INFOMANIAK_ACHAT_MAX si le montant est voulu — en "
            "le décidant, pas en le subissant." % (total, montant, periode, plafond))

    compte = compte_par_defaut(args.get("account"))
    corps = {"domain": nom, "amount_total_excl_tax": montant,
             "registration_period": periode}
    for facultatif in ("contacts", "additional_fields", "with_options", "address"):
        if args.get(facultatif) not in (None, ""):
            corps[facultatif] = args[facultatif]

    chemin = "/2/domains/accounts/%s/create" % urllib.parse.quote(str(compte), safe="")
    try:
        data = appel(chemin, corps=corps, methode="POST")
    except ErreurInfomaniak as err:
        # Un échec de *transport* — injoignable, délai dépassé — ne dit pas que
        # l'opération n'a pas abouti. C'est le seul endroit du serveur où
        # l'ambiguïté coûte de l'argent, donc le seul où on la nomme au lieu de
        # rendre l'erreur telle quelle. Surtout : ne pas rejouer.
        if "injoignable" in str(err):
            raise ErreurInfomaniak(
                "ISSUE INDÉTERMINÉE pour %s : %s. La requête a pu partir et "
                "aboutir. NE PAS REJOUER — vérifier d'abord avec l'outil "
                "« domaines », ou dans le manager, si le domaine figure "
                "désormais au compte %s." % (nom, err, compte))
        raise

    # Le domaine vient d'entrer dans le compte : la liste d'appartenance
    # retenue ne le connaît pas encore, et le refuserait au geste suivant.
    _DOMAINES_DU_COMPTE.pop(str(compte), None)
    return {"domaine": nom, "montant_ht": montant, "annees": periode,
            "compte": str(compte), "reponse": data}


def outil_serveurs_de_noms(args):
    """Changer les serveurs de noms d'un domaine. Geste lourd : il déplace
    l'autorité entière du domaine, et la propagation prend des heures."""
    nom = (args.get("domain") or "").strip()
    serveurs = args.get("nameservers")
    if not nom:
        raise ErreurInfomaniak("il faut un domaine dans domain.")
    if not isinstance(serveurs, list) or not serveurs:
        raise ErreurInfomaniak("nameservers doit être une liste non vide de serveurs de noms.")
    if len(serveurs) < 2:
        raise ErreurInfomaniak(
            "il faut au moins deux serveurs de noms : avec un seul, la moindre "
            "panne rend le domaine introuvable.")
    exige_ecriture("remplacer les serveurs de noms de %s" % nom)
    exige_appartenance(nom, "ce domaine")
    return appel("/2/domains/domains/%s/nameservers" % urllib.parse.quote(nom, safe=""),
                 corps={"nameservers": [str(s) for s in serveurs]}, methode="PUT")


# --------------------------------------------------------------------------
# table des outils
# --------------------------------------------------------------------------

def _o(nom, description, proprietes, requis, handler, ecrit=False, depense=False):
    marque = "[DÉPENSE] " if depense else ("[écrit] " if ecrit else "")
    titre = marque + description
    return {
        "name": nom,
        "description": titre,
        "inputSchema": {"type": "object", "properties": proprietes,
                        "required": requis},
        "handler": handler,
    }


S = {"type": "string"}
E = {"type": "integer"}
B = {"type": "boolean"}

TOOLS = [
    _o("comptes", "Les comptes Infomaniak visibles avec ce jeton.",
       {}, [], outil_comptes),

    _o("domaines", "Les domaines du compte, filtrables par recherche ou extension.",
       {"search": dict(S, description="filtre sur le nom"),
        "tld": dict(S, description="restreint à une extension, par exemple « ch »"),
        "account": dict(S, description="identifiant de compte ; sinon le compte par défaut"),
        "page": E, "per_page": E},
       [], outil_domaines),

    _o("domaine", "La fiche d'un domaine : expiration, statut, serveurs de noms.",
       {"domain": dict(S, description="le domaine, par exemple « exemple.ch »")},
       ["domain"], outil_domaine),

    _o("disponibilite",
       "Ce domaine est-il libre, et à quel prix. N'engage rien et ne réserve "
       "rien : aucun outil de ce serveur ne peut acheter un domaine.",
       {"domain": dict(S, description="le domaine complet, extension comprise"),
        "with_option_prices": dict(B, description="inclure le prix des options"),
        "account": dict(S, description="identifiant de compte ; sinon le compte par défaut")},
       ["domain"], outil_disponibilite),

    _o("zones", "Les zones DNS d'un domaine.",
       {"domain": S}, ["domain"], outil_zones),

    _o("enregistrements", "Les enregistrements DNS d'une zone, filtrables par type ou source.",
       {"zone": dict(S, description="le fqdn de la zone"),
        "type": dict(S, description="A, AAAA, CNAME, MX, TXT…"),
        "source": dict(S, description="filtre exact sur la source"),
        "search": S, "page": E, "per_page": E},
       ["zone"], outil_enregistrements),

    _o("verifie_enregistrement",
       "L'enregistrement est-il vraiment servi par les serveurs de noms — ce "
       "qui n'est pas la même chose qu'écrit dans la zone.",
       {"zone": S, "record": dict(E, description="l'identifiant numérique")},
       ["zone", "record"], outil_verifie_enregistrement),

    _o("dnssec", "L'état DNSSEC d'un domaine.",
       {"domain": S}, ["domain"], outil_dnssec),

    _o("ajoute_enregistrement", "Créer un enregistrement DNS.",
       {"zone": S,
        "type": dict(S, enum=list(TYPES)),
        "source": dict(S, description="le sous-domaine, vide ou « . » pour la racine"),
        "target": dict(S, description="la cible, par exemple « 95.217.21.250 »"),
        "ttl": dict(E, description="entre 60 et 86400 ; 3600 par défaut")},
       ["zone", "type", "target"], outil_ajoute_enregistrement, ecrit=True),

    _o("modifie_enregistrement", "Modifier la cible ou le TTL d'un enregistrement.",
       {"zone": S, "record": E, "target": S, "ttl": E},
       ["zone", "record"], outil_modifie_enregistrement, ecrit=True),

    _o("supprime_enregistrement", "Supprimer un enregistrement DNS.",
       {"zone": S, "record": E},
       ["zone", "record"], outil_supprime_enregistrement, ecrit=True),

    _o("contacts",
       "Les contacts du compte : propriétaire, administratif, technique, "
       "facturation. Leurs identifiants servent à renseigner une commande.",
       {"account": S}, [], outil_contacts),

    _o("commande_domaine",
       "Enregistrer un domaine. Engage une dépense qui ne se défait pas. Exige "
       "un armement propre (INFOMANIAK_ACHAT=1), reste sous un plafond, et "
       "n'accepte que le montant que l'appelant a lu lui-même avec "
       "« disponibilite » — il n'est jamais deviné.",
       {"domain": dict(S, description="le domaine à enregistrer"),
        "confirmation": dict(S, description="répéter exactement le même domaine"),
        "amount_total_excl_tax": {"type": "number",
                                  "description": "le montant HT attendu, lu avec disponibilite"},
        "registration_period": dict(E, description="en années, 1 par défaut, 10 au plus"),
        "contacts": {"type": "object", "description": "identifiants owner/admin/tech/billing"},
        "additional_fields": {"type": "array", "items": S,
                              "description": "champs exigés par certaines extensions"},
        "with_options": {"type": "object", "description": "options payantes"},
        "address": dict(E, description="identifiant d'adresse de facturation"),
        "account": S},
       ["domain", "confirmation", "amount_total_excl_tax"],
       outil_commande_domaine, depense=True),

    _o("serveurs_de_noms",
       "Remplacer les serveurs de noms d'un domaine. Déplace l'autorité entière ; "
       "la propagation prend des heures.",
       {"domain": S, "nameservers": {"type": "array", "items": S,
                                     "description": "au moins deux"}},
       ["domain", "nameservers"], outil_serveurs_de_noms, ecrit=True),
]

BY_NAME = {t["name"]: t for t in TOOLS}


# --------------------------------------------------------------------------
# protocole
# --------------------------------------------------------------------------

def result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def instructions():
    etat = ("Les outils d'écriture sont armés."
            if ecriture_armee() else
            "Le serveur est en LECTURE SEULE : les outils marqués [écrit] "
            "refuseront d'agir tant que INFOMANIAK_WRITE=1 n'est pas posé.")
    if achat_arme():
        depense = (" L'enregistrement de domaine est ARMÉ : « commande_domaine » "
                   "engagera une dépense réelle. Le montant doit être lu avec "
                   "« disponibilite » et reporté tel quel — ne jamais l'inventer, "
                   "l'API le vérifie. Ne jamais rejouer un appel dont l'issue "
                   "est inconnue.")
    else:
        depense = (" L'enregistrement de domaine n'est PAS armé : "
                   "« commande_domaine » refusera, sans qu'aucune requête ne "
                   "parte. Il faut INFOMANIAK_ACHAT=1, distinct de "
                   "INFOMANIAK_WRITE.")
    return ("Opère les domaines et les zones DNS d'un compte Infomaniak : "
            "lister les domaines, contrôler la disponibilité et le prix d'un "
            "nom, lire et modifier les enregistrements DNS, et enregistrer un "
            "domaine. " + etat + depense +
            " Aucun outil ne transfère de domaine.")


def handle(message):
    """Rend la réponse à envoyer, ou None pour une notification."""
    methode = message.get("method")
    mid = message.get("id")
    params = message.get("params") or {}

    if methode == "initialize":
        demande = params.get("protocolVersion")
        return {"protocolVersion": demande if isinstance(demande, str) and demande else PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": NAME, "version": VERSION},
                "instructions": instructions()}

    if methode in ("notifications/initialized", "notifications/cancelled"):
        return None

    if methode == "ping":
        return {}

    if methode == "tools/list":
        return {"tools": [{k: v for k, v in t.items() if k != "handler"} for t in TOOLS]}

    if methode == "tools/call":
        nom = params.get("name")
        outil = BY_NAME.get(nom)
        if not outil:
            return result("Cet outil n'existe pas : %r. Outils disponibles : %s."
                          % (nom, ", ".join(sorted(BY_NAME))), True)
        args = params.get("arguments")
        args = args if isinstance(args, dict) else {}
        try:
            return result(json.dumps(outil["handler"](args), ensure_ascii=False, indent=1))
        except ErreurInfomaniak as err:
            return result(str(err), True)
        except Exception as err:                     # noqa: BLE001
            # Un outil qui plante ne doit pas emporter le serveur : le client
            # perdrait la session entière pour une erreur d'un seul appel.
            return result("%s a échoué : %s: %s" % (nom, type(err).__name__, err), True)

    if mid is None:
        return None
    raise ErreurInfomaniak("méthode inconnue : %s" % methode)


def main():
    sortie = sys.stdout
    for ligne in sys.stdin:
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            message = json.loads(ligne)
        except ValueError:
            continue
        mid = message.get("id")
        try:
            charge = handle(message)
        except ErreurInfomaniak as err:
            if mid is not None:
                sortie.write(json.dumps({"jsonrpc": "2.0", "id": mid,
                                         "error": {"code": -32601, "message": str(err)}}) + "\n")
                sortie.flush()
            continue
        if mid is None or charge is None:
            continue
        sortie.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": charge},
                                ensure_ascii=False) + "\n")
        sortie.flush()


if __name__ == "__main__":
    main()
