"""Les outils, contre la fausse API.

Règle qu'on se donne ici : quand on vérifie qu'un geste n'a **pas** eu lieu, on
le constate côté serveur (aucune requête reçue), pas côté message d'erreur. Un
message d'erreur peut très bien arriver après que le mal est fait.
"""

import json
import os
import sys
import pathlib

RACINE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "tests"))

import faux_api                                            # noqa: E402

SERVEUR, BASE = faux_api.demarre()
os.environ["INFOMANIAK_BASE"] = BASE
os.environ["INFOMANIAK_TOKEN"] = faux_api.JETON
os.environ["INFOMANIAK_ACCOUNT"] = ""
os.environ.pop("INFOMANIAK_WRITE", None)

import infomaniak_mcp as ik                                # noqa: E402

ik.BASE = BASE

VERIFS = 0
ECHECS = []


def ok(condition, quoi):
    global VERIFS
    VERIFS += 1
    if not condition:
        ECHECS.append(quoi)


def ensembles(obtenu, attendu, quoi):
    """Comparer des ENSEMBLES, jamais une absence isolée ni un ordre.

    Un test qui compare des listes ordonnées vire au rouge sur un tri qui
    change ; un test qui vérifie une absence est vert quand rien n'est rendu.
    L'ensemble dit ce qu'on veut dire."""
    ok(set(obtenu) == set(attendu),
       "%s : attendu %r, obtenu %r" % (quoi, sorted(attendu), sorted(obtenu)))


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


_derniere_raison = [""]


def leve(fn, morceau, quoi):
    """L'appel doit échouer, et la raison doit *nommer* le problème.

    La raison est retenue dans `_derniere_raison` : certains refus méritent
    qu'on regarde ce qu'ils disent au-delà d'un mot-clé — qu'un plafond donne
    le total calculé, qu'une indétermination interdise le rejeu."""
    global VERIFS
    VERIFS += 1
    _derniere_raison[0] = ""
    try:
        fn()
    except ik.ErreurInfomaniak as err:
        _derniere_raison[0] = str(err)
        if morceau.lower() not in str(err).lower():
            ECHECS.append("%s : la raison ne dit pas %r — %s" % (quoi, morceau, err))
        return
    except Exception as err:                                # noqa: BLE001
        ECHECS.append("%s : mauvaise exception %s: %s" % (quoi, type(err).__name__, err))
        return
    ECHECS.append("%s : aucune erreur levée" % quoi)


def neuf():
    faux_api.remise_a_zero()
    ik._COMPTE["valeur"] = None
    os.environ["INFOMANIAK_ACCOUNT"] = ""
    os.environ.pop("INFOMANIAK_WRITE", None)


# ---------------------------------------------------------------- lecture
neuf()
r = ik.outil_comptes({})
egal(r["nombre"], 1, "comptes : nombre")
egal(r["comptes"][0]["id"], 4242, "comptes : identifiant")

vue = faux_api.requetes()[-1]
egal(vue["autorisation"], "Bearer " + faux_api.JETON, "l'entête porte le jeton en Bearer")
ok("application/json" in vue["content_type"], "l'entête Content-Type est du JSON")

neuf()
r = ik.outil_domaines({})
egal(r["nombre"], 2, "domaines : les deux")
r = ik.outil_domaines({"search": "exemple.ch"})
egal(r["nombre"], 1, "domaines : filtrés par recherche")
egal(faux_api.requetes(chemin_contient="/2/domains/domains")[-1]["params"].get("search"),
     ["exemple.ch"], "la recherche part bien en paramètre de requête")

r = ik.outil_domaines({"tld": "fr"})
egal(r["nombre"], 1, "domaines : filtrés par extension")

neuf()
r = ik.outil_domaine({"domain": "exemple.ch"})
egal(r["customer_name"], "exemple.ch", "domaine : la fiche")
leve(lambda: ik.outil_domaine({}), "domain", "domaine sans nom : refus qui nomme le champ")
leve(lambda: ik.outil_domaine({"domain": "inconnu.ch"}), "404",
     "domaine inconnu : l'erreur porte le code HTTP")

neuf()
r = ik.outil_zones({"domain": "exemple.ch"})
egal(r["nombre"], 1, "zones : une")
egal(r["zones"][0]["fqdn"], "exemple.ch", "zones : le fqdn")

neuf()
r = ik.outil_enregistrements({"zone": "exemple.ch"})
egal(r["nombre"], 3, "enregistrements : les trois")
egal(faux_api.requetes(chemin_contient="/records")[-1]["params"].get("with"),
     ["records_description"], "la description des enregistrements est demandée")

r = ik.outil_enregistrements({"zone": "exemple.ch", "type": "a"})
egal(r["nombre"], 1, "enregistrements : filtrés par type, insensible à la casse")
egal(r["enregistrements"][0]["type"], "A", "enregistrements : c'est bien le A")

r = ik.outil_enregistrements({"zone": "exemple.ch", "type": "CNAME"})
egal(r["nombre"], 1, "enregistrements : filtrés CNAME")
r = ik.outil_enregistrements({"zone": "exemple.ch", "source": "www"})
egal(r["nombre"], 1, "enregistrements : filtrés par source")
egal(r["enregistrements"][0]["source"], "www", "enregistrements : la bonne source")
r = ik.outil_enregistrements({"zone": "exemple.ch", "source": "ww"})
egal(r["nombre"], 0, "le filtre de source est exact, pas une sous-chaîne")

neuf()
r = ik.outil_verifie_enregistrement({"zone": "exemple.ch", "record": 101})
egal(r["resolved"], True, "vérification : l'enregistrement résout")
leve(lambda: ik.outil_verifie_enregistrement({"zone": "exemple.ch"}), "record",
     "vérification sans identifiant : refus")

neuf()
r = ik.outil_dnssec({"domain": "exemple.ch"})
egal(r["enabled"], False, "dnssec : l'état")


# ---------------------------------------------------- disponibilité (le step 0)
neuf()
r = ik.outil_disponibilite({"domain": "kiosquier.ch"})
egal(r["libre"], True, "disponibilité : libre")
egal(r["domaine"], "kiosquier.ch", "disponibilité : le domaine est rappelé")
egal(r["premium"], False, "disponibilité : le caractère premium est dit")
egal(r["devise"], "EUR", "disponibilité : la devise")

# Les deux prix côte à côte. C'est le point : le prix affiché est celui de la
# première période, souvent promotionnel, tandis que le coût réel du domaine
# est son renouvellement — payé chaque année ensuite. Un résumé qui ne rendrait
# que le premier ferait comparer une promotion à un tarif plein.
egal(r["premiere_periode_ht"], 6.0, "disponibilité : prix de première période")
egal(r["renouvellement_ht"], 9.9, "disponibilité : prix de renouvellement")
ok(r["premiere_periode_ht"] != r["renouvellement_ht"],
   "les deux prix sont bien distincts dans le résumé")
egal(r["periodes_possibles"], list(range(1, 11)), "disponibilité : périodes offertes")
ok("reponse" in r, "le brut est conservé sous reponse")
egal(r["reponse"]["is_available"], True, "le brut porte bien is_available")

r = ik.outil_disponibilite({"domain": "  KIOSQUIER.CH  "})
egal(r["domaine"], "kiosquier.ch", "disponibilité : le nom est normalisé")

r = ik.outil_disponibilite({"domain": "exemple.ch"})
egal(r["libre"], False, "disponibilité : pris")
ok("premiere_periode_ht" not in r,
   "un domaine pris n'affiche aucun prix — il n'y a rien à acheter")

r = ik.outil_disponibilite({"domain": "kiosquier.ch", "with_option_prices": True})
ok("options" in r["reponse"]["action"]["pricing"],
   "disponibilité : les options quand on les demande")
egal(faux_api.requetes(chemin_contient="/check")[-1]["corps"]["with_option_prices"], True,
     "l'option part bien dans le corps")

# ---- ce que l'extension exige, rendu AVEC la disponibilité ------------------
# Une fiche de documentation a dû être écrite parce que l'outil savait où
# trouver ces exigences et ne les disait pas : le champ additionnel du .app, sa
# forme, et les quatre rôles de contact. Un appelant qui ne sait pas qu'il faut
# demander ne demande pas — c'est à l'outil de le dire.
neuf()
r = ik.outil_disponibilite({"domain": "kiosquier.app"})
ok("commande" in r, "disponibilité : un bloc « commande » accompagne le prix")
c = r.get("commande") or {}

egal(c.get("champs_requis"), [{
        "nom": "x-accept-ssl-requirement", "type": "checkbox",
        "motif": "^1$", "valeur": "1",
        "texte": "J'ai lu et compris cette information"}],
     "les champs REQUIS de l'extension, et eux seuls")
egal(c.get("additional_fields"), {"x-accept-ssl-requirement": "1"},
     "un additional_fields prêt à envoyer — c'est ce qui évite de le deviner")
ensembles(c.get("contacts_requis") or [], ["owner", "admin", "tech", "billing"],
          "les quatre rôles de contact que .app exige")
egal(c.get("periodes"), list(range(1, 11)), "les durées offertes")
ok("objet" in (c.get("forme_additional_fields") or "").lower(),
   "et l'avertissement sur la FORME : un objet, malgré la spec qui dit tableau")

# Le champ « info » n'est pas une donnée à envoyer : il ne doit pas s'y glisser.
noms = [x["nom"] for x in c.get("champs_requis") or []]
ok("6a96_illisible" not in noms,
   "le champ d'information n'est pas confondu avec un champ à remplir")
ok("6a96_illisible" not in json.dumps(c.get("additional_fields") or {}),
   "ni dans le modèle prêt à envoyer")

# ---- un modèle qui n'a PAS l'air complet quand il ne l'est pas -------------
# Constaté contre la vraie API : .fr exige `restricted_publication`, un choix
# dont la valeur ne se déduit pas. Un modèle qui l'omet en silence a l'air prêt
# et fait refuser la commande — c'est un fail-OPEN, exactement ce qu'on refuse
# ailleurs. Il doit dire ce qui manque.
r = ik.outil_disponibilite({"domain": "monsite.fr"})
c = r.get("commande") or {}
egal(c.get("additional_fields"), {"restricted_publication": "1"},
     "un champ à choix avec valeur par défaut est pré-rempli avec ce défaut")
ok(c.get("additional_fields_complet") is True,
   "et le modèle s'annonce complet, puisque le défaut suffit")
champ = (c.get("champs_requis") or [{}])[0]
egal(champ.get("options"), [{"nom": "Oui", "valeur": "1"},
                            {"nom": "Non", "valeur": "0"}],
     "les options du choix sont rendues, pour qu'on puisse trancher autrement")
ok(champ.get("conditionnel") is True,
   "et le fait qu'il ne soit exigé que sous condition est signalé")

# Sans défaut ni motif contraignant, rien ne peut être pré-rempli : le modèle
# doit se déclarer INCOMPLET et nommer ce qui manque.
r = ik.outil_disponibilite({"domain": "monsite.xyz"})
c = r.get("commande") or {}
egal(c.get("additional_fields"), {},
     "un champ dont la valeur ne se déduit pas n'est pas inventé")
ok(c.get("additional_fields_complet") is False,
   "le modèle s'annonce INCOMPLET plutôt que de laisser croire qu'il suffit")
ensembles(c.get("a_renseigner") or [], ["x-siret"],
          "et il nomme précisément ce qui reste à renseigner")

# Une extension sans champ additionnel ne doit pas inventer un bloc vide
# trompeur : elle rend une liste vide et un modèle vide, pas l'absence.
r = ik.outil_disponibilite({"domain": "exemple2.ch"})
c = r.get("commande") or {}
egal(c.get("champs_requis"), [], "une extension sans champ requis le dit")
egal(c.get("additional_fields"), {}, "et rend un modèle vide, pas absent")
ensembles(c.get("contacts_requis") or [], ["owner"], "avec ses propres contacts")

# Les exigences d'une extension ne changent pas : on ne les redemande pas.
avant_tld = len(faux_api.requetes(chemin_contient="/2/tld/"))
ik.outil_disponibilite({"domain": "autre.app"})
egal(len(faux_api.requetes(chemin_contient="/2/tld/")), avant_tld,
     "les exigences d'une extension déjà vue ne sont pas redemandées")

# Un domaine PRIS n'a rien à commander : pas de bloc trompeur.
r = ik.outil_disponibilite({"domain": "exemple.ch"})
ok("commande" not in r or not r["commande"].get("montant_ht"),
   "un domaine pris ne porte pas d'instructions de commande")

# Compteur RELATIF : un nombre en dur casse au premier test ajouté au-dessus,
# et l'échec accuse alors le code au lieu du test.
avant_check = len(faux_api.requetes(chemin_contient="/check"))
leve(lambda: ik.outil_disponibilite({"domain": "kiosquier"}), "extension",
     "un nom sans extension est refusé avant l'appel")
egal(len(faux_api.requetes(chemin_contient="/check")), avant_check,
     "le nom sans extension n'a produit aucun appel réseau")

leve(lambda: ik.outil_disponibilite({}), "domain", "disponibilité sans domaine : refus")

# le compte se résout tout seul quand on ne le donne pas
neuf()
ik.outil_disponibilite({"domain": "kiosquier.ch"})
ok(any(r["chemin"] == "/1/accounts" for r in faux_api.requetes()),
   "le compte est résolu automatiquement au premier besoin")
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/4242/check", "le compte résolu est employé dans le chemin")

# ... et il n'est résolu qu'une fois
avant = len(faux_api.requetes(chemin_contient="/1/accounts"))
ik.outil_disponibilite({"domain": "autre.ch"})
egal(len(faux_api.requetes(chemin_contient="/1/accounts")), avant,
     "le compte n'est résolu qu'une seule fois")

# un compte fixé par l'environnement l'emporte, sans appel de résolution
neuf()
os.environ["INFOMANIAK_ACCOUNT"] = "777"
ik.outil_disponibilite({"domain": "kiosquier.ch"})
egal(len(faux_api.requetes(chemin_contient="/1/accounts")), 0,
     "un compte fixé évite l'appel de résolution")
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/777/check", "le compte fixé est employé")

# Plusieurs comptes : la résolution automatique doit REFUSER, pas choisir.
# Constaté en vrai le 2026-08-30 — le jeton voyait trois comptes, et prendre le
# premier revenait à tirer au sort lequel serait facturé. Un contrôle qui
# désigne une cible de dépense doit se fermer quand il ne sait pas.
neuf()
faux_api.ETAT["comptes"] = [{"id": 90812, "name": "Un tiers"},
                            {"id": 607373, "name": "Le bon compte"}]
leve(lambda: ik.outil_disponibilite({"domain": "kiosquier.ch"}), "plusieurs comptes",
     "plusieurs comptes sans choix : refus")
ik._COMPTE["valeur"] = None
leve(lambda: ik.outil_disponibilite({"domain": "kiosquier.ch"}), "607373",
     "le refus énumère les comptes, pour qu'on puisse trancher")
egal(len(faux_api.requetes(chemin_contient="/check")), 0,
     "le refus est arrivé avant tout appel de contrôle")

# ... mais un choix explicite passe, et c'est bien celui-là qui est employé
r = ik.outil_disponibilite({"domain": "kiosquier.ch", "account": "607373"})
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/607373/check", "le compte choisi est employé")
egal(r["libre"], True, "et le contrôle aboutit")

# un compte fixé par l'environnement lève aussi l'ambiguïté
neuf()
faux_api.ETAT["comptes"] = [{"id": 90812, "name": "Un tiers"},
                            {"id": 607373, "name": "Le bon compte"}]
os.environ["INFOMANIAK_ACCOUNT"] = "607373"
ik.outil_disponibilite({"domain": "kiosquier.ch"})
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/607373/check",
     "INFOMANIAK_ACCOUNT lève l'ambiguïté sans rien demander")

# un seul compte : pas d'ambiguïté, donc pas de refus
neuf()
ik.outil_disponibilite({"domain": "kiosquier.ch"})
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/4242/check",
     "un compte unique reste résolu automatiquement")


# ------------------------------------------------- le garde-fou d'écriture
# Sans armement : aucune requête ne doit partir. On le constate côté serveur.
neuf()
avant = len(faux_api.requetes())

leve(lambda: ik.outil_ajoute_enregistrement(
        {"zone": "exemple.ch", "type": "A", "target": "1.2.3.4"}),
     "lecture seule", "créer sans armement : refus")
leve(lambda: ik.outil_modifie_enregistrement(
        {"zone": "exemple.ch", "record": 101, "target": "1.2.3.4"}),
     "lecture seule", "modifier sans armement : refus")
leve(lambda: ik.outil_supprime_enregistrement({"zone": "exemple.ch", "record": 101}),
     "lecture seule", "supprimer sans armement : refus")
leve(lambda: ik.outil_serveurs_de_noms(
        {"domain": "exemple.ch", "nameservers": ["ns1.test.", "ns2.test."]}),
     "lecture seule", "changer les serveurs de noms sans armement : refus")

egal(len(faux_api.requetes()), avant,
     "aucune requête n'est partie pendant les quatre refus")
egal(len(ik.outil_enregistrements({"zone": "exemple.ch"})["enregistrements"]), 3,
     "la zone est intacte après les refus")

# La valeur doit être une des valeurs reconnues, pas n'importe quoi de vrai.
neuf()
os.environ["INFOMANIAK_WRITE"] = "0"
leve(lambda: ik.outil_supprime_enregistrement({"zone": "exemple.ch", "record": 101}),
     "lecture seule", "INFOMANIAK_WRITE=0 n'arme pas")
os.environ["INFOMANIAK_WRITE"] = "peut-etre"
leve(lambda: ik.outil_supprime_enregistrement({"zone": "exemple.ch", "record": 101}),
     "lecture seule", "une valeur fantaisiste n'arme pas")
os.environ.pop("INFOMANIAK_WRITE", None)


# ------------------------------------------------------ écriture, armée
neuf()
os.environ["INFOMANIAK_WRITE"] = "1"

r = ik.outil_ajoute_enregistrement(
    {"zone": "exemple.ch", "type": "a", "source": "test", "target": "1.2.3.4", "ttl": 120})
egal(r["cree"]["type"], "A", "création : le type est mis en capitales")
egal(r["cree"]["target"], "1.2.3.4", "création : la cible")
egal(r["cree"]["ttl"], 120, "création : le ttl")
egal(len(ik.outil_enregistrements({"zone": "exemple.ch"})["enregistrements"]), 4,
     "création : la zone en compte un de plus")

# le TTL par défaut, et ses bornes — imposées par l'API, donc refusées avant
r = ik.outil_ajoute_enregistrement({"zone": "exemple.ch", "type": "TXT", "target": "v=spf1"})
egal(r["cree"]["ttl"], 3600, "création : ttl par défaut à 3600")

avant = len(faux_api.requetes(chemin_contient="/records"))
leve(lambda: ik.outil_ajoute_enregistrement(
        {"zone": "exemple.ch", "type": "A", "target": "1.2.3.4", "ttl": 30}),
     "60", "ttl trop bas : refus qui donne la borne")
leve(lambda: ik.outil_ajoute_enregistrement(
        {"zone": "exemple.ch", "type": "A", "target": "1.2.3.4", "ttl": 90000}),
     "86400", "ttl trop haut : refus qui donne la borne")
egal(len(faux_api.requetes(chemin_contient="/records")), avant,
     "les ttl hors bornes n'ont produit aucun appel réseau")

# les bornes elles-mêmes sont acceptées
r = ik.outil_ajoute_enregistrement({"zone": "exemple.ch", "type": "A",
                                    "target": "1.1.1.1", "ttl": 60})
egal(r["cree"]["ttl"], 60, "ttl à la borne basse : accepté")
r = ik.outil_ajoute_enregistrement({"zone": "exemple.ch", "type": "A",
                                    "target": "1.1.1.2", "ttl": 86400})
egal(r["cree"]["ttl"], 86400, "ttl à la borne haute : accepté")

leve(lambda: ik.outil_ajoute_enregistrement(
        {"zone": "exemple.ch", "type": "TOTO", "target": "x"}),
     "type", "type inconnu : refus")
leve(lambda: ik.outil_ajoute_enregistrement({"zone": "exemple.ch", "type": "A"}),
     "target", "création sans cible : refus")

neuf()
os.environ["INFOMANIAK_WRITE"] = "1"
r = ik.outil_modifie_enregistrement({"zone": "exemple.ch", "record": 101,
                                     "target": "9.9.9.9"})
egal(r["modifie"]["target"], "9.9.9.9", "modification : la cible")
egal(faux_api.requetes(methode="PUT")[-1]["corps"], {"target": "9.9.9.9"},
     "modification : seul le champ donné part")
leve(lambda: ik.outil_modifie_enregistrement({"zone": "exemple.ch", "record": 101}),
     "rien à modifier", "modification vide : refus")

r = ik.outil_supprime_enregistrement({"zone": "exemple.ch", "record": 102})
egal(r["supprime"], 102, "suppression : l'identifiant est rendu")
restants = ik.outil_enregistrements({"zone": "exemple.ch"})["enregistrements"]
egal(len(restants), 2, "suppression : un de moins")
ok(all(x["id"] != 102 for x in restants), "suppression : c'est bien le 102 qui est parti")
ok(any(x["id"] == 101 for x in restants), "suppression : le voisin est intact")

# serveurs de noms : au moins deux, jamais un
neuf()
os.environ["INFOMANIAK_WRITE"] = "1"
avant = len(faux_api.requetes(methode="PUT"))
leve(lambda: ik.outil_serveurs_de_noms({"domain": "exemple.ch",
                                        "nameservers": ["ns1.test."]}),
     "deux", "un seul serveur de noms : refus")
leve(lambda: ik.outil_serveurs_de_noms({"domain": "exemple.ch", "nameservers": []}),
     "liste", "liste vide : refus")
egal(len(faux_api.requetes(methode="PUT")), avant,
     "les refus de serveurs de noms n'ont produit aucun appel")
r = ik.outil_serveurs_de_noms({"domain": "exemple.ch",
                               "nameservers": ["ns1.test.", "ns2.test."]})
egal(len(r["nameservers"]), 2, "deux serveurs de noms : accepté")


# ------------------------------------------------- erreurs de l'API, lisibles
neuf()
faux_api.ETAT["force_code"] = 401
leve(lambda: ik.outil_comptes({}), "401", "un 401 est rendu lisible")
faux_api.ETAT["force_code"] = 401
leve(lambda: ik.outil_comptes({}), "domain:read", "un 401 nomme les portées à vérifier")

faux_api.ETAT["force_code"] = 403
leve(lambda: ik.outil_comptes({}), "portée", "un 403 parle de portée, pas de jeton")

# Un 429 ne doit PAS affirmer une cause qu'on n'a pas mesurée. Le message
# disait « plafond de 60 requêtes par minute atteint » quel que soit ce
# qu'Infomaniak répondait — or le 2026-08-30 il est arrivé après trois requêtes.
# Une explication inventée envoie chercher au mauvais endroit ; on rend donc ce
# que l'API a dit, et on présente le plafond comme une piste, pas un verdict.
faux_api.ETAT["force_code"] = 429
faux_api.ETAT["force_corps"] = ('{"result":"error","error":{"code":"too_many_requests",'
                                '"description":"Order rate limit for this product"}}')
leve(lambda: ik.outil_comptes({}), "Order rate limit for this product",
     "un 429 rend ce que l'API a réellement dit")

faux_api.ETAT["force_code"] = 429
faux_api.ETAT["force_corps"] = ('{"result":"error","error":{"code":"too_many_requests",'
                                '"description":"Order rate limit for this product"}}')
_ = None
try:
    ik.outil_comptes({})
except ik.ErreurInfomaniak as err:
    _ = str(err)
ok(_ is not None, "le 429 lève bien")
ok("atteint" not in (_ or ""),
   "le message n'affirme plus que le plafond « est atteint » : %r" % (_ or ""))
ok("60" not in (_ or "") or "peut" in (_ or "").lower() or "piste" in (_ or "").lower(),
   "s'il cite 60/minute, c'est comme une piste, pas comme un constat : %r" % (_ or ""))

faux_api.ETAT["force_code"] = 200
faux_api.ETAT["force_corps"] = "<html>maintenance</html>"
leve(lambda: ik.outil_comptes({}), "JSON", "une réponse non-JSON est nommée telle quelle")

faux_api.ETAT["force_code"] = 500
faux_api.ETAT["force_corps"] = '{"result":"error","error":{"code":"boum","description":""}}'
leve(lambda: ik.outil_comptes({}), "boum", "un code d'erreur sans description reste visible")

# Le cas qui pique : HTTP 200, mais `result` vaut "error". L'API le fait, et
# ne regarder que le code HTTP ferait passer l'échec pour un succès — avec un
# `data` absent, donc une liste vide rendue comme si tout allait bien.
faux_api.ETAT["force_code"] = 200
faux_api.ETAT["force_corps"] = ('{"result":"error","error":{"code":"quota_exceeded",'
                                '"description":"trop de zones"}}')
leve(lambda: ik.outil_comptes({}), "trop de zones",
     "un 200 porteur de result=error est bien traité comme une erreur")

faux_api.ETAT["force_code"] = 200
faux_api.ETAT["force_corps"] = '{"result":"error","error":{"code":"quota_exceeded"}}'
leve(lambda: ik.outil_comptes({}), "quota_exceeded",
     "un 200 en erreur sans description montre au moins le code")

# assertion inverse : un vrai succès en 200 passe toujours
faux_api.ETAT["force_code"] = 200
faux_api.ETAT["force_corps"] = '{"result":"success","data":[{"id":1}]}'
egal(ik.outil_comptes({})["nombre"], 1, "un 200 en succès passe toujours")

# sans jeton du tout : le message doit dire où en créer un
neuf()
garde = os.environ.pop("INFOMANIAK_TOKEN")
os.environ.pop("INFOMANIAK_TOKEN_CMD", None)
avant = len(faux_api.requetes())
leve(lambda: ik.outil_comptes({}), "manager.infomaniak.com",
     "sans jeton : le message dit où en fabriquer un")
egal(len(faux_api.requetes()), avant, "sans jeton, aucune requête n'est tentée")
os.environ["INFOMANIAK_TOKEN"] = garde

# le jeton peut venir d'une commande — le secret ne traîne dans aucun fichier
neuf()
del os.environ["INFOMANIAK_TOKEN"]
os.environ["INFOMANIAK_TOKEN_CMD"] = "printf %s " + faux_api.JETON
egal(ik.outil_comptes({})["nombre"], 1, "le jeton peut venir d'une commande")
del os.environ["INFOMANIAK_TOKEN_CMD"]
os.environ["INFOMANIAK_TOKEN"] = faux_api.JETON


# -------------------------------------------------------------- la cadence
# Le plafond est de 60 par minute et ne se relève pas : la cadence doit
# attendre plutôt que de laisser partir la 61e.
dormi = []
c = ik.Cadence(3, 60.0)
for i in range(3):
    c.attendre(maintenant=100.0 + i, dormir=dormi.append)
egal(dormi, [], "sous le plafond : on n'attend pas")
c.attendre(maintenant=103.0, dormir=dormi.append)
egal(len(dormi), 1, "au plafond : on attend")
ok(abs(dormi[0] - 57.0) < 0.001, "on attend juste ce qu'il faut : %r" % dormi)

c2 = ik.Cadence(3, 60.0)
for i in range(3):
    c2.attendre(maintenant=100.0 + i, dormir=dormi.append)
avant = len(dormi)
c2.attendre(maintenant=200.0, dormir=dormi.append)
egal(len(dormi), avant, "la fenêtre est glissante : passé 60 s, on repart libre")

# Et elle doit freiner *de nouveau* dans la fenêtre suivante. Sans cet examen,
# une cadence qui n'élague jamais reste verte : les vieux horodatages gonflent
# la liste, le repos calculé devient négatif, et la garde « repos > 0 » avale
# silencieusement l'absence de freinage. C'est-à-dire qu'on ne freine plus
# jamais après la première minute — exactement le contraire du but.
c3 = ik.Cadence(3, 60.0)
for t in (100.0, 101.0, 102.0):
    c3.attendre(maintenant=t, dormir=dormi.append)
for t in (200.0, 201.0, 202.0):
    c3.attendre(maintenant=t, dormir=dormi.append)
avant = len(dormi)
c3.attendre(maintenant=203.0, dormir=dormi.append)
egal(len(dormi), avant + 1, "la fenêtre suivante freine elle aussi")
ok(abs(dormi[-1] - 57.0) < 0.001,
   "et elle freine du bon montant, calculé sur la fenêtre courante : %r" % dormi[-1])
ok(len(c3.appels) <= 3,
   "les horodatages périmés sont élagués : %d retenus pour un plafond de 3"
   % len(c3.appels))


# ------------------------------------------------------- la table des outils
noms = {t["name"] for t in ik.TOOLS}
ok("disponibilite" in noms, "l'outil de disponibilité existe")
for interdit in ("achete", "acheter", "commande", "create_domain", "transfer",
                 "transfere", "order"):
    ok(interdit not in noms, "aucun outil ne s'appelle %r" % interdit)

# Aucun chemin d'achat ne doit être *appelé*. On regarde les chaînes réellement
# passées à `appel(...)`, pas le texte du fichier : la prose du module cite ces
# chemins pour expliquer qu'on ne les emprunte pas, et une recherche naïve dans
# la source confondrait l'explication avec l'usage.
import ast                                                  # noqa: E402

arbre = ast.parse((RACINE / "infomaniak_mcp.py").read_text(encoding="utf-8"))
chemins_appeles = []
for noeud in ast.walk(arbre):
    if not (isinstance(noeud, ast.Call) and getattr(noeud.func, "id", "") == "appel"):
        continue
    if not noeud.args:
        continue
    premier = noeud.args[0]
    if isinstance(premier, ast.Constant) and isinstance(premier.value, str):
        chemins_appeles.append(premier.value)
    elif isinstance(premier, ast.BinOp):        # "/2/…%s…" % quelque_chose
        gauche = premier.left
        if isinstance(gauche, ast.Constant) and isinstance(gauche.value, str):
            chemins_appeles.append(gauche.value)
        else:
            chemins_appeles.append(ast.unparse(premier))
    else:
        chemins_appeles.append(ast.unparse(premier))

ok(len(chemins_appeles) >= 10,
   "l'inventaire des chemins appelés a bien été construit : %d" % len(chemins_appeles))
ok(all(isinstance(c, str) for c in chemins_appeles), "tous les chemins sont des chaînes")
# On ne regarde plus seulement le premier argument de `appel()` : un chemin
# peut transiter par une variable, et l'inventaire le manquerait — donc
# manquerait aussi un chemin d'achat dissimulé de la même façon. On cherche
# désormais **toute chaîne littérale** du module, et dans quelle fonction elle
# se trouve. C'est la question qu'on veut poser : qui connaît ce chemin.
def fonctions_citant(motif):
    trouvees = []
    for f in ast.walk(arbre):
        if not isinstance(f, ast.FunctionDef):
            continue
        for n in ast.walk(f):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and motif in n.value:
                trouvees.append(f.name)
                break
    return sorted(set(trouvees))

# L'instrument voit-il ce qu'il prétend voir ? Assertion de contrôle sur un
# motif dont on sait qu'il existe.
ok(fonctions_citant("/2/zones/") != [],
   "l'inventaire voit les chemins de zone, donc il verrait un chemin d'achat")

egal(fonctions_citant("/transfer"), [],
     "aucune fonction ne connaît /transfer — le transfert reste hors d'atteinte")

# /create existe maintenant, mais dans UNE SEULE fonction. On ne supprime pas
# le test qui surveillait ce chemin, on le retourne : un test effacé laisse un
# trou exactement là où on regardait.
egal(fonctions_citant("/create"), ["outil_commande_domaine"],
     "seul l'outil de commande connaît /create")
# et l'assertion inverse : l'inventaire voit bien les chemins qui existent
ok(any("/2/zones/" in c for c in chemins_appeles),
   "l'inventaire voit les chemins de zone (donc il verrait un chemin d'achat)")
ok(any("/1/accounts" in c for c in chemins_appeles),
   "l'inventaire voit le chemin des comptes")

ecrivains = {t["name"] for t in ik.TOOLS if t["description"].startswith("[écrit]")}
egal(ecrivains, {"ajoute_enregistrement", "modifie_enregistrement",
                 "supprime_enregistrement", "serveurs_de_noms"},
     "les outils qui écrivent sont exactement ceux annoncés comme tels")

depensiers = {t["name"] for t in ik.TOOLS if t["description"].startswith("[DÉPENSE]")}
egal(depensiers, {"commande_domaine"},
     "un seul outil engage une dépense, et il est marqué comme tel")
ok(not (ecrivains & depensiers),
   "les deux marques ne se recouvrent pas : écrire n'est pas dépenser")

for t in ik.TOOLS:
    schema = t["inputSchema"]
    ok(schema["type"] == "object", "%s : schéma objet" % t["name"])
    for requis in schema["required"]:
        ok(requis in schema["properties"],
           "%s : le champ requis %r est décrit" % (t["name"], requis))

# les instructions doivent dire l'état réel, dans les deux sens
os.environ.pop("INFOMANIAK_WRITE", None)
ok("LECTURE SEULE" in ik.instructions(), "les instructions annoncent la lecture seule")
os.environ["INFOMANIAK_WRITE"] = "1"
ok("LECTURE SEULE" not in ik.instructions(),
   "armé, les instructions ne parlent plus de lecture seule")
ok("armés" in ik.instructions(), "armé, les instructions le disent")
os.environ.pop("INFOMANIAK_WRITE", None)



# =================================================================== la commande
# La règle de ce fichier vaut ici plus qu'ailleurs : quand on affirme qu'aucune
# commande n'est passée, on le constate côté serveur — `faux_api.ETAT["commandes"]`
# — et pas au message d'erreur reçu.

def commandes():
    return faux_api.ETAT.get("commandes", [])


# --- non armé : rien ne part, quoi qu'on demande ---------------------------
neuf()
os.environ["INFOMANIAK_WRITE"] = "1"          # écrire est armé...
os.environ.pop("INFOMANIAK_ACHAT", None)      # ...mais pas dépenser
avant = len(faux_api.requetes())

leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0}),
     "non armé", "sans INFOMANIAK_ACHAT : refus")
ok("INFOMANIAK_ACHAT" in str(_derniere_raison[0]),
   "le refus nomme la variable qui armerait")
egal(commandes(), [], "aucune commande n'a été passée")
egal(len(faux_api.requetes()), avant, "aucune requête n'est partie")

# INFOMANIAK_WRITE n'arme PAS la dépense — c'est tout l'intérêt de deux
# armements distincts, et un test doit le prouver plutôt que le supposer.
ok(ik.ecriture_armee() and not ik.achat_arme(),
   "écrire est armé alors que dépenser ne l'est pas : les deux sont bien séparés")
os.environ.pop("INFOMANIAK_WRITE", None)

# --- armé : les quatre barrières, une par une ------------------------------
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"

# barrière « cible » : la confirmation doit répéter le domaine
avant = len(commandes())
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.fr",
         "amount_total_excl_tax": 6.0}),
     "confirmation", "confirmation qui ne correspond pas : refus")
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "amount_total_excl_tax": 6.0}),
     "confirmation", "confirmation absente : refus")
egal(len(commandes()), avant, "aucune commande malgré deux tentatives")

# barrière « montant » : obligatoire, jamais deviné
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch"}),
     "amount_total_excl_tax", "montant absent : refus")
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 0}),
     "négatif", "montant nul : refus")
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": "beaucoup"}),
     "nombre", "montant illisible : refus")
egal(len(commandes()), avant, "toujours aucune commande")

# le serveur ne va JAMAIS chercher le prix tout seul pour combler le montant
egal(len(faux_api.requetes(chemin_contient="/check")), 0,
     "aucun contrôle de prix n'est lancé en douce pour deviner le montant")

# barrière « période »
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0, "registration_period": 0}),
     "entre 1 et 10", "période nulle : refus")
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0, "registration_period": 11}),
     "entre 1 et 10", "période trop longue : refus")

# barrière « plafond » — et elle porte sur le TOTAL, période comprise
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
os.environ["INFOMANIAK_ACHAT_MAX"] = "50"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 60.0}),
     "plafond", "montant au-dessus du plafond : refus")
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 20.0, "registration_period": 5}),
     "plafond", "5 ans à 20 € dépassent 50 € : refus")
ok("100.00" in str(_derniere_raison[0]),
   "le refus donne le total calculé, pas seulement le prix unitaire")
egal(commandes(), [], "le plafond n'a rien laissé passer")

# un plafond illisible REFUSE au lieu de retomber sur le défaut
os.environ["INFOMANIAK_ACHAT_MAX"] = "cinquante"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0}),
     "n'est pas un nombre", "plafond illisible : refus, pas de repli silencieux")
os.environ["INFOMANIAK_ACHAT_MAX"] = "0"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0}),
     "n'autorise aucune", "plafond nul : refus")
egal(commandes(), [], "aucune commande sous plafond illisible ou nul")
os.environ.pop("INFOMANIAK_ACHAT_MAX", None)

# --- le chemin qui aboutit -------------------------------------------------
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
r = ik.outil_commande_domaine(
    {"domain": "  KIOSQUIER.CH ", "confirmation": "kiosquier.ch",
     "amount_total_excl_tax": 6.0})
egal(r["domaine"], "kiosquier.ch", "le nom est normalisé des deux côtés")
egal(r["annees"], 1, "une année par défaut")
egal(len(commandes()), 1, "exactement une commande a été passée")
egal(commandes()[0]["domain"], "kiosquier.ch", "et c'est le bon domaine")
egal(commandes()[0]["amount_total_excl_tax"], 6.0, "avec le montant annoncé")
egal(commandes()[0]["registration_period"], 1, "et la période")

# le contrôle de montant de l'API mord vraiment : montant faux → refus
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 3.0}),
     "invalid_expected_amount", "montant qui ne colle pas au prix : l'API refuse")
egal(commandes(), [], "et rien n'a été enregistré")

# les champs facultatifs traversent quand ils sont donnés, et pas sinon
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
ik.outil_commande_domaine(
    {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
     "amount_total_excl_tax": 6.0, "contacts": {"owner": 11}})
egal(commandes()[0].get("contacts"), {"owner": 11}, "les contacts traversent")
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
ik.outil_commande_domaine(
    {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
     "amount_total_excl_tax": 6.0})
ok("contacts" not in commandes()[0],
   "un champ facultatif absent n'est pas inventé dans le corps")

# un nom sans extension n'atteint jamais le réseau
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier", "confirmation": "kiosquier",
         "amount_total_excl_tax": 6.0}),
     "extension", "nom sans extension : refus")
egal(len(faux_api.requetes()), 0, "et aucune requête n'est partie")

# plusieurs comptes : on ne devine pas qui paie
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
faux_api.ETAT["comptes"] = [{"id": 90812, "name": "Un tiers"},
                            {"id": 607373, "name": "Le bon compte"}]
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0}),
     "plusieurs comptes", "commande sans compte désigné : refus")
egal(commandes(), [], "personne n'a été facturé au hasard")
r = ik.outil_commande_domaine(
    {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
     "amount_total_excl_tax": 6.0, "account": "607373"})
egal(r["compte"], "607373", "le compte employé est rendu dans la réponse")
egal(faux_api.requetes(chemin_contient="/create")[-1]["chemin"],
     "/2/domains/accounts/607373/create", "et c'est bien celui-là qui est visé")

# --- l'issue indéterminée --------------------------------------------------
# Un échec de transport ne dit pas que la commande n'est pas passée. Le message
# doit l'annoncer et interdire le rejeu, sinon on paie deux fois.
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
vrai_appel = ik.appel


def appel_qui_coupe(chemin, **kw):
    if "/create" in chemin:
        raise ik.ErreurInfomaniak(
            "l'API Infomaniak est injoignable sur %s : timed out" % ik.BASE)
    return vrai_appel(chemin, **kw)


ik.appel = appel_qui_coupe
try:
    leve(lambda: ik.outil_commande_domaine(
            {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
             "amount_total_excl_tax": 6.0}),
         "INDÉTERMINÉE", "coupure réseau : l'issue est annoncée indéterminée")
    ok("NE PAS REJOUER" in str(_derniere_raison[0]),
       "et le message interdit explicitement le rejeu")
    ok("kiosquier.ch" in str(_derniere_raison[0]),
       "le message nomme le domaine concerné, pour aller vérifier")
finally:
    ik.appel = vrai_appel

# --- le détail des erreurs de validation ------------------------------------
# L'API range dans `error.errors` un tableau qui NOMME l'attribut fautif et,
# souvent, les valeurs acceptées. Sans lui, « Validation failed » n'apprend
# rien : c'est ce qui m'a fait sonder à l'aveugle le 2026-08-30 alors que la
# réponse contenait déjà la liste des valeurs possibles.
neuf()
faux_api.ETAT["force_code"] = 422
faux_api.ETAT["force_corps"] = json.dumps({
    "result": "error",
    "error": {"code": "validation_failed", "description": "Validation failed",
              "errors": [{"code": "validation_rule_in",
                          "description": "The selected with.0 is invalid.",
                          "context": {"attribute": "with.0",
                                      "values": ["fields", "periods"]}}]}})
leve(lambda: ik.outil_comptes({}), "with.0",
     "une erreur de validation nomme l'attribut fautif")
ok("fields" in _derniere_raison[0] and "periods" in _derniere_raison[0],
   "et elle rend les valeurs acceptées : %r" % _derniere_raison[0][:200])

# plusieurs erreurs : toutes doivent remonter, pas seulement la première
neuf()
faux_api.ETAT["force_code"] = 400
faux_api.ETAT["force_corps"] = json.dumps({
    "result": "error",
    "error": {"code": "invalid_additional_field", "description": "bad fields",
              "errors": [{"description": "champ A manquant"},
                         {"description": "champ B invalide"}]}})
leve(lambda: ik.outil_comptes({}), "champ A manquant", "la première erreur remonte")
ok("champ B invalide" in _derniere_raison[0],
   "la seconde aussi : on ne perd pas les erreurs suivantes")

# --- le solde prépayé, et où le recharger -----------------------------------
# La commande par l'API tire sur le crédit prépayé, jamais sur une carte
# enregistrée — constaté le 2026-08-30. Un message qui dit « fonds
# insuffisants » sans dire où les mettre laisse le lecteur devant un moteur de
# recherche. On y met l'adresse.
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
# Compte épinglé : sans ça, le forçage frapperait l'appel de résolution de
# compte, qui a lieu AVANT la commande — on mesurerait alors le mauvais chemin.
os.environ["INFOMANIAK_ACCOUNT"] = "4242"
faux_api.ETAT["force_code"] = 500
faux_api.ETAT["force_corps"] = (
    '{"result":"error","error":{"code":"insufficient_funds_prepaid_balance",'
    '"description":"Insufficient funds prepaid balance"}}')
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0}),
     "manager.infomaniak.com/v3/invoicing/payment-methods",
     "fonds insuffisants : le message donne l'adresse pour créditer")
ok("prépayé" in _derniere_raison[0].lower(),
   "et il explique que le paiement passe par le crédit prépayé")
ok("INDÉTERMIN" not in _derniere_raison[0],
   "ce n'est pas une issue indéterminée : le refus est net, rien n'a été commandé")

# L'adresse doit aussi figurer dans la description de l'outil, pour qu'un
# modèle la connaisse avant d'échouer, pas seulement après.
ok("manager.infomaniak.com/v3/invoicing/payment-methods"
   in ik.BY_NAME["commande_domaine"]["description"],
   "la description de commande_domaine porte l'adresse de crédit")

# une erreur métier ordinaire, elle, reste rendue telle quelle
neuf()
os.environ["INFOMANIAK_ACHAT"] = "1"
faux_api.ETAT["libres"]["exemple.ch"] = False
leve(lambda: ik.outil_commande_domaine(
        {"domain": "exemple.ch", "confirmation": "exemple.ch",
         "amount_total_excl_tax": 6.0}),
     "invalid_domain_action", "un refus métier n'est pas déguisé en indétermination")
ok("INDÉTERMINÉE" not in str(_derniere_raison[0]),
   "et il ne porte pas l'avertissement de rejeu, qui serait trompeur ici")

os.environ.pop("INFOMANIAK_ACHAT", None)

# les instructions annoncent l'état de l'armement de dépense, dans les deux sens
ok("n'est PAS armé" in ik.instructions(),
   "instructions : la dépense non armée est annoncée")
os.environ["INFOMANIAK_ACHAT"] = "1"
ok("ARMÉ" in ik.instructions(), "instructions : la dépense armée est annoncée")
ok("ne jamais l'inventer" in ik.instructions().lower()
   or "inventer" in ik.instructions(),
   "instructions armées : le montant ne doit pas être inventé")
os.environ.pop("INFOMANIAK_ACHAT", None)


SERVEUR.shutdown()
print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
