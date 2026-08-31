#!/usr/bin/env python3
"""Les douze durcissements de l'audit adverse, éprouvés un par un.

    python3 tests/check_durcissement.py

`check_oauth.py` éprouve le flux nominal et les refus que la spec énonce.
Celui-ci n'éprouve que ce que l'audit du 2026-08-31 a trouvé de **cassé** :
D1 à D12 de `TODO.md`, chacune avec sa section. Chaque assertion a été vue
rouge contre le serveur d'avant le correctif — c'est la seule chose qui prouve
qu'elle mord.

Le banc est jetable : des `serveur.py` lancés en sous-processus sur des ports
libres, des répertoires d'état temporaires, et la fausse API du dépôt à la
place d'Infomaniak. Rien ne sort de la machine, aucun jeton réel n'est employé.

Quatre règles tenues partout ici :

1. Affirmer qu'un geste n'a **pas** eu lieu se constate côté serveur — le
   fichier d'état, la fausse API, le jeton d'après. Jamais sur un code de
   retour : un refus annoncé qui révoque quand même est exactement la faute
   qu'on cherche.
2. Une absence isolée est verte quand rien ne se produit du tout. On compare
   des **ensembles**, et on double chaque refus d'une assertion inverse
   exigeant que le geste légitime, lui, aboutisse — sans quoi « tout casser »
   serait une façon de passer au vert.
3. Un `/healthz` qui répond ne prouve pas que c'est *notre* serveur : chaque
   section exige que notre propre processus soit vivant.
4. Aucun sommeil ne mesure quoi que ce soit. Une réécriture se détecte par
   l'inode et l'horodatage, pas en attendant.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

RACINE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "tests"))

import faux_api                                            # noqa: E402
import marque_proxy                                        # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
CLIENT = "infomaniak-domains-claude"

# Les portées annoncées par la découverte. Les nommer en dur est volontaire :
# la cloison de D11 sépare ces deux-là, et un renommage silencieux doit se
# voir ici plutôt que de passer pour un changement de décor.
SCOPE_LIRE = "domaines:lire"
SCOPE_ECRIRE = "domaines:ecrire"

# D11 — l'inventaire attendu de part et d'autre de la cloison. Deux ensembles
# non vides, et exactement ceux-là : « au moins un de chaque côté » laisserait
# passer une marque renommée sur QUATORZE outils sur quinze.
ECRITURE_ATTENDUE = {"ajoute_enregistrement", "modifie_enregistrement",
                     "supprime_enregistrement", "serveurs_de_noms",
                     "commande_domaine"}
LECTURE_ATTENDUE = {"comptes", "domaines", "domaine", "disponibilite", "zones",
                    "enregistrements", "verifie_enregistrement", "dnssec",
                    "contacts", "solde"}

VERIFS = 0
ECHECS = []
CORPS_VUS = []


# --------------------------------------------------------------------------
# le comptage
# --------------------------------------------------------------------------

def ok(condition, quoi):
    global VERIFS
    VERIFS += 1
    if not condition:
        ECHECS.append(quoi)


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def ensembles(obtenu, attendu, quoi):
    a, b = set(obtenu), set(attendu)
    ok(a == b, "%s : manquant %s, en trop %s" % (quoi, sorted(b - a), sorted(a - b)))


# --------------------------------------------------------------------------
# le banc d'essai
# --------------------------------------------------------------------------

def port_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


API_SERVEUR, API_BASE = faux_api.demarre()
faux_api.remise_a_zero()

BUREAU = tempfile.mkdtemp(prefix="durcissement-journaux-")
ETAT = tempfile.mkdtemp(prefix="durcissement-etat-")
PORT = port_libre()
BASE = "http://127.0.0.1:%d" % PORT

# Un identifiant de compte reconnaissable : D12 exige que /_whoami ne le
# recrache pas. Il est choisi hors de l'alphabet hexadécimal aux deux bouts
# pour qu'une empreinte ne puisse pas le contenir par hasard.
COMPTE = "8675309"

ENV_COMMUNE = dict(os.environ)
ENV_COMMUNE.update({
    "INFOMANIAK_BASE": API_BASE,
    "INFOMANIAK_TOKEN": faux_api.JETON,
    "INFOMANIAK_ACCOUNT": COMPTE,
    "INFOMANIAK_RATE": "1000000",
    "PYTHONUNBUFFERED": "1",
})
ENV_COMMUNE.update(marque_proxy.env())
for arme in ("INFOMANIAK_WRITE", "INFOMANIAK_ACHAT", "INFOMANIAK_TOKEN_CMD"):
    ENV_COMMUNE.pop(arme, None)

PROCS = []              # (nom, processus, journal) — tout ce qu'on a lancé
JETABLES = [ETAT, BUREAU]   # les répertoires à balayer, quoi qu'il arrive


class PasDeRedirection(urllib.request.HTTPRedirectHandler):
    """Suivre la redirection emmènerait sur claude.ai, dont la réponse n'a rien
    à nous dire — et masquerait ce que notre serveur a répondu."""

    def redirect_request(self, *args, **kwargs):
        return None


OUVREUR = urllib.request.build_opener(PasDeRedirection)


def http(methode, chemin, corps=None, ctype=None, entetes=None, base=None):
    """Rend (statut, en-têtes, corps). Un statut 0 dit « aucune réponse » —
    c'est une donnée, pas un accident : D6 et D8 ne cherchent que ça."""
    requete = urllib.request.Request((base or BASE) + chemin, data=corps,
                                     method=methode)
    if ctype:
        requete.add_header("Content-Type", ctype)
    for cle, valeur in (entetes or {}).items():
        requete.add_header(cle, valeur)
    try:
        with OUVREUR.open(requete, timeout=10) as reponse:
            statut, tetes = reponse.status, dict(reponse.headers)
            texte = reponse.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        statut, tetes = err.code, dict(err.headers)
        texte = err.read().decode("utf-8", "replace")
    except Exception as err:                                # noqa: BLE001
        statut, tetes, texte = 0, {}, "aucune réponse : %s" % err
    CORPS_VUS.append(texte)
    return statut, tetes, texte


def get(chemin, entetes=None, base=None):
    return http("GET", chemin, entetes=entetes, base=base)


def post(chemin, corps=b"", ctype="application/json", entetes=None, base=None):
    return http("POST", chemin, corps, ctype, entetes, base)


def formulaire(chemin, champs, entetes=None, base=None):
    return post(chemin, urllib.parse.urlencode(champs).encode(),
                "application/x-www-form-urlencoded", entetes, base)


def js(corps):
    try:
        return json.loads(corps)
    except ValueError:
        return {}


def rpc(methode, params=None, jeton=None, entetes=None, base=None):
    tetes = dict(entetes or {})
    if jeton:
        tetes["Authorization"] = "Bearer " + jeton
    message = {"jsonrpc": "2.0", "id": 1, "method": methode}
    if params is not None:
        message["params"] = params
    statut, tetes_rep, texte = post("/mcp", json.dumps(message).encode(),
                                    "application/json", tetes, base)
    return statut, tetes_rep, js(texte)


def lance(nom, dossier_code, dossier_etat, port, base_publique=None, sup=None):
    """Un serveur de plus, avec son code, son état et son adresse publique.

    D10 en demande deux qui partagent l'état, D12 trois qui ne partagent rien :
    le banc doit donc savoir lancer autre chose que « le » serveur."""
    env = dict(ENV_COMMUNE)
    env.update({"INFOMANIAK_LISTEN_PORT": str(port),
                "INFOMANIAK_DATA": dossier_etat,
                "INFOMANIAK_PUBLIC_BASE":
                    base_publique or ("http://127.0.0.1:%d" % port)})
    env.update(sup or {})
    journal = open(os.path.join(BUREAU, "sortie-%s.txt" % nom), "w+")
    proc = subprocess.Popen([sys.executable,
                             os.path.join(str(dossier_code), "serveur.py")],
                            env=env, stdout=journal, stderr=subprocess.STDOUT)
    PROCS.append((nom, proc, journal))
    adresse = "http://127.0.0.1:%d" % port
    # Le seul sommeil du fichier, et il ne mesure rien : il attend que le port
    # soit ouvert.
    limite = time.monotonic() + 15
    while time.monotonic() < limite:
        if proc.poll() is not None:
            ok(False, "%s s'est arrêté au démarrage (code %s) — %s"
               % (nom, proc.returncode, journal_de(journal)[-400:]))
            return None
        if get("/healthz", base=adresse)[0] == 200:
            return proc
        time.sleep(0.02)
    ok(False, "%s n'a pas répondu sur /healthz en 15 s" % nom)
    return None


def journal_de(journal):
    try:
        journal.flush()
        position = journal.tell()
        journal.seek(0)
        texte = journal.read()
        journal.seek(position)
        return texte
    except Exception:                                       # noqa: BLE001
        return ""


def tout_le_journal():
    return "\n".join(journal_de(j) for _, _, j in PROCS)


def vivant(ou, proc=None):
    cible = proc if proc is not None else PRINCIPAL[0]
    ok(cible is not None and cible.poll() is None,
       "%s : notre processus serveur est vivant" % ou)


# --------------------------------------------------------------------------
# ce que le serveur a écrit — la seule preuve qu'une écriture n'a pas eu lieu
# --------------------------------------------------------------------------

def fichiers_etat(dossier=None):
    return sorted(p for p in pathlib.Path(dossier or ETAT).rglob("*") if p.is_file())


def etat_brut(dossier=None):
    return "\n".join(p.read_text("utf-8", "replace") for p in fichiers_etat(dossier))


def signature_etat(dossier=None):
    """De quoi reconnaître une RÉÉCRITURE, pas seulement un changement.

    Réécrire le même JSON est une écriture : le contenu ne la montrerait pas.
    `os.replace` change l'inode, ce qu'aucune granularité d'horodatage ne peut
    masquer — c'est ce numéro-là qui fait foi."""
    trace = {}
    for chemin in fichiers_etat(dossier):
        st = chemin.stat()
        trace[chemin.name] = (st.st_ino, st.st_mtime_ns, st.st_size,
                              hashlib.sha256(chemin.read_bytes()).hexdigest())
    return trace


def vieillir_etat(dossier=None):
    """Recule l'horodatage de l'état d'un jour.

    Sur un système de fichiers à la seconde, deux écritures dans la même
    seconde se confondraient. Après ce recul, la moindre réécriture fait
    bondir l'horodatage d'un jour : la mesure ne dépend plus de la finesse du
    système de fichiers."""
    quand = time.time() - 86400
    for chemin in fichiers_etat(dossier):
        os.utime(chemin, (quand, quand))


# --------------------------------------------------------------------------
# le flux d'autorisation, complet, sans raccourci
# --------------------------------------------------------------------------

def pkce(verifier=None):
    if verifier is None:
        verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    defi = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()).rstrip(b"=").decode()
    return verifier, defi


def csrf_de(html):
    trouve = (re.search(r'name="csrf"[^>]*value="([^"]+)"', html)
              or re.search(r'value="([^"]+)"[^>]*name="csrf"', html))
    return trouve.group(1) if trouve else ""


def code_de(location):
    return (urllib.parse.parse_qs(
        urllib.parse.urlparse(location or "").query).get("code") or [""])[0]


HUMAIN = {}             # rempli par la sonde de D1


def humaines(extra=None):
    tetes = dict(HUMAIN)
    tetes.update(marque_proxy.navigation())
    tetes.update(extra or {})
    return tetes


def params_autorisation(defi, scope, resource=None, etat="s1"):
    return {"response_type": "code", "client_id": CLIENT,
            "redirect_uri": REDIRECT, "code_challenge": defi,
            "code_challenge_method": "S256", "state": etat,
            "scope": scope, "resource": resource or (BASE + "/mcp")}


def page_consentement(params, entetes=None, base=None):
    return get("/authorize?" + urllib.parse.urlencode(params),
               humaines(entetes), base)


def consentir(csrf, entetes=None, base=None):
    return formulaire("/consent", {"csrf": csrf, "action": "autoriser"},
                      humaines(entetes), base)


def flux(scope=None, resource=None, etat="s1", verifier=None, echanger=True):
    """Le chemin complet que Claude emprunte : page, consentement, échange.

    Rend tout ce qu'on a vu en route — y compris ce qui a échoué, pour que le
    rapport nomme l'étape et pas seulement le symptôme."""
    scope = scope or (SCOPE_LIRE + " " + SCOPE_ECRIRE)
    verifier, defi = pkce(verifier)
    vu = {"verifier": verifier, "defi": defi, "scope": scope}
    statut, _, html = page_consentement(
        params_autorisation(defi, scope, resource, etat))
    vu["csrf"] = csrf_de(html)
    if statut != 200 or not vu["csrf"]:
        vu["erreur"] = "page de consentement absente (statut %s)" % statut
        return vu
    _, tetes, _ = consentir(vu["csrf"])
    vu["location"] = tetes.get("Location", "")
    vu["code"] = code_de(vu["location"])
    if not vu["code"]:
        vu["erreur"] = "aucun code émis par /consent"
        return vu
    if not echanger:
        return vu
    statut, _, corps = formulaire("/token", {
        "grant_type": "authorization_code", "code": vu["code"],
        "redirect_uri": REDIRECT, "client_id": CLIENT,
        "code_verifier": verifier})
    jetons = js(corps)
    vu["statut"] = statut
    vu["acces"] = jetons.get("access_token") or ""
    vu["rafraichir"] = jetons.get("refresh_token") or ""
    if not vu["acces"]:
        vu["erreur"] = "aucun jeton délivré (statut %s)" % statut
    return vu


def hexs(texte):
    """Les empreintes que porte un texte. Douze caractères hexadécimaux au
    minimum : en dessous, une date ou une couleur CSS passerait pour une
    empreinte."""
    return set(re.findall(r"\b[0-9a-fA-F]{12,}\b", texte or ""))


PRINCIPAL = [None]
QUEUE = ""

try:
    if not (RACINE / "serveur.py").exists():
        ok(False, "serveur.py n'existe pas : rien à éprouver")
        raise SystemExit
    PRINCIPAL[0] = lance("principal", RACINE, ETAT, PORT)

    if PRINCIPAL[0] is not None:

        # ---- D1 : la marque du proxy -----------------------------------
        # Ce qui garde la page qui émet les codes d'autorisation. Un en-tête
        # que l'appelant écrit lui-même ne prouve rien : le pod est joignable
        # sur 8080 sans passer par Traefik.
        print("\nD1. un en-tête forgé ne franchit pas la frontière humaine")
        vivant("D1")

        def entre(entetes):
            return get("/", entetes)[0] == 200

        trouvee = marque_proxy.trouver(entre)
        ok(trouvee is not None,
           "le banc trouve une façon d'entrer côté humain — sans quoi tout ce "
           "qui suit serait vert parce que rien ne répond. Essayé : %s"
           % ([sorted(c) for c in marque_proxy.candidats()],))
        HUMAIN.update(trouvee or {})
        print("   entrée humaine constatée : %s" % (sorted(HUMAIN) or "(aucune)"))

        # Tout ce qu'un inconnu peut écrire lui-même. La marque sous son vrai
        # nom mais avec une valeur inventée en fait partie : c'est la valeur
        # qui protège, jamais le nom.
        FORGES = [("aucun en-tête", {}),
                  ("Basic inventé", {"Authorization": "Basic bnaGV6:cXVvaQ=="}),
                  ("Basic du proxy rejoué", dict(marque_proxy.ANCIEN_REGIME)),
                  ("X-Forwarded-User", {"X-Forwarded-User": "mechant"}),
                  ("X-Auth-Request-User", {"X-Auth-Request-User": "mechant"}),
                  ("X-Forwarded-Email", {"X-Forwarded-Email": "x@mechant.example"})]
        FORGES += [("%s forgée" % nom, {nom: "marque-inventee-par-l-attaquant"})
                   for nom in marque_proxy.NOMS_ENTETE]
        FORGES += [("%s tronquée" % nom, {nom: marque_proxy.VALEUR[:-1]})
                   for nom in marque_proxy.NOMS_ENTETE]

        for chemin in ("/", "/authorize?response_type=code", "/revoke"):
            passants = []
            for quoi, tetes in FORGES:
                tetes = dict(tetes)
                tetes.update(marque_proxy.navigation())
                if chemin == "/revoke":
                    statut = formulaire(chemin, {"grant": "tout"}, tetes)[0]
                else:
                    statut = get(chemin, tetes)[0]
                if statut != 401:
                    passants.append("%s → %s" % (quoi, statut))
            ensembles(passants, [],
                      "%s : rien de ce qu'un inconnu peut écrire ne franchit "
                      "la frontière humaine" % chemin)

        # L'assertion inverse : la marque véritable, elle, entre. Sans elle,
        # « tout refuser » serait une façon de passer au vert.
        egal(get("/", humaines())[0], 200,
             "et la marque véritable ouvre bien la page humaine")

        # ---- D2 : aucun code en clair dans l'état ----------------------
        # `empreinte()` promet noir sur blanc que le fichier d'état volé ne
        # donne aucun jeton utilisable. L'URL de réponse de la fenêtre de
        # grâce recopiait le code tel quel — instantané de PVC, kubectl cp.
        print("\nD2. le code d'autorisation n'est jamais persisté en clair")
        vivant("D2")
        session = flux(etat="d2", echanger=False)
        ok(not session.get("erreur"), "un consentement aboutit — %s"
           % session.get("erreur", ""))
        code_d2 = session.get("code") or ""
        fichier = etat_brut()
        ok(bool(code_d2), "un code a bien été émis : sans lui on ne cherche rien")
        ok(code_d2 and code_d2 not in fichier,
           "le code émis ne se lit pas dans le fichier d'état")
        ok("code=" not in fichier,
           "et aucune URL de réponse porteuse d'un code n'y dort non plus")
        ensembles([c for c in (code_d2,) if c and c in fichier], [],
                  "rien de ce qui a été émis ne se relit sur le volume")
        # … et il reste échangeable : ne plus rien écrire serait une façon de
        # passer au vert en cassant l'autorisation.
        statut, _, corps = formulaire("/token", {
            "grant_type": "authorization_code", "code": code_d2,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": session["verifier"]})
        egal(statut, 200, "le code reste échangeable : rien n'a été cassé")
        acces_d2 = js(corps).get("access_token") or ""
        ok(bool(acces_d2), "  et il délivre un jeton d'accès")

        # ---- D3 : la grâce ne re-livre pas un code consommé ------------
        # Le geste même pour lequel la grâce existe — recharger la page —
        # renvoyait un code déjà échangé. L'échanger une seconde fois révoque
        # toute la famille et tue l'autorisation qui marchait.
        print("\nD3. recharger /consent ne re-livre pas un code déjà échangé")
        vivant("D3")
        session = flux(etat="d3", echanger=False)
        csrf3, code3 = session.get("csrf", ""), session.get("code", "")
        ok(bool(code3), "un code est émis — %s" % session.get("erreur", ""))

        # Avant l'échange, la grâce doit rester : c'est elle qui sort
        # l'utilisateur du cul-de-sac quand il recharge.
        _, tetes, _ = consentir(csrf3)
        egal(code_de(tetes.get("Location")), code3,
             "recharger AVANT l'échange rend la même réponse : la grâce vit")

        statut, _, corps = formulaire("/token", {
            "grant_type": "authorization_code", "code": code3,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": session["verifier"]})
        egal(statut, 200, "le code s'échange")
        acces3 = js(corps).get("access_token") or ""

        _, tetes, _ = consentir(csrf3)
        relivres = {code_de(tetes.get("Location"))} - {""}
        ensembles(relivres & {code3}, [],
                  "recharger APRÈS l'échange ne re-livre pas le code consommé")
        # Ni un code NEUF : le jeton anti-CSRF a servi, et une grâce qui bat
        # monnaie à chaque rechargement remplacerait un trou par un autre.
        ensembles([c for c in relivres
                   if formulaire("/token", {
                       "grant_type": "authorization_code", "code": c,
                       "redirect_uri": REDIRECT, "client_id": CLIENT,
                       "code_verifier": session["verifier"]})[0] == 200], [],
                  "et rien de ce qu'elle re-livre n'est échangeable")
        # Et surtout : le rechargement n'a rien tué. C'est le dégât réel de la
        # dette — un rejeu déclenché par un geste innocent.
        egal(rpc("tools/list", {}, acces3)[0], 200,
             "et l'autorisation qui marchait marche toujours")
        egal(rpc("tools/list", {}, acces_d2)[0], 200,
             "  celle d'avant aussi : aucune famille n'a été révoquée")

        # ---- D4 : un /token anonyme en échec n'écrit pas ---------------
        # /token est l'un des sept chemins sortis de l'authentification :
        # n'importe qui l'atteint. Six chemins de refus réécrivaient tout
        # l'état sous le verrou global que /mcp doit prendre.
        print("\nD4. un /token anonyme en échec ne réécrit pas l'état")
        vivant("D4")
        # Un code VIERGE, jamais échangé : présenté avec un mauvais client_id,
        # il emprunte un chemin de refus qui ne doit rien consommer. Y mettre
        # un code déjà échangé ferait tout autre chose — un rejeu, qui révoque
        # la famille, et dont l'écriture serait parfaitement légitime.
        vierge = flux(etat="d4-vierge", echanger=False)
        ok(bool(vierge.get("code")), "un code vierge est disponible — %s"
           % vierge.get("erreur", ""))
        vieillir_etat()
        avant = signature_etat()
        ok(bool(avant), "il y a bien un état sur le volume à surveiller")
        REFUS = [
            ("code inconnu", {"grant_type": "authorization_code",
                              "code": "code-qui-n-a-jamais-existe",
                              "redirect_uri": REDIRECT, "client_id": CLIENT,
                              "code_verifier": "v" * 43}),
            ("rafraîchissement inconnu", {"grant_type": "refresh_token",
                                          "refresh_token": "jamais-emis",
                                          "client_id": CLIENT}),
            ("client_id qui ne correspond pas",
             {"grant_type": "authorization_code", "code": vierge.get("code", "x"),
              "redirect_uri": REDIRECT, "client_id": "un-autre-client",
              "code_verifier": "v" * 43}),
            ("adresse de retour qui ne correspond pas",
             {"grant_type": "authorization_code", "code": vierge.get("code", "x"),
              "redirect_uri": "https://mechant.example/cb", "client_id": CLIENT,
              "code_verifier": "v" * 43}),
            ("type de permission inconnu", {"grant_type": "客", "code": "x"}),
        ]
        statuts = []
        for _quoi, champs in REFUS * 5:
            statuts.append(formulaire("/token", champs)[0])
        ensembles([s for s in statuts if s == 200], [],
                  "aucun de ces %d appels anonymes n'a délivré quoi que ce soit"
                  % len(statuts))
        egal(signature_etat(), avant,
             "et aucun n'a réécrit l'état : ni inode, ni horodatage, ni contenu")

        # L'assertion inverse : ce qui DOIT être écrit l'est toujours. Un
        # serveur qui ne persiste plus rien passerait la précédente.
        session = flux(etat="d4")
        ok(not session.get("erreur"), "un flux légitime aboutit encore — %s"
           % session.get("erreur", ""))
        ok(signature_etat() != avant,
           "et lui, il a bien écrit : le volume n'est pas gelé")
        acces_d4 = session.get("acces") or ""

        # ---- D5 : /revoke exige un jeton anti-CSRF ---------------------
        # Le Basic est un credential ambiant : le navigateur le rejoue seul sur
        # une soumission inter-site. Une page hostile révoquait tout.
        print("\nD5. /revoke est protégé comme /consent")
        vivant("D5")
        statut, _, accueil = get("/", humaines())
        egal(statut, 200, "la page d'accueil s'affiche")
        csrf5 = csrf_de(accueil)
        ok(bool(csrf5), "elle porte un jeton anti-CSRF pour la révocation")

        HOSTILES = [
            ("sans jeton anti-CSRF", {}, {}),
            ("avec un jeton inventé", {"csrf": "invente-de-toutes-pieces"}, {}),
            ("depuis une origine étrangère", {"csrf": csrf5},
             {"Origin": "https://mechant.example"}),
            ("en soumission inter-site", {"csrf": csrf5},
             {"Sec-Fetch-Site": "cross-site"}),
        ]
        acceptes = []
        for quoi, champs, tetes in HOSTILES:
            corps = {"grant": "tout"}
            corps.update(champs)
            statut = formulaire("/revoke", corps, humaines(tetes))[0]
            if statut not in (400, 403):
                acceptes.append("%s → %s" % (quoi, statut))
        ensembles(acceptes, [],
                  "aucune soumission hostile n'est acceptée par /revoke")
        # La preuve n'est pas le code de retour : c'est que l'autorisation vit
        # encore. Un 403 qui révoque quand même est exactement la faute.
        egal(rpc("tools/list", {}, acces_d4)[0], 200,
             "et rien n'a été révoqué : le jeton d'avant fonctionne encore")
        egal(rpc("tools/list", {}, acces3)[0], 200,
             "  ni celui d'avant l'avant")

        # L'assertion inverse : la vraie révocation, elle, coupe. Sans elle,
        # « refuser tout le monde » passerait pour un correctif.
        statut, _, _ = formulaire("/revoke", {"grant": "tout", "csrf": csrf5},
                                  humaines())
        ok(statut in (302, 303), "une révocation légitime est acceptée — %s" % statut)
        ensembles([n for n, j in (("d2", acces_d2), ("d3", acces3), ("d4", acces_d4))
                   if rpc("tools/list", {}, j)[0] == 200], [],
                  "et elle coupe TOUTE la famille, pas le seul jeton présenté")

        # ---- D6 : un port malformé rend une réponse --------------------
        # Un chemin public et non authentifié qui coupe la socket et crache une
        # trace de pile : le contrôle d'audience devenait une porte de déni de
        # service.
        print("\nD6. un port malformé dans `resource` rend une réponse HTTP")
        vivant("D6")
        MALFORMEES = ["https://exemple.test:99999/mcp",
                      "https://exemple.test:99999999/mcp",
                      "https://exemple.test:port/mcp",
                      "https://exemple.test:-1/mcp",
                      "http://[::1:80/mcp"]
        muettes, mauvaises = [], []
        for ressource in MALFORMEES:
            statut, _, corps = formulaire("/token", {
                "grant_type": "authorization_code", "code": "x",
                "redirect_uri": REDIRECT, "client_id": CLIENT,
                "code_verifier": "v" * 43, "resource": ressource})
            if statut == 0:
                muettes.append(ressource)
            elif not (statut == 400 and js(corps).get("error") == "invalid_target"):
                mauvaises.append("%s → %s %s" % (ressource, statut, corps[:60]))
        ensembles(muettes, [], "/token répond à chaque ressource malformée")
        ensembles(mauvaises, [],
                  "et la traite comme une ressource inconnue : 400 invalid_target")

        muettes = []
        for ressource in MALFORMEES:
            _, defi = pkce()
            statut, tetes, _ = page_consentement(
                params_autorisation(defi, SCOPE_LIRE, ressource, "d6"))
            if statut == 0:
                muettes.append(ressource)
        ensembles(muettes, [], "/authorize aussi répond à chacune")
        vivant("D6 — après les ressources malformées")
        egal(get("/healthz")[0], 200, "et le serveur sert encore la sonde")

        # ---- D7 : le code_verifier doit être celui du RFC 7636 ---------
        # `encode('ascii','ignore')` tronquait : le contrôle cessait de prouver
        # « le client est celui qui a demandé le code » — la seule chose que
        # PKCE existe pour prouver.
        print("\nD7. un code_verifier hors du RFC 7636 est refusé")
        vivant("D7")
        # Première famille : la TRONCATURE. Le défi porte sur le vrai verifier,
        # et on en présente une variante que `encode('ascii','ignore')` ramenait
        # à lui. C'est là que le contrôle cessait de prouver quoi que ce soit.
        acceptes, rejets_legitimes = [], []
        for quoi, faux in [("un caractère non-ASCII ajouté", "%sé"),
                           ("un caractère non-ASCII de chaque côté", "é%sø"),
                           ("un caractère hors plan de base ajouté", "%s\U0001f600")]:
            vrai = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
            session = flux(etat="d7-troncature", verifier=vrai, echanger=False)
            code = session.get("code") or ""
            if not code:
                acceptes.append("%s : aucun code émis (%s)"
                                % (quoi, session.get("erreur", "")))
                continue
            base_t = {"grant_type": "authorization_code", "code": code,
                      "redirect_uri": REDIRECT, "client_id": CLIENT}
            if formulaire("/token", dict(base_t, code_verifier=faux % vrai))[0] == 200:
                acceptes.append("%s → jeton délivré" % quoi)
            # Le refus ne doit rien avoir consommé : le vrai verifier marche
            # encore. Sans cette moitié, « tout refuser » passerait au vert.
            if formulaire("/token", dict(base_t, code_verifier=vrai))[0] != 200:
                rejets_legitimes.append(quoi)
        ensembles(acceptes, [],
                  "aucune variante du vrai verifier n'obtient de jeton : ce que "
                  "PKCE prouve, c'est que le porteur est celui qui a demandé")
        ensembles(rejets_legitimes, [],
                  "et après chaque refus, le verifier légitime marche encore")

        # Seconde famille : la FORME. Le défi porte cette fois sur le verifier
        # malformé lui-même — le hachage CONCORDE donc. Ce qui doit refuser
        # n'est pas le hachage mais `[A-Za-z0-9._~-]{43,128}`, que le RFC 7636
        # impose et que personne ne vérifiait.
        acceptes, sans_code = [], []
        for quoi, faux in [("trop court (42 caractères)", "a" * 42),
                           ("trop long (129 caractères)", "a" * 129),
                           ("hors alphabet (+ / =)", "a+b/c=" * 8),
                           ("hors alphabet (espace)", "a b c d " * 6 + "abcdefghij"),
                           ("hors alphabet (deux-points)", "a:b:c:" * 8)]:
            session = flux(etat="d7-forme", verifier=faux, echanger=False)
            code = session.get("code") or ""
            if not code:
                # /authorize l'a refusé plus tôt : le verifier n'a jamais servi.
                # C'est un refus valable, mais il faut le distinguer.
                sans_code.append(quoi)
                continue
            statut, _, _ = formulaire("/token", {
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": REDIRECT, "client_id": CLIENT,
                "code_verifier": faux})
            if statut == 200:
                acceptes.append("%s → jeton délivré alors que le hachage "
                                "concorde" % quoi)
        ensembles(acceptes, [],
                  "aucun verifier hors de la forme du RFC 7636 n'obtient de "
                  "jeton, hachage concordant ou non")
        print("   %d forme(s) refusée(s) dès /authorize" % len(sans_code))

        # Et la forme légitime, elle, aboutit : refuser tout le monde n'est pas
        # un correctif.
        session = flux(etat="d7-legitime")
        ok(not session.get("erreur"),
           "un verifier conforme obtient toujours son jeton — %s"
           % session.get("erreur", ""))

        # ---- D8 : des params malformés rendent une erreur JSON-RPC -----
        # `params` non-objet ou `name` non-hachable levaient AVANT le contrôle
        # de portée : connexion coupée, trace de pile, contrôle jamais atteint.
        print("\nD8. des params malformés sur /mcp rendent une erreur JSON-RPC")
        vivant("D8")
        lecture = flux(scope=SCOPE_LIRE, etat="d8")
        ok(not lecture.get("erreur"), "une session en lecture seule aboutit — %s"
           % lecture.get("erreur", ""))
        jeton_lecture = lecture.get("acces") or ""

        # Ce que D8 nomme, et rien de plus : un `params` qui n'est pas un objet,
        # un `name` qui n'est pas hachable. Tous deux levaient AVANT le
        # contrôle de portée — c'est cet ordre-là qui est en cause.
        MALFORMES = [("params en liste", ["tools"]),
                     ("params en chaîne", "ajoute_enregistrement"),
                     ("params en nombre", 7),
                     ("params en booléen", True),
                     ("name en objet", {"name": {"a": 1}}),
                     ("name en liste", {"name": ["ajoute_enregistrement"]}),
                     ("name en objet, arguments d'écriture",
                      {"name": {"ajoute_enregistrement": 1},
                       "arguments": {"zone": "exemple.ch", "type": "A",
                                     "target": "203.0.113.9"}})]
        faux_api.RECU.clear()
        muets, sans_erreur = [], []
        for quoi, params in MALFORMES:
            statut, _, sortie = rpc("tools/call", params, jeton_lecture)
            if statut == 0:
                muets.append(quoi)
                continue
            erreur = sortie.get("error")
            if not (statut == 200 and isinstance(erreur, dict)
                    and isinstance(erreur.get("code"), int)
                    and "result" not in sortie):
                sans_erreur.append("%s → %s %s" % (quoi, statut,
                                                   json.dumps(sortie)[:80]))
        ensembles(muets, [], "chaque appel malformé reçoit une réponse")
        ensembles(sans_erreur, [], "et chacune est une erreur JSON-RPC en règle")
        ensembles([r["chemin"] for r in faux_api.RECU], [],
                  "et aucun n'a atteint l'API : le contrôle précède l'appel")
        vivant("D8 — après les params malformés")

        # Le contrôle de portée est atteint quoi qu'on lui présente : c'est ce
        # que la trace de pile court-circuitait.
        faux_api.RECU.clear()
        statut, _, sortie = rpc("tools/call", {
            "name": "ajoute_enregistrement",
            "arguments": {"zone": "exemple.ch", "type": "A",
                          "target": "203.0.113.9"}}, jeton_lecture)
        ok(statut == 403 and js(json.dumps(sortie)).get("error") == "insufficient_scope",
           "un jeton de lecture ne peut pas appeler un outil d'écriture — %s %s"
           % (statut, json.dumps(sortie)[:100]))
        ensembles([r["chemin"] for r in faux_api.RECU
                   if r["methode"] in ("POST", "PUT", "DELETE")], [],
                  "et rien n'est parti vers l'API")

        # ---- D11 : la cloison lecture / écriture -----------------------
        # `portee_outil()` lit une marque en tête de description. La renommer
        # dans infomaniak_mcp.py ferait basculer TOUS les outils en lecture,
        # en silence.
        print("\nD11. la cloison lecture/écriture tombe où elle doit")
        vivant("D11")
        ecriture = flux(scope=SCOPE_LIRE + " " + SCOPE_ECRIRE, etat="d11")
        jeton_ecriture = ecriture.get("acces") or ""
        ok(not ecriture.get("erreur"), "une session complète aboutit — %s"
           % ecriture.get("erreur", ""))

        _, _, sortie = rpc("tools/list", {}, jeton_ecriture)
        inventaire = [t.get("name") for t in
                      sortie.get("result", {}).get("tools", [])]
        ensembles(inventaire, ECRITURE_ATTENDUE | LECTURE_ATTENDUE,
                  "l'inventaire des outils est complet : un outil ajouté sans "
                  "être rangé d'un côté ou de l'autre se voit ici")

        # La source indépendante : ce que la DÉCLARATION dit, et non la marque
        # qu'on en a tirée. Deux dérivations qui doivent tomber d'accord —
        # renommer la marque d'un seul côté les fait diverger.
        import ast                                          # noqa: E402
        declares = set()
        arbre = ast.parse((RACINE / "infomaniak_mcp.py").read_text("utf-8"))
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.Call) and getattr(noeud.func, "id", "") == "_o":
                drapeaux = {mc.arg: getattr(mc.value, "value", None)
                            for mc in noeud.keywords}
                if drapeaux.get("ecrit") or drapeaux.get("depense"):
                    declares.add(ast.literal_eval(noeud.args[0]))
        ensembles(declares, ECRITURE_ATTENDUE,
                  "les outils DÉCLARÉS écrivains sont ceux qu'on attend")

        faux_api.RECU.clear()
        refuses = set()
        for nom in sorted(ECRITURE_ATTENDUE | LECTURE_ATTENDUE):
            statut, _, sortie = rpc("tools/call", {"name": nom, "arguments": {}},
                                    jeton_lecture)
            if statut == 403 and js(json.dumps(sortie)).get("error") == "insufficient_scope":
                refuses.add(nom)
        ensembles(refuses, ECRITURE_ATTENDUE,
                  "un jeton de LECTURE se voit refuser exactement les outils "
                  "qui écrivent — ni plus, ni moins")

        refuses = set()
        for nom in sorted(ECRITURE_ATTENDUE | LECTURE_ATTENDUE):
            statut, _, sortie = rpc("tools/call", {"name": nom, "arguments": {}},
                                    jeton_ecriture)
            if statut == 403 and js(json.dumps(sortie)).get("error") == "insufficient_scope":
                refuses.add(nom)
        ensembles(refuses, [],
                  "un jeton des DEUX portées ne se voit refuser aucun outil")
        ensembles([r["chemin"] for r in faux_api.RECU
                   if r["methode"] in ("POST", "PUT", "DELETE")], [],
                  "et la cloison s'éprouve sans qu'aucune écriture ne parte : "
                  "l'armement reste désarmé sous la portée")

        # ---- D10 : le contrôle d'audience ------------------------------
        # Signalé par l'agent qui a écrit le serveur, pas par un auditeur. Un
        # contrôle qu'aucun test ne mord est un contrôle dont on ne sait rien.
        print("\nD10. un jeton présenté sous une autre adresse est refusé")
        vivant("D10")
        egal(rpc("tools/list", {}, jeton_ecriture)[0], 200,
             "le jeton fonctionne là où il a été émis")

        AUTRE_PORT = port_libre()
        AUTRE_BASE = "http://127.0.0.1:%d" % AUTRE_PORT
        # Même état, même jetons : SEULE l'adresse publique change. Ce qui
        # refusera ne peut donc être que le contrôle d'audience.
        autre = lance("autre-adresse", RACINE, ETAT, AUTRE_PORT)
        if autre is not None:
            statut, tetes, _ = rpc("tools/list", {}, jeton_ecriture, base=AUTRE_BASE)
            egal(statut, 401,
                 "le même jeton, présenté sous une AUTRE adresse publique, "
                 "est refusé")
            ok("invalid_token" in (tetes.get("WWW-Authenticate") or ""),
               "  et le défi le dit — %s" % tetes.get("WWW-Authenticate", "(aucun)"))
            egal(rpc("tools/list", {}, jeton_ecriture)[0], 200,
                 "  tandis qu'il fonctionne toujours sous la sienne")
            autre.terminate()

        # L'autre moitié de la mutation : altérer l'audience DANS l'état. Si le
        # contrôle disparaissait, ce jeton passerait quand même.
        etats = fichiers_etat()
        ok(bool(etats), "il y a bien un fichier d'état à altérer")
        if etats:
            fichier_etat = etats[0]
            original = fichier_etat.read_bytes()
            altere = original.replace((BASE + "/mcp").encode(),
                                      b"https://ailleurs.example/mcp")
            ok(altere != original,
               "l'adresse de la ressource est bien inscrite dans l'état : "
               "sans elle, le contrôle d'audience n'aurait rien à comparer")
            fichier_etat.write_bytes(altere)
            egal(rpc("tools/list", {}, jeton_ecriture)[0], 401,
                 "un jeton dont l'audience a été altérée est refusé")
            fichier_etat.write_bytes(original)
            egal(rpc("tools/list", {}, jeton_ecriture)[0], 200,
                 "  et l'état rendu, il refonctionne : c'est bien l'audience "
                 "qui a refusé, pas un état cassé")

        # ---- D12 : /_whoami, l'empreinte du code chargé ----------------
        # Quatre cases du tableau d'amorçage sont vides. Celle-ci — « quel
        # artefact tourne ? » — se remplit avec une empreinte servie, pas avec
        # un ETAT.md qui affirme.
        print("\nD12. /_whoami sert l'empreinte du code chargé")
        vivant("D12")
        statut, _, whoami = get("/_whoami", humaines())
        egal(statut, 200, "/_whoami répond")
        empreintes = hexs(whoami)
        ok(bool(empreintes),
           "il porte au moins une empreinte — %s" % whoami[:160])
        ok(faux_api.JETON not in whoami, "le jeton d'API n'y figure pas")
        ok(COMPTE not in whoami, "l'identifiant de compte non plus")
        ensembles([j for j in (jeton_ecriture, jeton_lecture) if j and j in whoami],
                  [], "ni aucun jeton OAuth en cours")

        # L'empreinte doit être fonction du CODE, et de lui seul : deux pods
        # qui servent le même code doivent s'annoncer pareil, deux artefacts
        # différents doivent se distinguer. On lance donc trois copies — une
        # intacte, une dont serveur.py a bougé d'un octet, une dont
        # infomaniak_mcp.py a bougé.
        def copie(nom, perturbe=None):
            dossier = tempfile.mkdtemp(prefix="durcissement-copie-%s-" % nom)
            JETABLES.append(dossier)
            for fichier in ("serveur.py", "infomaniak_mcp.py"):
                shutil.copy2(str(RACINE / fichier), os.path.join(dossier, fichier))
            if perturbe:
                with open(os.path.join(dossier, perturbe), "a", encoding="utf-8") as fh:
                    fh.write("\n# une perturbation d'un octet, posée par le banc\n")
            etat = tempfile.mkdtemp(prefix="durcissement-copie-etat-")
            JETABLES.append(etat)
            port = port_libre()
            proc = lance("copie-%s" % nom, dossier, etat, port)
            adresse = "http://127.0.0.1:%d" % port
            vus = hexs(get("/_whoami", humaines(), adresse)[2]) if proc else set()
            if proc is not None:
                proc.terminate()
            return vus

        temoin = copie("temoin")
        ok(bool(temoin), "la copie témoin sert elle aussi une empreinte")
        ensembles(temoin, empreintes,
                  "deux processus qui servent le MÊME code s'annoncent pareil — "
                  "sinon l'empreinte ne compare rien d'un pod à l'autre")
        for fichier in ("serveur.py", "infomaniak_mcp.py"):
            perturbee = copie(fichier.split(".")[0], fichier)
            ok(bool(perturbee) and perturbee != temoin,
               "un octet changé dans %s change l'empreinte : l'artefact chargé "
               "est bien ce qu'elle décrit" % fichier)

        # ---- D9 : /authorize refuse ce qui n'est pas une navigation ----
        # Tous les paramètres sont publics. Une page hostile boucle sur une
        # balise <img>, le navigateur rejoue le Basic, et chaque requête ajoute
        # une entrée et réécrit tout le JSON. Cette section vient en dernier :
        # elle inonde volontairement l'état.
        print("\nD9. /authorize refuse ce qui n'est pas une navigation")
        vivant("D9")
        _, defi9 = pkce()
        parametres = params_autorisation(defi9, SCOPE_LIRE, etat="d9")

        CONTEXTES = [
            ("balise <img>", {"Sec-Fetch-Dest": "image",
                              "Sec-Fetch-Mode": "no-cors",
                              "Sec-Fetch-Site": "cross-site"}),
            ("appel fetch() inter-site", {"Sec-Fetch-Dest": "empty",
                                          "Sec-Fetch-Mode": "cors",
                                          "Sec-Fetch-Site": "cross-site"}),
            ("iframe", {"Sec-Fetch-Dest": "iframe",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "cross-site"}),
            ("script", {"Sec-Fetch-Dest": "script",
                        "Sec-Fetch-Mode": "no-cors",
                        "Sec-Fetch-Site": "same-origin"}),
        ]
        vieillir_etat()
        avant = signature_etat()
        servis = []
        for quoi, tetes in CONTEXTES:
            entetes = dict(HUMAIN)
            entetes.update(tetes)
            statut, _, html = get("/authorize?" + urllib.parse.urlencode(parametres),
                                  entetes)
            if statut == 200 and csrf_de(html):
                servis.append("%s → page de consentement servie" % quoi)
        ensembles(servis, [],
                  "aucun contexte de non-navigation n'obtient la page de "
                  "consentement")
        egal(signature_etat(), avant,
             "et aucun n'a écrit sur le volume : ni inode, ni horodatage")

        # L'assertion inverse : une vraie navigation passe, et elle écrit.
        statut, _, html = page_consentement(parametres)
        egal(statut, 200, "une navigation véritable, elle, obtient la page")
        ok(bool(csrf_de(html)), "  avec son jeton anti-CSRF")
        ok(signature_etat() != avant,
           "  et elle a persisté sa demande : c'est de là que /consent relira "
           "les paramètres plutôt que du corps qu'on lui poste")

        # La borne. Sans elle, une page hostile fait grossir le JSON sans fin.
        _, defi_flot = pkce()
        flot = params_autorisation(defi_flot, SCOPE_LIRE, etat="flot")
        interroge = "/authorize?" + urllib.parse.urlencode(flot)
        for _ in range(300):
            get(interroge, humaines())
        gardees = etat_brut().count(defi_flot)
        ok(1 <= gardees < 300,
           "300 demandes n'en laissent qu'un nombre borné dans l'état — %d "
           "gardée(s)" % gardees)
        print("   %d demande(s) gardée(s) sur 300" % gardees)

        # Et le propriétaire garde sa porte : une borne qui l'enferme dehors
        # remplace un déni de service par un autre.
        session = flux(etat="apres-le-flot")
        ok(not session.get("erreur"),
           "et le propriétaire s'autorise encore après le flot — %s"
           % session.get("erreur", ""))
        vivant("D9 — après le flot")

        # ---- le secret ne fuit nulle part ------------------------------
        print("\nle jeton Infomaniak ne fuit ni dans les réponses ni au journal")
        ok(not any(faux_api.JETON in c for c in CORPS_VUS),
           "le jeton d'API n'apparaît dans aucune réponse")
        ok(faux_api.JETON not in tout_le_journal(),
           "ni dans ce que les serveurs ont journalisé")

except SystemExit:
    pass
except Exception as err:                                    # noqa: BLE001
    import traceback
    ECHECS.append("la suite s'est interrompue : %s: %s\n%s"
                  % (type(err).__name__, err, traceback.format_exc()))
    VERIFS += 1

finally:
    QUEUE = tout_le_journal()
    for _nom, proc, journal in PROCS:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:                               # noqa: BLE001
                proc.kill()
        try:
            journal.close()
        except Exception:                                   # noqa: BLE001
            pass
    API_SERVEUR.shutdown()
    for jetable in JETABLES:
        shutil.rmtree(jetable, ignore_errors=True)

if ECHECS and QUEUE.strip():
    print("--- ce que les serveurs ont dit ---")
    print(QUEUE[-1200:])

print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
