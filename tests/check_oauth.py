#!/usr/bin/env python3
"""Le serveur d'autorisation et le transport MCP, éprouvés de bout en bout.

    python3 tests/check_oauth.py

Avant `serveur.py`, ce dépôt ne s'ouvrait qu'à qui tenait déjà la machine :
stdio, un processus, un utilisateur. Après, il est joignable depuis Internet et
sa sécurité tient entièrement dans un serveur d'autorisation écrit à la main.
Chaque refus que la spec exige « sans exception » a ici son test.

Le banc d'essai est **jetable** : un `serveur.py` lancé en sous-processus sur un
port libre, un répertoire d'état temporaire, et la fausse API du dépôt à la
place d'Infomaniak. Rien ne sort de la machine, aucun jeton réel n'est employé,
et la production n'est jamais touchée.

Le contrat de lancement, tenu par ce fichier :

    INFOMANIAK_LISTEN_PORT   le port d'écoute — le Service s'appellera
                             `infomaniak-domains`, donc k8s injectera
                             `INFOMANIAK_DOMAINS_PORT` et l'écoute doit avoir
                             sa propre variable, comme chez kiosquier.
    INFOMANIAK_DATA          le répertoire d'état OAuth (le PVC, en production)
    INFOMANIAK_HUMAIN        « utilisateur:mot_de_passe » de la page humaine.
                             Facultatif : en production la frontière humaine est
                             chez Traefik. La suite **constate** le régime en
                             vigueur au lieu de le supposer.

Trois règles tenues partout ici :

1. Quand on affirme qu'un geste n'a **pas** eu lieu, on le constate côté
   serveur. Un `GET /authorize` qui ne montre pas de code peut très bien en
   avoir écrit un dans l'état : on va donc chercher ce qu'il a écrit, et on
   éprouve que rien de neuf n'est échangeable contre un jeton.
2. Une assertion d'absence est verte quand la page ne rend rien du tout. On
   compare donc des **ensembles**, jamais une absence isolée.
3. Un `/healthz` qui répond ne prouve pas que c'est *notre* serveur. Chaque
   section exige d'abord que notre propre processus soit vivant.
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
import infomaniak_mcp as ik                                # noqa: E402
import marque_proxy                                        # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
BASIC = "Basic " + base64.b64encode(b"vincent:secret").decode()

VERIFS = 0
ECHECS = []
CORPS_VUS = []          # tout ce que le serveur nous a répondu, pour la fuite


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
    """Deux ensembles, et le rapport nomme ce qui manque et ce qui est en trop.

    Comparer autrement — une longueur, une appartenance isolée — rend vert un
    serveur qui ne rend rien du tout."""
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

PORT = port_libre()
BASE = "http://127.0.0.1:%d" % PORT
ETAT = tempfile.mkdtemp(prefix="check-oauth-etat-")
# Le journal vit ailleurs : dans le répertoire d'état, il fausserait l'empreinte
# de ce que le serveur y a réellement écrit.
BUREAU = tempfile.mkdtemp(prefix="check-oauth-log-")
JOURNAL = open(os.path.join(BUREAU, "sortie-serveur.txt"), "w+")

ENV = dict(os.environ)
ENV.update({
    "INFOMANIAK_LISTEN_PORT": str(PORT),
    "INFOMANIAK_DATA": ETAT,
    "INFOMANIAK_HUMAIN": "vincent:secret",
    # La fausse API tient le rôle d'Infomaniak : le connecteur appellera
    # celle-là et pas le vrai service, et elle enregistre chaque requête reçue.
    "INFOMANIAK_BASE": API_BASE,
    "INFOMANIAK_TOKEN": faux_api.JETON,
    "INFOMANIAK_ACCOUNT": "",
    "INFOMANIAK_RATE": "1000000",
    "PYTHONUNBUFFERED": "1",
})
# La marque du proxy, POSÉE : sans elle, le serveur retombe sur son exception
# de boucle locale et cette suite n'emprunterait jamais la frontière humaine
# telle que la production la tient. Un banc qui contourne le garde-fou qu'il
# est censé traverser ne dit rien de la production.
ENV.update(marque_proxy.env())
# Désarmés, comme en production : les armer se décide, ne se subit pas.
for arme in ("INFOMANIAK_WRITE", "INFOMANIAK_ACHAT", "INFOMANIAK_TOKEN_CMD"):
    ENV.pop(arme, None)

PROC = None


class PasDeRedirection(urllib.request.HTTPRedirectHandler):
    """Suivre la redirection emmènerait sur claude.ai, dont la réponse n'a rien
    à nous dire — et masquerait ce que notre serveur a réellement répondu."""

    def redirect_request(self, *args, **kwargs):
        return None


OUVREUR = urllib.request.build_opener(PasDeRedirection)


def http(methode, chemin, corps=None, ctype=None, entetes=None):
    """Rend (statut, en-têtes, corps). Un serveur injoignable est une donnée,
    pas un accident : sans ça, la suite tombe à la première route manquante au
    lieu de rendre son rapport."""
    requete = urllib.request.Request(BASE + chemin, data=corps, method=methode)
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
        statut, tetes, texte = 0, {}, "injoignable : %s" % err
    CORPS_VUS.append(texte)
    return statut, tetes, texte


def get(chemin, entetes=None):
    return http("GET", chemin, entetes=entetes)


def post(chemin, corps=b"", ctype="application/json", entetes=None):
    return http("POST", chemin, corps, ctype, entetes)


def formulaire(chemin, champs, entetes=None):
    return post(chemin, urllib.parse.urlencode(champs).encode(),
                "application/x-www-form-urlencoded", entetes)


def js(corps):
    try:
        return json.loads(corps)
    except ValueError:
        return {}


def code_erreur(sortie):
    """Le code d'erreur JSON-RPC, ou None. Un refus HTTP porte lui aussi une
    clé `error`, mais une chaîne : la lire sans regarder coûte une trace de
    pile au milieu du rapport."""
    erreur = (sortie or {}).get("error")
    return erreur.get("code") if isinstance(erreur, dict) else None


def rpc(methode, params=None, jeton=None, entetes=None):
    tetes = dict(entetes or {})
    if jeton:
        tetes["Authorization"] = "Bearer " + jeton
    corps = json.dumps({"jsonrpc": "2.0", "id": 1, "method": methode,
                        "params": params or {}}).encode()
    statut, tetes_rep, texte = post("/mcp", corps, "application/json", tetes)
    return statut, tetes_rep, js(texte)


def demarre():
    global PROC
    if not (RACINE / "serveur.py").exists():
        ok(False, "serveur.py n'existe pas encore : rien à éprouver")
        return False
    PROC = subprocess.Popen([sys.executable, str(RACINE / "serveur.py")],
                            env=ENV, stdout=JOURNAL, stderr=subprocess.STDOUT)
    # Le seul sommeil de la suite, et il ne mesure rien : il attend que le port
    # soit ouvert. Aucun scénario n'est éprouvé par l'attente — une expiration
    # se prouve en la posant dans l'état, jamais en dormant devant.
    limite = time.monotonic() + 15
    while time.monotonic() < limite:
        if PROC.poll() is not None:
            ok(False, "serveur.py s'est arrêté au démarrage (code %s) — %s"
               % (PROC.returncode, sortie_serveur()[-400:]))
            return False
        if get("/healthz")[0] == 200:
            return True
        time.sleep(0.02)
    ok(False, "serveur.py n'a pas répondu sur /healthz en 15 s")
    return False


def sortie_serveur():
    try:
        JOURNAL.flush()
        JOURNAL.seek(0)
        return JOURNAL.read()
    except Exception:                                       # noqa: BLE001
        return ""


def vivant(ou):
    """Un `/healthz` qui répond ne prouve pas que c'est le nôtre : sur un port
    réutilisé, n'importe quoi peut tenir le rôle."""
    ok(PROC is not None and PROC.poll() is None,
       "%s : notre processus serveur est vivant" % ou)


# --------------------------------------------------------------------------
# ce que le serveur a écrit — la seule preuve qu'un geste n'a pas eu lieu
# --------------------------------------------------------------------------

OPAQUE = re.compile(r"[A-Za-z0-9_\-]{20,}")


def etat_brut():
    """Le contenu de tous les fichiers d'état, concaténé."""
    morceaux = []
    for chemin in sorted(pathlib.Path(ETAT).rglob("*")):
        if chemin.is_file():
            try:
                morceaux.append(chemin.read_text("utf-8", "replace"))
            except OSError:
                pass
    return "\n".join(morceaux)


def empreinte_etat():
    trace = {}
    for chemin in sorted(pathlib.Path(ETAT).rglob("*")):
        if chemin.is_file():
            trace[str(chemin.relative_to(ETAT))] = hashlib.sha256(
                chemin.read_bytes()).hexdigest()
    return trace


def chaines_nouvelles(avant, apres, plafond=8):
    """Les valeurs opaques que le serveur a écrites entre deux instants.

    C'est le nerf du contrôle « /authorize n'émet jamais de code » : la page
    peut fort bien n'en montrer aucun tout en en ayant persisté un. On va donc
    chercher ce qu'elle a écrit, et on l'éprouve contre /token."""
    connues = set(OPAQUE.findall(avant))
    neuves = [c for c in OPAQUE.findall(apres) if c not in connues]
    vues, propres = set(), []
    for c in neuves:
        if c not in vues:
            vues.add(c)
            propres.append(c)
    return propres[:plafond]


def echangeable(code, verifier, client):
    """Ce code est-il accepté par /token ? Rend True s'il délivre un jeton."""
    statut, _, corps = formulaire("/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "client_id": client,
        "code_verifier": verifier})
    return statut == 200 and bool(js(corps).get("access_token"))


# --------------------------------------------------------------------------
# le flux d'autorisation
# --------------------------------------------------------------------------

def pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    defi = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, defi


def csrf_de(html):
    trouve = (re.search(r'name="csrf"[^>]*value="([^"]+)"', html)
              or re.search(r'value="([^"]+)"[^>]*name="csrf"', html))
    return trouve.group(1) if trouve else ""


HUMAIN = {}             # rempli à la première sonde — voir `marque_proxy`


def regime_humain(chemin):
    """Le chemin exige-t-il les identifiants humains ? On le constate."""
    statut, tetes, _ = get(chemin)
    return statut == 401 and "basic" in tetes.get("WWW-Authenticate", "").lower()


def page_consentement(params, entetes=None):
    tetes = dict(HUMAIN)
    tetes.update(entetes or {})
    return get("/authorize?" + urllib.parse.urlencode(params), tetes)


def consentir(csrf, champs=None, entetes=None):
    tetes = dict(HUMAIN)
    tetes.update(entetes or {})
    corps = {"csrf": csrf, "action": "autoriser"}
    corps.update(champs or {})
    return formulaire("/consent", corps, tetes)


def code_de(location):
    return (urllib.parse.parse_qs(
        urllib.parse.urlparse(location or "").query).get("code") or [""])[0]


def autoriser(client, scope, resource=None, etat="s1"):
    """Le flux complet jusqu'au jeton. Rend un dict de tout ce qu'on a vu —
    aucun raccourci : c'est exactement le chemin que Claude empruntera."""
    verifier, defi = pkce()
    params = {"response_type": "code", "client_id": client,
              "redirect_uri": REDIRECT, "code_challenge": defi,
              "code_challenge_method": "S256", "state": etat,
              "scope": scope, "resource": resource or (BASE + "/mcp")}
    statut, _, html = page_consentement(params)
    csrf = csrf_de(html)
    if statut != 200 or not csrf:
        return {"verifier": verifier, "defi": defi, "erreur":
                "page de consentement absente (statut %s)" % statut}
    _, tetes, _ = consentir(csrf)
    code = code_de(tetes.get("Location"))
    if not code:
        return {"verifier": verifier, "defi": defi, "csrf": csrf,
                "erreur": "aucun code émis par /consent"}
    statut, _, corps = formulaire("/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "client_id": client, "code_verifier": verifier})
    jetons = js(corps)
    return {"verifier": verifier, "defi": defi, "csrf": csrf, "code": code,
            "statut": statut, "acces": jetons.get("access_token") or "",
            "rafraichir": jetons.get("refresh_token") or "",
            "portee": jetons.get("scope") or "", "jetons": jetons}


# --------------------------------------------------------------------------

try:
    if demarre():

        # ---- 1. les documents de découverte ----------------------------
        print("\n1. les documents de découverte")
        vivant("découverte")
        statut, _, prm_brut = get("/.well-known/oauth-protected-resource")
        egal(statut, 200, "la ressource protégée est servie")
        prm = js(prm_brut)
        egal(prm.get("resource"), BASE + "/mcp",
             "elle nomme exactement l'adresse à coller dans Claude")
        egal(prm.get("authorization_servers"), [BASE],
             "et son serveur d'autorisation")
        portees = prm.get("scopes_supported") or []
        ok(len(portees) >= 2,
           "au moins deux portées sont annoncées : sans quoi « une portée "
           "élargie est refusée » ne veut rien dire — vu %r" % (portees,))
        egal(get("/.well-known/oauth-protected-resource/mcp")[2], prm_brut,
             "le chemin suffixé rend le MÊME document")

        statut, _, as_brut = get("/.well-known/oauth-authorization-server")
        egal(statut, 200, "les métadonnées du serveur d'autorisation sont servies")
        asm = js(as_brut)
        egal(asm.get("issuer"), BASE,
             "l'émetteur est l'hôte sur lequel on nous a appelés")
        egal(asm.get("issuer"), (prm.get("authorization_servers") or ["(absent)"])[0],
             "et il est identique à celui annoncé par la ressource")
        egal(asm.get("code_challenge_methods_supported"), ["S256"],
             "S256 est la seule méthode annoncée")
        egal(asm.get("token_endpoint_auth_methods_supported"), ["none"],
             "le client est public : aucun secret à porter")
        ensembles(
            [urllib.parse.urlparse(asm.get(cle) or "").path for cle in
             ("authorization_endpoint", "token_endpoint", "registration_endpoint")],
            ["/authorize", "/token", "/register"],
            "les trois adresses annoncées sont celles du contrat")
        ok(all((asm.get(cle) or "").startswith(BASE) for cle in
               ("authorization_endpoint", "token_endpoint", "registration_endpoint")),
           "et toutes portent l'émetteur, pas un autre hôte")

        statut, _, oidc_brut = get("/.well-known/openid-configuration")
        egal(statut, 200, "le document openid est servi lui aussi")
        egal(js(oidc_brut).get("issuer"), BASE, "  avec le même émetteur")
        egal(js(oidc_brut).get("code_challenge_methods_supported"), ["S256"],
             "  et la même exigence PKCE")

        # ---- 2. la frontière : ce qui s'atteint sans identifiants -------
        print("\n2. la frontière")
        vivant("frontière")
        MACHINE = ["/mcp", "/token", "/register",
                   "/.well-known/oauth-protected-resource",
                   "/.well-known/oauth-protected-resource/mcp",
                   "/.well-known/oauth-authorization-server",
                   "/.well-known/openid-configuration"]
        ensembles([c for c in MACHINE if regime_humain(c)], [],
                  "aucun chemin machine ne réclame les identifiants humains")
        # Le régime humain, lui, se constate — en production il est chez
        # Traefik, en local il peut être dans l'application. Ce qui compte est
        # qu'il soit le MÊME sur la page et sur le consentement : protéger l'une
        # sans l'autre laisserait l'autorisation à la portée de n'importe qui.
        regime_page = regime_humain("/")
        if regime_page:
            # Comment on entre se CONSTATE aussi : la marque du proxy depuis
            # D1, le Basic avant elle. Deviner le nom en dur ferait virer au
            # rouge un correctif juste — c'est la valeur qui protège, jamais le
            # nom de l'en-tête, qu'un inconnu peut écrire de toute façon.
            HUMAIN.update(marque_proxy.trouver(lambda t: get("/", t)[0] == 200)
                          or dict(marque_proxy.ANCIEN_REGIME))
        # Ce qu'un navigateur pose sur une vraie navigation : depuis D9,
        # /authorize refuse ce qui n'en est pas une.
        HUMAIN.update(marque_proxy.navigation())
        print("   régime humain constaté : %s"
              % ("identifiants exigés par l'application"
                 if regime_page else "frontière hors application"))

        # ---- 3. l'enregistrement de client -----------------------------
        print("\n3. /register — sans état et idempotent")
        vivant("register")
        avant = empreinte_etat()
        demande = json.dumps({"client_name": "Claude", "redirect_uris": [REDIRECT],
                              "grant_types": ["authorization_code", "refresh_token"],
                              "token_endpoint_auth_method": "none"}).encode()
        statut, _, corps = post("/register", demande)
        egal(statut, 201, "l'enregistrement rend 201")
        un = js(corps)
        CLIENT = un.get("client_id") or "client-inconnu"
        ok(bool(un.get("client_id")), "un client_id est rendu — %s" % corps[:120])
        ok(bool(un) and "client_secret" not in un,
           "aucun secret n'est émis : le client est public")
        egal(js(post("/register", demande)[2]).get("client_id"), un.get("client_id"),
             "un second enregistrement rend le MÊME client_id")
        egal(empreinte_etat(), avant,
           "rien n'est écrit sur le volume : un enregistrement qui écrit "
           "s'inonde depuis l'extérieur")
        statut, _, corps = post("/register", json.dumps(
            {"redirect_uris": ["https://mechant.example/callback"]}).encode())
        egal(statut, 400, "une adresse de retour hors liste est refusée")
        ok("redirect" in corps.lower(), "et le refus nomme ce qui coince — %s" % corps[:120])
        statut, _, corps = post("/register", json.dumps(
            {"redirect_uris": [REDIRECT], "client_name": "<script>x</script>"}).encode())
        ok("<script>" not in corps,
           "le nom fourni par le client n'est jamais renvoyé — %s" % corps[:120])

        # ---- 4. GET /authorize n'émet JAMAIS de code -------------------
        print("\n4. /authorize n'émet jamais de code")
        vivant("authorize")
        verifier, defi = pkce()
        base_q = {"response_type": "code", "client_id": CLIENT,
                  "redirect_uri": REDIRECT, "code_challenge": defi,
                  "code_challenge_method": "S256", "state": "s1",
                  "scope": " ".join(portees), "resource": BASE + "/mcp"}
        # /authorize n'est PAS un chemin machine : il doit relever du même
        # régime que la page humaine. Protéger l'une sans l'autre laisserait
        # l'autorisation à la portée de n'importe qui.
        egal(regime_humain("/authorize?" + urllib.parse.urlencode(base_q)), regime_page,
             "/authorize relève du même régime que la page humaine")

        avant_texte = etat_brut()
        statut, tetes, html = page_consentement(base_q)
        egal(statut, 200, "la page de consentement s'affiche")
        ok("Location" not in tetes, "aucune redirection — %s" % sorted(tetes))
        ok("code=" not in html, "aucun code dans le corps")
        ok("claude.ai" in html, "l'hôte du destinataire est montré au lecteur")
        ok("frame-ancestors 'none'" in tetes.get("Content-Security-Policy", ""),
           "le clickjacking est bloqué — %s" % tetes.get("Content-Security-Policy", "(aucune)"))
        egal(tetes.get("X-Frame-Options"), "DENY", "et l'encadrement refusé")

        # La preuve côté serveur : tout ce que /authorize vient d'écrire est
        # éprouvé contre /token. Une page qui ne montre pas de code peut très
        # bien en avoir persisté un.
        ecrits = chaines_nouvelles(avant_texte, etat_brut())
        # Sans candidat, l'assertion suivante serait verte parce qu'elle
        # n'éprouve rien — le piège de l'absence isolée. /authorize doit avoir
        # persisté sa demande : c'est de cet enregistrement que /consent relira
        # les paramètres, plutôt que du corps qu'on lui poste.
        ok(bool(ecrits),
           "/authorize a persisté sa demande côté serveur : sans quoi /consent "
           "lirait les paramètres d'autorisation dans son corps, et un "
           "formulaire fabriqué suffirait")
        print("   %d valeur(s) écrite(s) par /authorize, éprouvée(s) contre /token"
              % len(ecrits))
        ensembles([c for c in ecrits if echangeable(c, verifier, CLIENT)], [],
                  "et rien de ce qu'il a écrit n'est échangeable contre un jeton")

        for mauvais, pourquoi in [
                ({"client_id": "inconnu-au-bataillon"}, "client inconnu"),
                ({"redirect_uri": "https://mechant.example/cb"}, "destinataire hors liste"),
                ({"redirect_uri": REDIRECT + "/../x"}, "remontée de chemin")]:
            q = dict(base_q)
            q.update(mauvais)
            statut, tetes, _ = page_consentement(q)
            egal(statut, 400, "refusé localement : %s" % pourquoi)
            ok("Location" not in tetes,
               "  et sans rien renvoyer au destinataire : %s" % pourquoi)

        for mauvais, attendu in [({"code_challenge_method": "plain"}, "invalid_request"),
                                 ({"code_challenge": ""}, "invalid_request"),
                                 ({"response_type": "token"}, "unsupported_response_type"),
                                 ({"resource": "https://ailleurs.example/mcp"}, "invalid_target")]:
            q = dict(base_q)
            q.update(mauvais)
            statut, tetes, _ = page_consentement(q)
            loc = tetes.get("Location", "")
            ok(statut == 302 and attendu in loc,
               "%s rend l'erreur %s au client — statut=%s location=%s"
               % (list(mauvais)[0], attendu, statut, loc))
            ok("iss=" in loc, "  et l'émetteur accompagne le refus — %s" % loc)
            ok("code=" not in loc, "  et aucun code n'y est glissé — %s" % loc)

        # ---- 5. POST /consent, seul émetteur ---------------------------
        print("\n5. /consent — le seul endroit qui émet un code")
        vivant("consent")
        statut, _, html = page_consentement(base_q)
        csrf = csrf_de(html)
        ok(bool(csrf), "la page porte un jeton anti-CSRF")

        avant_texte = etat_brut()
        avant_empreinte = empreinte_etat()
        statut, _, _ = formulaire("/consent", {"action": "autoriser"}, dict(HUMAIN))
        egal(statut, 400, "sans jeton anti-CSRF, refusé")
        statut, _, _ = consentir("inventé-de-toutes-pièces")
        egal(statut, 400, "avec un jeton inventé, refusé")
        ensembles([c for c in chaines_nouvelles(avant_texte, etat_brut())
                   if echangeable(c, verifier, CLIENT)], [],
                  "et aucun de ces refus n'a émis de code échangeable")

        statut, tetes, _ = consentir(csrf, {"redirect_uri": "https://mechant.example/cb"})
        egal(statut, 302, "un destinataire glissé dans le corps est ignoré")
        loc = tetes.get("Location", "")
        ok(loc.startswith(REDIRECT), "  le code part chez le vrai destinataire — %s" % loc)
        code1 = code_de(loc)
        ok(bool(code1), "  un code est émis")
        ok("state=s1" in loc, "l'état du client est réémis tel quel — %s" % loc)
        ok("iss=" in loc, "l'émetteur accompagne la réponse — %s" % loc)
        ok(empreinte_etat() != avant_empreinte,
           "le code est persisté : un code non persisté est rejouable "
           "indéfiniment, et une relance du serveur l'oublierait")

        # Un jeton anti-CSRF ne sert qu'une fois. La formulation porte sur le
        # geste, pas sur le statut : ce qui doit être impossible, c'est qu'un
        # même jeton fabrique un SECOND code — qu'on le refuse sèchement ou
        # qu'on ramène le lecteur au même endroit, l'invariant est là.
        statut, tetes2, _ = consentir(csrf)
        code2 = code_de(tetes2.get("Location"))
        ok(code2 in ("", code1),
           "rejouer le jeton anti-CSRF n'émet pas un SECOND code — %r puis %r"
           % (code1, code2))
        statut, _, _ = consentir("jamais-vu-de-la-vie")
        egal(statut, 400, "un jeton jamais vu reste refusé")

        statut, _, html2 = page_consentement(base_q)
        csrf2 = csrf_de(html2)
        statut, _, corps = consentir(csrf2, entetes={"Origin": "https://mechant.example"})
        egal(statut, 403, "une origine étrangère est refusée")
        ok("mechant.example" in corps,
           "et le refus dit ce qu'il a reçu : un refus muet coûte une heure de "
           "diagnostic — %s" % corps[:120])
        statut, _, _ = consentir(csrf2, entetes={"Sec-Fetch-Site": "cross-site"})
        egal(statut, 403, "une soumission inter-site aussi")
        # Une origine OPAQUE n'est pas une origine étrangère : des navigateurs
        # l'envoient sur une navigation légitime, et la refuser bloque le
        # consentement pour de bon. La défense reste le jeton à usage unique.
        statut, tetes, _ = consentir(csrf2, entetes={"Origin": "null",
                                                     "Sec-Fetch-Site": "same-origin"})
        egal(statut, 302, "une origine opaque n'est PAS refusée")
        ok((tetes.get("Location") or "").startswith(REDIRECT),
           "  et le code part chez le destinataire attendu")

        # ---- 6. PKCE et l'échange du code ------------------------------
        print("\n6. PKCE S256 et l'échange du code")
        vivant("token")
        base_t = {"grant_type": "authorization_code", "code": code1,
                  "redirect_uri": REDIRECT, "client_id": CLIENT}
        statut, _, corps = formulaire("/token", base_t)
        egal(statut, 400, "sans code_verifier, refusé — le contournement le plus "
                          "fréquent des serveurs écrits à la main")
        egal(js(corps).get("error"), "invalid_grant", "  avec le code normalisé")
        statut, _, corps = formulaire("/token", dict(base_t, code_verifier="mauvais" * 8))
        egal(statut, 400, "avec un mauvais verifier, refusé")
        statut, _, corps = formulaire("/token", dict(
            base_t, code_verifier=verifier, resource="https://ailleurs.example/mcp"))
        egal(statut, 400, "un code échangé pour une AUTRE ressource est refusé")
        egal(js(corps).get("error"), "invalid_target", "  et le dit")

        statut, tetes, corps = formulaire("/token", dict(base_t, code_verifier=verifier))
        egal(statut, 200, "avec le bon verifier, un jeton est délivré")
        jetons = js(corps)
        ok(len(jetons.get("access_token") or "") >= 32,
           "le jeton d'accès est assez large pour n'être pas devinable")
        ok(bool(jetons.get("refresh_token")), "un jeton de rafraîchissement l'accompagne")
        egal(jetons.get("token_type"), "Bearer", "le type est Bearer")
        ok(isinstance(jetons.get("expires_in"), int) and jetons["expires_in"] > 0,
           "il expire — %r" % jetons.get("expires_in"))
        ok("no-store" in (tetes.get("Cache-Control") or "").lower(),
           "la réponse n'est pas mise en cache — %s" % tetes.get("Cache-Control", "(aucun)"))

        # ---- 7. le code rejoué révoque la famille ----------------------
        print("\n7. le rejeu")
        vivant("rejeu")
        acces_mort = jetons.get("access_token") or "absent"
        rafraichir_mort = jetons.get("refresh_token") or "absent"
        statut, _, _ = formulaire("/token", dict(base_t, code_verifier=verifier))
        egal(statut, 400, "rejouer le code est refusé")
        egal(rpc("tools/list", jeton=acces_mort)[0], 401,
             "et le jeton d'accès issu du code rejoué est révoqué")
        egal(formulaire("/token", {"grant_type": "refresh_token",
                                   "refresh_token": rafraichir_mort,
                                   "client_id": CLIENT})[0], 400,
             "toute la famille l'est : le rafraîchissement aussi")

        # ---- 8. le transport MCP ---------------------------------------
        print("\n8. le transport MCP")
        vivant("mcp")
        session = autoriser(CLIENT, " ".join(portees))
        ok(not session.get("erreur"), "une session complète aboutit — %s"
           % session.get("erreur", ""))
        acces = session.get("acces") or "absent"

        for corps, pourquoi in [(b"", "corps vide"),
                                (b"{", "JSON tronqué"),
                                (b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                                 "requête valide")]:
            statut, tetes, texte = post("/mcp", corps)
            egal(statut, 401, "sans Bearer, %s rend 401" % pourquoi)
            defi_auth = tetes.get("WWW-Authenticate", "")
            ok(defi_auth.startswith("Bearer"),
               "  avec un défi Bearer : %s — %s" % (pourquoi, defi_auth or "(aucun)"))
            ok("resource_metadata=" in defi_auth,
               "  qui pointe vers la ressource protégée : %s — %s" % (pourquoi, defi_auth))
            ok(BASE + "/.well-known/oauth-protected-resource" in defi_auth,
               "  et l'adresse y est complète : %s — %s" % (pourquoi, defi_auth))

        statut, _, texte = post("/mcp", b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                                "application/json", {"Authorization": BASIC})
        egal(statut, 401, "les identifiants humains n'ouvrent PAS le MCP")
        ensembles([n for n in ik.BY_NAME if n in texte], [],
                  "et aucun nom d'outil ne fuit dans le refus")

        statut, _, sortie = rpc("initialize", {"protocolVersion": "2025-06-18"}, acces)
        egal(statut, 200, "initialize répond")
        egal(sortie.get("result", {}).get("protocolVersion"), "2025-06-18",
             "  en renvoyant la version demandée")
        egal(sortie.get("result", {}).get("serverInfo", {}).get("name"), ik.NAME,
             "  et le nom du serveur, celui du module partagé")

        statut, tetes, texte = post(
            "/mcp", b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
            "application/json", {"Authorization": "Bearer " + acces})
        egal(statut, 202, "une notification rend 202")
        egal(texte, "", "  avec un corps vide")

        statut, _, sortie = rpc("methode/inconnue", jeton=acces)
        egal(statut, 200, "une méthode inconnue reste un 200 JSON-RPC")
        egal(code_erreur(sortie), -32601, "  avec le code -32601")
        # Porteur en main : sinon le 401 du défi masque la question posée, qui
        # est « ce transport est-il en POST seulement ».
        egal(get("/mcp", {"Authorization": "Bearer " + acces})[0], 405,
             "GET /mcp rend 405 : le transport est en POST seulement")

        statut, _, sortie = rpc("tools/list", jeton=acces)
        noms = [t.get("name") for t in sortie.get("result", {}).get("tools", [])]
        ensembles(noms, ik.BY_NAME.keys(),
                  "le MCP distant rend exactement les outils du module partagé")

        faux_api.RECU.clear()
        statut, _, sortie = rpc("tools/call", {"name": "domaines", "arguments": {}}, acces)
        texte = "".join(c.get("text", "") for c in sortie.get("result", {}).get("content", []))
        ok("exemple.ch" in texte,
           "un outil de lecture répond avec ce que l'API a rendu — %s" % texte[:160])
        ensembles([r["methode"] for r in faux_api.RECU], ["GET"],
                  "et il n'a fait que lire")

        # L'armement d'écriture ne franchit pas le transport : désarmé, il le
        # reste, et on le constate côté API — aucune requête n'est partie.
        faux_api.RECU.clear()
        statut, _, sortie = rpc("tools/call", {
            "name": "ajoute_enregistrement",
            "arguments": {"zone": "exemple.ch", "type": "A", "target": "203.0.113.9"}},
            acces)
        ok(sortie.get("result", {}).get("isError") is True or statut == 403,
           "un outil d'écriture refuse tant que INFOMANIAK_WRITE n'est pas posé")
        ensembles([r["chemin"] for r in faux_api.RECU
                   if r["methode"] in ("POST", "PUT", "DELETE")], [],
                  "et aucune écriture n'est partie vers l'API")

        # ---- 9. la rotation du rafraîchissement ------------------------
        print("\n9. la rotation du rafraîchissement")
        vivant("rafraîchissement")
        vieux = session.get("rafraichir") or "absent"
        statut, _, corps = formulaire("/token", {"grant_type": "refresh_token",
                                                 "refresh_token": vieux,
                                                 "client_id": CLIENT})
        egal(statut, 200, "le rafraîchissement délivre un jeton")
        neuf = js(corps)
        ok(bool(neuf.get("refresh_token")), "et un nouveau jeton de rafraîchissement")
        ok(neuf.get("refresh_token") != vieux, "  différent de l'ancien : il tourne")
        ok(neuf.get("access_token") not in ("", None, session.get("acces")),
           "  et un nouveau jeton d'accès")
        egal(rpc("tools/list", jeton=neuf.get("access_token") or "x")[0], 200,
             "le jeton frais ouvre le MCP")

        statut, _, _ = formulaire("/token", {"grant_type": "refresh_token",
                                             "refresh_token": vieux,
                                             "client_id": CLIENT})
        egal(statut, 400, "réutiliser l'ancien rafraîchissement est refusé")
        egal(rpc("tools/list", jeton=neuf.get("access_token") or "x")[0], 401,
             "et toute la famille est révoquée, jeton frais compris")
        egal(formulaire("/token", {"grant_type": "refresh_token",
                                   "refresh_token": neuf.get("refresh_token") or "x",
                                   "client_id": CLIENT})[0], 400,
             "  y compris le rafraîchissement qui venait d'être émis")

        # ---- 10. les portées et l'audience -----------------------------
        print("\n10. les portées et l'audience")
        vivant("portées")
        etroite = portees[0] if portees else ""
        large = " ".join(portees)
        restreint = autoriser(CLIENT, etroite, etat="s2")
        ok(not restreint.get("erreur"), "une autorisation restreinte aboutit — %s"
           % restreint.get("erreur", ""))
        ensembles((restreint.get("portee") or "").split(), [etroite],
                  "le jeton ne porte QUE la portée consentie")
        statut, _, corps = formulaire("/token", {
            "grant_type": "refresh_token",
            "refresh_token": restreint.get("rafraichir") or "absent",
            "client_id": CLIENT, "scope": large})
        egal(statut, 400, "élargir la portée au rafraîchissement est refusé")
        egal(js(corps).get("error"), "invalid_scope", "  et le dit")
        # Et quoi qu'il réponde, aucun jeton ne doit sortir avec la portée
        # élargie : un 200 qui rabote silencieusement serait moins grave qu'un
        # 200 qui accorde, mais seul le second se voit ici.
        ensembles((js(corps).get("scope") or etroite).split(), [etroite],
                  "  et aucun jeton élargi n'est délivré")

        # Et le refus ne doit RIEN avoir consommé. Le code posait `used = True`
        # avant de valider la portée : un refus brûlait alors un jeton valide,
        # et l'usage légitime suivant était lu comme un rejeu — donc révoquait
        # toute la famille. Trouvé par audit adverse le 2026-08-31. Le vérifier
        # demande l'appel d'après, pas seulement le code de retour.
        statut, _, corps = formulaire("/token", {
            "grant_type": "refresh_token",
            "refresh_token": restreint.get("rafraichir") or "absent",
            "client_id": CLIENT})
        egal(statut, 200,
             "un refus de portée n'a consommé aucun jeton : le suivant marche")
        ok(bool(js(corps).get("access_token")),
           "  et il délivre bien un jeton d'accès")
        ensembles((js(corps).get("scope") or "").split(), [etroite],
                  "  avec la portée d'origine, ni plus ni moins")

        elargi = autoriser(CLIENT, etroite, etat="s3")
        statut, _, corps = formulaire("/token", {
            "grant_type": "refresh_token",
            "refresh_token": elargi.get("rafraichir") or "absent",
            "client_id": CLIENT, "scope": etroite})
        egal(statut, 200, "la rejouer à l'identique, en revanche, passe")
        ensembles((js(corps).get("scope") or etroite).split(), [etroite],
                  "  et la portée n'a pas bougé")

        ailleurs = autoriser(CLIENT, large, resource="https://ailleurs.example/mcp",
                             etat="s4")
        ok(bool(ailleurs.get("erreur")),
           "aucun jeton n'est délivré pour une autre ressource — %s"
           % json.dumps(ailleurs.get("jetons", {}))[:160])

        # ---- 11. le jeton Infomaniak ne fuit jamais --------------------
        print("\n11. le secret ne fuit pas")
        vivant("fuite")
        ok(not any(faux_api.JETON in c for c in CORPS_VUS),
           "le jeton d'API n'apparaît dans aucune réponse du serveur")
        ok(faux_api.JETON not in sortie_serveur(),
           "ni dans ce que le serveur a journalisé")

    # ---------------------------------------------------------------------------
    # La CSP de la page de consentement doit laisser PARTIR la redirection.
    #
    # `form-action` s'applique aussi à la CIBLE D'UNE REDIRECTION qui suit une
    # soumission. Avec `form-action 'self'`, le serveur émet bien son 302 vers
    # l'adresse de retour — et le navigateur le REFUSE, sans rien dire : le bouton
    # « Autoriser » paraît sans effet, et on peut cliquer indéfiniment.
    #
    # Constaté sur le connecteur voisin le 2026-08-31, après six codes émis et zéro
    # jeton échangé. La seule trace est dans la console du navigateur :
    #   « Refused to load … because it does not appear in the form-action
    #     directive of the Content Security Policy. »
    # Aucun test côté serveur ne pouvait la voir : le serveur, lui, répondait bien.
    verif, defi = pkce()
    statut, tetes, _ = page_consentement({
        "response_type": "code", "client_id": CLIENT, "redirect_uri": REDIRECT,
        "code_challenge": defi, "code_challenge_method": "S256",
        "state": "csp", "scope": "domaines:lire"})
    egal(statut, 200, "csp : la page de consentement est rendue")
    csp = ""
    for nom, valeur in (tetes or {}).items():
        if nom.lower() == "content-security-policy":
            csp = valeur
    ok(csp != "", "csp : la page porte une Content-Security-Policy")
    ok("form-action" in csp, "csp : elle contient une directive form-action")
    origine = "/".join(REDIRECT.split("/")[:3])
    ok(origine in csp,
       "csp : form-action nomme l'adresse de retour %s — sans elle le navigateur "
       "refuse la redirection et le code n'atteint jamais le client : %r"
       % (origine, csp))

    # Et l'assertion inverse : la page d'accueil, dont le formulaire poste vers
    # /revoke, doit RESTER en 'self'. Élargir sa CSP sans raison serait une
    # régression silencieuse.
    statut, tetes, _ = get("/", HUMAIN)
    accueil = ""
    for nom, valeur in (tetes or {}).items():
        if nom.lower() == "content-security-policy":
            accueil = valeur
    ok(origine not in accueil,
       "csp : la page d'accueil ne nomme PAS l'adresse de retour — son formulaire "
       "ne quitte jamais le site : %r" % accueil)

except Exception as err:                                    # noqa: BLE001
    import traceback
    ECHECS.append("la suite s'est interrompue : %s: %s\n%s"
                  % (type(err).__name__, err, traceback.format_exc()))
    VERIFS += 1

finally:
    if PROC is not None and PROC.poll() is None:
        PROC.terminate()
        try:
            PROC.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            PROC.kill()
    QUEUE = sortie_serveur()
    try:
        JOURNAL.close()
    except Exception:                                       # noqa: BLE001
        pass
    API_SERVEUR.shutdown()
    shutil.rmtree(ETAT, ignore_errors=True)
    shutil.rmtree(BUREAU, ignore_errors=True)

# Ce que le serveur a dit vient AVANT le compte : le lanceur de la suite
# n'affiche que la fin de chaque sortie, et le compte doit y rester.
if ECHECS and QUEUE.strip():
    print("--- ce que le serveur a dit ---")
    print(QUEUE[-1200:])
# ---------------------------------------------------------------------------
# Un refus de portée ne consomme AUCUN jeton.
#
# Le code posait `used = True` avant de valider la portée : un refus brûlait
# alors un jeton valide, et l'usage légitime suivant était lu comme un rejeu —
# donc révoquait toute la famille. Trouvé par audit adverse le 2026-08-31.
# Le vérifier demande deux appels : celui qui refuse, puis celui qui doit
# encore marcher.

print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
