#!/usr/bin/env python3
"""Ce qui a SURVÉCU au premier audit, et les trous de test qui l'ont permis.

    python3 tests/check_survivants.py

`check_durcissement.py` éprouve les douze correctifs D1 à D12. Un second audit,
adverse lui aussi, a montré que six failles leur survivaient — et, plus grave,
que sept invariants que la prose du dépôt affirme n'étaient éprouvés par aucun
test. Un invariant qu'aucune mutation ne tue est une croyance, pas une
propriété.

Ce fichier porte donc deux moitiés :

  **Les failles qui restaient.** L'état qui enfle sans borne (S4), la lecture
  qui écrit (S5), et la page d'accueil qui évince le jeton de révocation de
  Vincent (S6). Les trois autres — le slowloris, la coupure non annoncée, la
  désynchronisation CL.TE — vivent sous le JSON-RPC : elles sont dans
  `check_transport_http.py`, qui parle en socket brute.

  **Les invariants sans garde.** Une seule prise de verrou (T1), /consent qui
  ne lit rien de son corps (T2), un code non persisté qui n'est pas émis (T3),
  la péremption du code (T4), le contrôle d'audience (T5), la robustesse de
  `handle()` (T6), et la frontière qui n'était lancée par personne (T7).

Quatre règles, les mêmes que partout ici :

1. Une absence se constate côté serveur — le fichier d'état, l'inode, le jeton
   d'après. Jamais sur un code de retour : un refus annoncé qui écrit quand
   même est exactement la faute qu'on cherche.
2. Chaque refus est doublé de son assertion INVERSE, qui exige que le geste
   légitime aboutisse. Sans elle, « tout casser » serait une façon de passer
   au vert.
3. Un `/healthz` qui répond ne prouve pas que c'est notre serveur : chaque
   section exige que notre propre processus soit vivant.
4. Aucun sommeil ne mesure quoi que ce soit. Une péremption se prouve en la
   POSANT dans l'état, jamais en attendant devant.
"""

import ast
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
import threading
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
SCOPE_LIRE = "domaines:lire"
SCOPE_ECRIRE = "domaines:ecrire"
SCOPES = SCOPE_LIRE + " " + SCOPE_ECRIRE

# Les bornes que ce fichier exige des péremptions écrites dans l'état. Elles
# sont larges à dessein : on n'éprouve pas une valeur, on éprouve un ORDRE DE
# GRANDEUR. Un code d'autorisation qui vivrait un an et une pierre tombale qui
# vivrait quatre-vingt-dix jours tombent dehors ; changer 300 en 240 ne casse
# rien, et ne doit rien casser.
CODE_MAX = 900              # un code d'autorisation : quinze minutes au plus
CODE_MIN = 60               # ... et une minute au moins, sinon il est inutile
TOMBE_MAX = 2 * 3600        # une pierre tombale : deux heures au plus
ACCES_MAX = 86400           # un jeton d'accès : un jour au plus
CHAINE_MAX = 400 * 86400    # une chaîne de rafraîchissement : un an et des

VERIFS = 0
ECHECS = []


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


def entre(valeur, bas, haut, quoi):
    ok(bas <= valeur <= haut,
       "%s : %r n'est pas dans [%r, %r]" % (quoi, valeur, bas, haut))


# --------------------------------------------------------------------------
# le banc d'essai — jetable, hors ligne, sans jeton réel
# --------------------------------------------------------------------------

def port_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


API_SERVEUR, API_BASE = faux_api.demarre()
faux_api.remise_a_zero()

BUREAU = tempfile.mkdtemp(prefix="survivants-journaux-")
JETABLES = [BUREAU]
PROCS = []

ENV_COMMUNE = dict(os.environ)
ENV_COMMUNE.update({
    "INFOMANIAK_BASE": API_BASE,
    "INFOMANIAK_TOKEN": faux_api.JETON,
    "INFOMANIAK_ACCOUNT": "",
    "INFOMANIAK_RATE": "1000000",
    "PYTHONUNBUFFERED": "1",
})
ENV_COMMUNE.update(marque_proxy.env())
for arme in ("INFOMANIAK_WRITE", "INFOMANIAK_ACHAT", "INFOMANIAK_TOKEN_CMD"):
    ENV_COMMUNE.pop(arme, None)


class PasDeRedirection(urllib.request.HTTPRedirectHandler):
    """Suivre la redirection emmènerait sur claude.ai, dont la réponse n'a rien
    à nous dire — et masquerait ce que notre serveur a répondu."""

    def redirect_request(self, *args, **kwargs):
        return None


OUVREUR = urllib.request.build_opener(PasDeRedirection)


def http(methode, chemin, base, corps=None, ctype=None, entetes=None):
    """Rend (statut, en-têtes, corps). Un statut 0 dit « aucune réponse » —
    c'est une donnée, pas un accident."""
    requete = urllib.request.Request(base + chemin, data=corps, method=methode)
    if ctype:
        requete.add_header("Content-Type", ctype)
    for cle, valeur in (entetes or {}).items():
        requete.add_header(cle, valeur)
    try:
        with OUVREUR.open(requete, timeout=15) as reponse:
            return reponse.status, dict(reponse.headers), \
                reponse.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode("utf-8", "replace")
    except Exception as err:                                # noqa: BLE001
        return 0, {}, "aucune réponse : %s" % err


def js(corps):
    try:
        return json.loads(corps)
    except ValueError:
        return {}


class Kiosque:
    """Un serveur, son état, et tout ce qu'on sait lui demander.

    Chaque section qui touche à l'ÉTAT prend le sien : mesurer une réécriture
    sur un volume que trois autres sections écrivent ne mesure rien.
    """

    def __init__(self, nom, sup=None):
        self.nom = nom
        self.etat = tempfile.mkdtemp(prefix="survivants-%s-" % nom)
        JETABLES.append(self.etat)
        self.port = port_libre()
        self.base = "http://127.0.0.1:%d" % self.port
        env = dict(ENV_COMMUNE)
        env.update({"INFOMANIAK_LISTEN_PORT": str(self.port),
                    "INFOMANIAK_DATA": self.etat,
                    "INFOMANIAK_PUBLIC_BASE": self.base})
        env.update(sup or {})
        self.journal = open(os.path.join(BUREAU, "sortie-%s.txt" % nom), "w+")
        self.proc = subprocess.Popen(
            [sys.executable, str(RACINE / "serveur.py")],
            env=env, stdout=self.journal, stderr=subprocess.STDOUT)
        PROCS.append(self.proc)
        limite = time.monotonic() + 15
        while time.monotonic() < limite:
            if self.proc.poll() is not None:
                ok(False, "%s s'est arrêté au démarrage (code %s)"
                   % (nom, self.proc.returncode))
                return
            if self.get("/healthz")[0] == 200:
                return
            time.sleep(0.02)
        ok(False, "%s n'a pas répondu sur /healthz en 15 s" % nom)

    # ---- parler ----------------------------------------------------------

    def get(self, chemin, entetes=None):
        return http("GET", chemin, self.base, entetes=entetes)

    def post(self, chemin, corps=b"", ctype="application/json", entetes=None):
        return http("POST", chemin, self.base, corps, ctype, entetes)

    def formulaire(self, chemin, champs, entetes=None):
        return self.post(chemin, urllib.parse.urlencode(champs).encode(),
                         "application/x-www-form-urlencoded", entetes)

    def rpc(self, methode, params=None, jeton=None):
        tetes = {"Authorization": "Bearer " + jeton} if jeton else {}
        message = {"jsonrpc": "2.0", "id": 1, "method": methode}
        if params is not None:
            message["params"] = params
        statut, tetes_rep, texte = self.post("/mcp", json.dumps(message).encode(),
                                             "application/json", tetes)
        return statut, tetes_rep, js(texte)

    def vivant(self, ou):
        ok(self.proc is not None and self.proc.poll() is None,
           "%s : notre processus serveur est vivant (%s)" % (ou, self.nom))

    # ---- ce qu'il a écrit ------------------------------------------------

    @property
    def fichier(self):
        return pathlib.Path(self.etat) / "oauth.json"

    def etat_lu(self):
        try:
            return json.loads(self.fichier.read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def etat_ecrit(self, data):
        """Réécrit l'état SOUS le serveur. C'est ainsi qu'on fait passer le
        temps : poser une péremption dans le passé mesure la péremption, alors
        qu'attendre devant ne mesure que la patience du banc."""
        self.fichier.write_text(json.dumps(data, indent=1, sort_keys=True),
                                encoding="utf-8")

    def signature(self):
        """De quoi reconnaître une RÉÉCRITURE, pas seulement un changement.

        Réécrire le même JSON est une écriture, et le contenu ne la montre pas.
        `os.replace` change l'inode : c'est ce numéro-là qui fait foi."""
        trace = {}
        for chemin in sorted(pathlib.Path(self.etat).rglob("*")):
            if chemin.is_file():
                st = chemin.stat()
                trace[chemin.name] = (st.st_ino, st.st_mtime_ns, st.st_size,
                                      hashlib.sha256(chemin.read_bytes()).hexdigest())
        return trace

    def vieillir(self):
        """Recule l'horodatage des fichiers d'un jour, pour qu'une réécriture
        dans la même seconde ne puisse pas se confondre avec l'absence de
        réécriture sur un système de fichiers à la seconde."""
        quand = time.time() - 86400
        for chemin in pathlib.Path(self.etat).rglob("*"):
            if chemin.is_file():
                os.utime(chemin, (quand, quand))

    # ---- le flux d'autorisation, sans raccourci ---------------------------

    def flux(self, scope=None, etat="s", verifier=None, echanger=True,
             extra_consent=None):
        """Le chemin complet que Claude emprunte : page, consentement, échange.

        Rend tout ce qu'on a vu en route, y compris ce qui a échoué : un
        rapport qui nomme l'étape vaut mieux qu'un rapport qui nomme le
        symptôme."""
        scope = scope or SCOPES
        verifier, defi = pkce(verifier)
        vu = {"verifier": verifier, "defi": defi, "scope": scope}
        params = {"response_type": "code", "client_id": CLIENT,
                  "redirect_uri": REDIRECT, "code_challenge": defi,
                  "code_challenge_method": "S256", "state": etat,
                  "scope": scope, "resource": self.base + "/mcp"}
        statut, _, page = self.get("/authorize?" + urllib.parse.urlencode(params),
                                   humaines())
        vu["csrf"] = csrf_de(page)
        if statut != 200 or not vu["csrf"]:
            vu["erreur"] = "page de consentement absente (statut %s)" % statut
            return vu
        champs = {"csrf": vu["csrf"], "action": "autoriser"}
        champs.update(extra_consent or {})
        _, tetes, _ = self.formulaire("/consent", champs, humaines())
        vu["location"] = tetes.get("Location", "")
        vu["code"] = code_de(vu["location"])
        if not vu["code"] or not echanger:
            if not vu["code"]:
                vu["erreur"] = "aucun code émis par /consent"
            return vu
        vu.update(self.echange(vu["code"], verifier))
        return vu

    def echange(self, code, verifier):
        statut, _, corps = self.formulaire("/token", {
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": verifier})
        jetons = js(corps)
        vu = {"statut": statut, "acces": jetons.get("access_token") or "",
              "rafraichir": jetons.get("refresh_token") or "",
              "portee": jetons.get("scope") or ""}
        if not vu["acces"]:
            vu["erreur"] = "aucun jeton délivré (statut %s)" % statut
        return vu

    def rotation(self, rafraichir):
        statut, _, corps = self.formulaire("/token", {
            "grant_type": "refresh_token", "refresh_token": rafraichir,
            "client_id": CLIENT})
        jetons = js(corps)
        return (statut, jetons.get("access_token") or "",
                jetons.get("refresh_token") or "")


def pkce(verifier=None):
    if verifier is None:
        verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    defi = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()).rstrip(b"=").decode()
    return verifier, defi


def csrf_de(page):
    trouve = (re.search(r'name="csrf"[^>]*value="([^"]+)"', page or "")
              or re.search(r'value="([^"]+)"[^>]*name="csrf"', page or ""))
    return trouve.group(1) if trouve else ""


def code_de(location):
    return (urllib.parse.parse_qs(
        urllib.parse.urlparse(location or "").query).get("code") or [""])[0]


HUMAIN = {}             # rempli par la sonde d'entrée, comme dans D1


def humaines(extra=None):
    tetes = dict(HUMAIN)
    tetes.update(marque_proxy.navigation())
    tetes.update(extra or {})
    return tetes


# --------------------------------------------------------------------------
# l'analyse du source — pour les invariants qu'aucune requête ne montre
# --------------------------------------------------------------------------

SOURCE_SERVEUR = (RACINE / "serveur.py").read_text("utf-8")
ARBRE_SERVEUR = ast.parse(SOURCE_SERVEUR)
FONCTIONS = {n.name: n for n in ast.walk(ARBRE_SERVEUR)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def nom_appele(noeud):
    """Le nom de la fonction appelée, qu'elle soit libre ou méthode."""
    cible = noeud.func
    if isinstance(cible, ast.Name):
        return cible.id
    if isinstance(cible, ast.Attribute):
        return cible.attr
    return ""


def dedans(noeud):
    """L'ensemble des nœuds contenus dans celui-ci, par identité."""
    return {id(x) for x in ast.walk(noeud)}


def prises_de_verrou(fonction):
    """Les `with _oauth_lock:` d'une fonction."""
    prises = []
    for noeud in ast.walk(fonction):
        if isinstance(noeud, ast.With):
            for objet in noeud.items:
                if isinstance(objet.context_expr, ast.Name) \
                        and objet.context_expr.id == "_oauth_lock":
                    prises.append(noeud)
    return prises


# --------------------------------------------------------------------------

try:
    if not (RACINE / "serveur.py").exists():
        ok(False, "serveur.py n'existe pas : rien à éprouver")
        raise SystemExit

    PRINCIPAL = Kiosque("principal")

    # La sonde d'entrée côté humain. Sans elle, tout ce qui suit serait vert
    # parce que rien ne répondrait.
    trouvee = marque_proxy.trouver(
        lambda tetes: PRINCIPAL.get("/", dict(tetes, **marque_proxy.navigation()))[0] == 200)
    ok(trouvee is not None,
       "le banc trouve une façon d'entrer côté humain — essayé : %s"
       % ([sorted(c) for c in marque_proxy.candidats()],))
    HUMAIN.update(trouvee or {})

    # ======================================================================
    # T2. /consent ne lit RIEN de son corps, sauf csrf et action
    # ======================================================================
    # La prose l'affirme depuis le premier jour. La moitié seulement en était
    # éprouvée : le mutant qui fait relire `code_challenge` depuis le
    # formulaire survivait, et c'est le champ qui décide À QUI le code sera
    # remis. Une auto-soumission fabriquée aurait lié le code au défi de
    # l'attaquant.
    print("\nT2. /consent ne lit que csrf et action")
    PRINCIPAL.vivant("T2")

    _, defi_hostile = pkce()
    HOSTILE = {"code_challenge": defi_hostile,
               "code_challenge_method": "plain",
               "redirect_uri": "https://mechant.example/cb",
               "scope": SCOPE_ECRIRE,
               "resource": "https://ailleurs.example/mcp",
               "state": "vole-par-le-formulaire",
               "client_id": "un-autre-client",
               "grant_type": "authorization_code"}

    vu = PRINCIPAL.flux(scope=SCOPE_LIRE, etat="t2", extra_consent=HOSTILE)
    ok(not vu.get("erreur"),
       "le consentement aboutit malgré les champs surnuméraires — %s"
       % vu.get("erreur", ""))
    ok(vu.get("location", "").startswith(REDIRECT),
       "le code part à l'adresse ENREGISTRÉE, pas à celle du formulaire — %s"
       % vu.get("location", "")[:90])
    ok("state=vole-par-le-formulaire" not in vu.get("location", ""),
       "et il porte le state enregistré, pas celui du formulaire")
    ok("state=t2" in vu.get("location", ""),
       "  lequel est bien celui de la demande — %s" % vu.get("location", "")[:90])
    egal(vu.get("portee"), SCOPE_LIRE,
         "la portée délivrée est celle de la demande, pas celle du formulaire")
    ok(bool(vu.get("acces")),
       "et le code s'échange avec le verifier D'ORIGINE : c'est le défi "
       "enregistré qui lie le code, pas celui que le formulaire porte — %s"
       % vu.get("erreur", ""))

    # L'autre bout de la même preuve : le défi du formulaire ne doit ouvrir
    # aucune porte. Un code neuf, pour ne pas confondre un refus de rejeu avec
    # un refus de PKCE.
    verifier_hostile, _ = pkce(base64.urlsafe_b64encode(
        hashlib.sha256(b"hostile").digest() * 2).rstrip(b"=").decode()[:60])
    verifier_hostile, defi_hostile2 = pkce()
    vu2 = PRINCIPAL.flux(scope=SCOPE_LIRE, etat="t2b", echanger=False,
                         extra_consent=dict(HOSTILE, code_challenge=defi_hostile2))
    ok(bool(vu2.get("code")), "un second code est émis — %s" % vu2.get("erreur", ""))
    resultat = PRINCIPAL.echange(vu2.get("code", "x"), verifier_hostile)
    egal(resultat["statut"], 400,
         "le verifier qui répond au défi DU FORMULAIRE est refusé")
    ok(not resultat["acces"], "  et rien n'est délivré")

    # La source, parce que le comportement ne montre que ce qu'on a pensé à
    # lui demander : /consent ne doit lire aucune autre clé de son corps.
    consent = FONCTIONS.get("_consent")
    ok(consent is not None, "on retrouve _consent dans le source")
    if consent is not None:
        lues = set()
        for noeud in ast.walk(consent):
            if isinstance(noeud, ast.Call) and nom_appele(noeud) == "get" \
                    and isinstance(noeud.func, ast.Attribute) \
                    and isinstance(noeud.func.value, ast.Name) \
                    and noeud.func.value.id == "form" and noeud.args:
                if isinstance(noeud.args[0], ast.Constant):
                    lues.add(noeud.args[0].value)
                else:
                    lues.add("<calculée>")
            if isinstance(noeud, ast.Subscript) and isinstance(noeud.value, ast.Name) \
                    and noeud.value.id == "form":
                lues.add(getattr(noeud.slice, "value", "<calculée>"))
        ensembles(lues, {"csrf", "action"},
                  "_consent ne lit que csrf et action dans son formulaire — "
                  "tout le reste se relit depuis l'enregistrement serveur")

    # ======================================================================
    # T1. une seule prise de verrou
    # ======================================================================
    # « Tout se joue dans UNE SEULE prise de verrou » : la prose le dit,
    # aucun test ne le disait. Découper la prise de `_token_code` en deux
    # laissait la suite entièrement verte — deux requêtes concurrentes
    # porteuses du même code vérifieraient toutes deux avant qu'aucune n'ait
    # écrit, et repartiraient chacune avec des jetons.
    print("\nT1. l'échange tient dans une seule prise de verrou")
    PRINCIPAL.vivant("T1")

    # Ce qui doit rester sous verrou, et sans quoi la section est décorative.
    SOUS_VERROU = {"oauth_frais", "oauth_load", "oauth_save", "oauth_revoquer",
                   "_emettre", "memoire_poser", "memoire_consommer"}
    ATOMIQUES = ("_token_code", "_token_refresh", "_consent", "_authorize",
                 "_revoke", "_accueil", "_porteur")
    for nom in ATOMIQUES:
        fonction = FONCTIONS.get(nom)
        ok(fonction is not None, "on retrouve %s dans le source" % nom)
        if fonction is None:
            continue
        prises = prises_de_verrou(fonction)
        egal(len(prises), 1,
             "%s prend le verrou exactement une fois — deux prises, c'est une "
             "fenêtre entre la vérification et l'écriture" % nom)
        if len(prises) != 1:
            continue
        interieur = dedans(prises[0])
        dehors = sorted({nom_appele(n) for n in ast.walk(fonction)
                         if isinstance(n, ast.Call)
                         and nom_appele(n) in SOUS_VERROU
                         and id(n) not in interieur})
        ensembles(dehors, [],
                  "%s ne touche à l'état QUE sous le verrou ; hors verrou : %s"
                  % (nom, dehors))

    # Et la course elle-même, en vrai : huit fils, un seul code.
    course = PRINCIPAL.flux(etat="t1", echanger=False)
    ok(bool(course.get("code")), "un code est prêt pour la course — %s"
       % course.get("erreur", ""))
    if course.get("code"):
        depart = threading.Barrier(8)
        recoltes = []
        verrou_banc = threading.Lock()

        def concourir():
            depart.wait()
            resultat = PRINCIPAL.echange(course["code"], course["verifier"])
            with verrou_banc:
                recoltes.append(resultat)

        fils = [threading.Thread(target=concourir) for _ in range(8)]
        for f in fils:
            f.start()
        for f in fils:
            f.join(30)
        egal(len([r for r in recoltes if r["acces"]]), 1,
             "huit échanges simultanés du MÊME code délivrent un jeton une "
             "seule fois")
        egal(len(recoltes), 8, "  et les huit ont bien reçu une réponse")

    # ======================================================================
    # T6. handle() ne lève plus sur un params malformé
    # ======================================================================
    # D8 a durci `serveur.py`. Mais un garde-fou posé chez l'appelant ne
    # protège que cet appelant : `infomaniak_mcp.handle()` levait toujours, et
    # c'est lui la source de vérité, appelée aussi sur stdio.
    print("\nT6. handle() encaisse un params malformé")
    import infomaniak_mcp                                   # noqa: E402

    MALFORMES = [("params en liste", ["tools"]),
                 ("params en chaîne", "ajoute_enregistrement"),
                 ("params en nombre", 7),
                 ("params en booléen", True),
                 ("name en objet", {"name": {"a": 1}}),
                 ("name en liste", {"name": ["ajoute_enregistrement"]}),
                 ("name en nombre", {"name": 3}),
                 ("arguments en liste", {"name": "domaines", "arguments": ["x"]})]
    leves, sans_erreur = [], []
    for quoi, params in MALFORMES:
        try:
            rendu = infomaniak_mcp.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
        except Exception as err:                            # noqa: BLE001
            leves.append("%s → %s: %s" % (quoi, type(err).__name__, err))
            continue
        if not isinstance(rendu, dict):
            sans_erreur.append("%s → %r" % (quoi, rendu))
    ensembles(leves, [], "aucun params malformé ne fait lever handle()")
    ensembles(sans_erreur, [], "et chacun rend une réponse JSON-RPC en règle")

    for quoi, params in [("initialize", ["x"]), ("ping", "x"), ("tools/list", 7)]:
        try:
            infomaniak_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": quoi,
                                   "params": params})
            leve = ""
        except Exception as err:                            # noqa: BLE001
            leve = "%s: %s" % (type(err).__name__, err)
        egal(leve, "", "%s encaisse un params malformé" % quoi)

    # L'assertion inverse : ce qui est bien formé continue de marcher, sinon
    # « tout refuser » passerait pour un correctif.
    rendu = infomaniak_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    ok(isinstance(rendu, dict) and len(rendu.get("tools") or []) > 5,
       "et tools/list rend toujours l'inventaire complet")
    rendu = infomaniak_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "outil-qui-n-existe-pas"}})
    ok(isinstance(rendu, dict) and rendu.get("isError"),
       "un outil inconnu reste une erreur applicative, pas une exception")

    # ======================================================================
    # S6. GET / n'évince plus le jeton anti-CSRF de révocation
    # ======================================================================
    # Régression introduite par le correctif de D5 : la page d'accueil frappe
    # un jeton dans une table globale de 32 places, SANS le contrôle de
    # navigation que /authorize avait reçu. Trente-deux chargements hostiles
    # — une balise `<img src="/">` dans une page ouverte ailleurs, le
    # credential ambiant rejoué tout seul — évinçaient celui de Vincent et lui
    # interdisaient de révoquer, au moment précis où il en a besoin.
    print("\nS6. trente-deux chargements hostiles n'évincent pas le jeton de Vincent")
    PRINCIPAL.vivant("S6")

    session = PRINCIPAL.flux(etat="s6")
    ok(not session.get("erreur"), "une autorisation à révoquer existe — %s"
       % session.get("erreur", ""))
    statut, _, accueil = PRINCIPAL.get("/", humaines())
    egal(statut, 200, "la page d'accueil s'affiche pour une vraie navigation")
    csrf_vincent = csrf_de(accueil)
    ok(bool(csrf_vincent), "et elle porte un jeton anti-CSRF de révocation")

    # Tout ce qu'une page hostile peut provoquer : chaque forme porte son
    # Sec-Fetch-Dest, et aucune n'est une navigation de premier plan.
    CHARGEMENTS = [{"Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors"},
                   {"Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"},
                   {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"},
                   {"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"}]
    servis, jetons_frappes = [], set()
    for tour in range(40):
        tetes = dict(HUMAIN)
        tetes.update(CHARGEMENTS[tour % len(CHARGEMENTS)])
        statut, _, page = PRINCIPAL.get("/", tetes)
        if statut != 403:
            servis.append("%s → %s" % (sorted(tetes), statut))
        if csrf_de(page):
            jetons_frappes.add(csrf_de(page))
    ensembles(servis, [],
              "aucun chargement en arrière-plan n'obtient la page d'accueil")
    ensembles(jetons_frappes, [],
              "donc aucun ne frappe de jeton : la table n'est pas remplie par "
              "un inconnu")

    # La preuve n'est pas le code de retour, c'est que Vincent peut ENCORE
    # révoquer. Son jeton date d'avant les quarante chargements.
    statut, _, page = PRINCIPAL.formulaire(
        "/revoke", {"grant": "tout", "csrf": csrf_vincent}, humaines())
    ok(statut in (302, 303),
       "le jeton de Vincent, émis AVANT l'inondation, révoque encore — %s" % statut)
    ok("périmée" not in page,
       "et il n'est pas rejeté comme périmé : %s" % page[:120])
    egal(PRINCIPAL.rpc("tools/list", {}, session.get("acces"))[0], 401,
         "  et la révocation a bien coupé la famille")

    # L'assertion inverse : une vraie navigation obtient toujours la page et un
    # jeton qui marche. Sans elle, « refuser tout le monde » serait un
    # correctif. Une autorisation d'abord — la page ne porte de bouton, donc de
    # jeton, que s'il y a quelque chose à révoquer.
    session = PRINCIPAL.flux(etat="s6-inverse")
    ok(not session.get("erreur"), "une nouvelle autorisation aboutit — %s"
       % session.get("erreur", ""))
    statut, _, accueil = PRINCIPAL.get("/", humaines())
    egal(statut, 200, "une navigation de premier plan obtient toujours la page")
    ok(bool(csrf_de(accueil)), "  avec un jeton neuf")
    statut, _, _ = PRINCIPAL.formulaire(
        "/revoke", {"grant": "tout", "csrf": csrf_de(accueil)}, humaines())
    ok(statut in (302, 303), "  et ce jeton neuf est accepté — %s" % statut)

    # ======================================================================
    # S1 (suite). le budget de lecture est borné DES DEUX CÔTÉS
    # ======================================================================
    # Le budget lui-même s'éprouve en socket brute — `check_transport_http.py`
    # tient un serveur au goutte-à-goutte et le regarde répondre 408. Ce qui se
    # joue ici est sa BORNE BASSE, qu'aucune socket ne montre : un réglage à
    # zéro — une variable vide dans un manifeste, un « 0 » distrait — donnerait
    # un serveur qui refuse tout corps, donc un connecteur mort en silence.
    # Le vide doit tomber du côté qui alarme quand il s'agit d'autoriser, et du
    # côté qui fonctionne quand il s'agit de patienter.
    print("\nS1. un budget de lecture mal réglé ne tue pas le connecteur")
    ZERO = Kiosque("delai-zero", sup={"INFOMANIAK_DELAI_CORPS": "0"})
    ZERO.vivant("S1 borne basse")
    enregistrement = json.dumps({"redirect_uris": [REDIRECT]}).encode()
    statut, _, _ = ZERO.post("/register", enregistrement)
    egal(statut, 201,
         "un budget réglé à zéro est ramené à sa borne basse : le serveur lit "
         "encore les corps qu'on lui envoie")

    ILLISIBLE = Kiosque("delai-illisible", sup={"INFOMANIAK_DELAI_CORPS": "à peu près"})
    ILLISIBLE.vivant("S1 valeur illisible")
    statut, _, _ = ILLISIBLE.post("/register", enregistrement)
    egal(statut, 201,
         "et une valeur illisible retombe sur le défaut plutôt que d'empêcher "
         "le serveur de démarrer")

    # ======================================================================
    # S4. l'état ne peut plus enfler sans borne
    # ======================================================================
    # Chaque rotation laissait une pierre tombale gardée quatre-vingt-dix
    # jours ; `data["grants"]` n'était purgée NULLE PART. Un état qui n'a pas
    # de plafond sur un volume est un OOMKill à échéance — et un OOMKill dont
    # le redémarrage relit le même fichier est PERMANENT.
    print("\nS4. rien dans l'état ne grandit sans se périmer")
    S4 = Kiosque("s4")
    S4.vivant("S4")

    vu = S4.flux(etat="s4")
    ok(not vu.get("erreur"), "une session aboutit — %s" % vu.get("erreur", ""))
    rafraichir = vu.get("rafraichir", "")
    ROTATIONS = 30
    echecs_rotation = []
    for tour in range(ROTATIONS):
        statut, _acces, rafraichir = S4.rotation(rafraichir)
        if statut != 200 or not rafraichir:
            echecs_rotation.append("tour %d → %s" % (tour, statut))
            break
    ensembles(echecs_rotation, [], "%d rotations aboutissent" % ROTATIONS)

    etat = S4.etat_lu()
    maintenant = time.time()
    pierres = {cle: v for cle, v in etat.get("refresh", {}).items() if v.get("used")}
    egal(len(pierres), ROTATIONS,
         "chaque rotation laisse bien une pierre tombale — sans quoi la borne "
         "qu'on va mesurer ne mesurerait rien")
    trop_longues = sorted(
        "%.0f j" % ((float(v.get("exp", 0)) - maintenant) / 86400.0)
        for v in pierres.values()
        if float(v.get("exp", 0)) - maintenant > TOMBE_MAX)
    ensembles(trop_longues, [],
              "et aucune ne survit plus de deux heures : c'est ce qui bornait "
              "l'état, et elles vivaient quatre-vingt-dix jours")
    vivantes = [v for v in etat.get("refresh", {}).values() if not v.get("used")]
    egal(len(vivantes), 1, "un seul jeton de rafraîchissement est vivant")

    # Le temps passe — posé dans l'état, pas attendu. Puis une requête
    # quelconque, et le ménage doit avoir eu lieu.
    etat = S4.etat_lu()
    for entree in etat["refresh"].values():
        if entree.get("used"):
            entree["exp"] = maintenant - 1
    S4.etat_ecrit(etat)
    S4.formulaire("/token", {"grant_type": "refresh_token",
                             "refresh_token": "jamais-emis", "client_id": CLIENT})
    apres = S4.etat_lu()
    egal(len(apres.get("refresh", {})), 1,
         "une fois périmées, les %d pierres tombales disparaissent — il ne "
         "reste que le jeton vivant" % ROTATIONS)
    statut, acces_s4, rafraichir = S4.rotation(rafraichir)
    egal(statut, 200,
         "et le jeton vivant, lui, tourne toujours : le ménage n'a pas emporté "
         "ce qui sert")

    # Les autorisations : la table que rien ne vidait.
    etat = S4.etat_lu()
    egal(len([g for g in etat.get("grants", {}).values() if not g.get("revoked")]), 1,
         "une autorisation vivante")
    sans_peremption = [gid for gid, g in etat.get("grants", {}).items()
                       if not g.get("exp")]
    ensembles(sans_peremption, [],
              "et elle porte une péremption : sans elle, `grants` est la seule "
              "table qu'aucun mécanisme ne vide")
    for gid, g in etat.get("grants", {}).items():
        entre(float(g.get("exp", 0)) - maintenant, 0, CHAINE_MAX,
              "la péremption de l'autorisation %s est dans des bornes plausibles"
              % gid[:8])

    _, _, accueil = S4.get("/", humaines())
    S4.formulaire("/revoke", {"grant": "tout", "csrf": csrf_de(accueil)}, humaines())
    etat = S4.etat_lu()
    tombes = [g for g in etat.get("grants", {}).values() if g.get("revoked")]
    egal(len(tombes), 1, "révoquer laisse une pierre tombale")
    trop_longues = [g for g in tombes
                    if float(g.get("exp", 0)) - time.time() > TOMBE_MAX]
    ensembles([g.get("created") for g in trop_longues], [],
              "et elle se périme elle aussi — sinon le geste de ménage serait "
              "le geste qui encombre")

    etat = S4.etat_lu()
    for g in etat["grants"].values():
        if g.get("revoked"):
            g["exp"] = time.time() - 1
    S4.etat_ecrit(etat)
    S4.get("/healthz")
    S4.formulaire("/token", {"grant_type": "refresh_token",
                             "refresh_token": "jamais-emis", "client_id": CLIENT})
    egal(len(S4.etat_lu().get("grants", {})), 0,
         "une fois périmée, la pierre tombale disparaît aussi")

    # L'assertion inverse, et elle est le cœur de la section : une autorisation
    # VIVANTE ne doit pas être emportée par le même ménage.
    vu = S4.flux(etat="s4-inverse")
    ok(not vu.get("erreur"), "une nouvelle autorisation aboutit — %s"
       % vu.get("erreur", ""))
    S4.formulaire("/token", {"grant_type": "refresh_token",
                             "refresh_token": "jamais-emis", "client_id": CLIENT})
    egal(len(S4.etat_lu().get("grants", {})), 1,
         "et elle survit au ménage : ce qui périt est ce qui a expiré, pas ce "
         "qui sert")
    egal(S4.rpc("tools/list", {}, vu.get("acces"))[0], 200,
         "  son jeton fonctionne encore")

    # Un état écrit par la version d'AVANT les péremptions : l'autorisation n'y
    # porte pas d'`exp`. La jeter serait déconnecter Claude sans prévenir, au
    # premier redémarrage qui suit la mise à jour — un correctif de fuite qui
    # coupe le connecteur n'est pas un correctif. On la répare, on ne la jette
    # pas. Le connecteur est DÉPLOYÉ : cet état-là existe pour de bon.
    etat = S4.etat_lu()
    for g in etat["grants"].values():
        g.pop("exp", None)
    S4.etat_ecrit(etat)
    egal(S4.rpc("tools/list", {}, vu.get("acces"))[0], 200,
         "un état écrit avant les péremptions se relit sans rien perdre")
    repare = S4.etat_lu()
    egal(len(repare.get("grants", {})), 1,
         "l'autorisation qui n'avait pas de péremption est toujours là")
    ensembles([gid for gid, g in repare.get("grants", {}).items() if not g.get("exp")],
              [], "et la péremption qui lui manquait lui a été POSÉE")
    _, _, accueil = S4.get("/", humaines())
    ok(bool(csrf_de(accueil)),
       "  et elle reste révocable depuis la page : réparer, c'est garder ce "
       "qui sert")

    # ======================================================================
    # S5. une lecture n'est pas une écriture
    # ======================================================================
    # `_porteur()` réécrivait TOUT l'état à chaque requête authentifiée — et
    # jusque sur un `GET /mcp` qui ne rend qu'un 405. C'est ce qui rendait
    # létale la table qui enfle : son coût se payait par requête.
    print("\nS5. une requête authentifiée ne réécrit pas l'état")
    S5 = Kiosque("s5")
    S5.vivant("S5")

    vu = S5.flux(etat="s5")
    ok(not vu.get("erreur"), "une session aboutit — %s" % vu.get("erreur", ""))
    acces = vu.get("acces", "")
    # Une première requête a le droit d'écrire : c'est elle qui pose
    # l'horodatage d'activité. C'est la SUITE qu'on mesure.
    S5.rpc("tools/list", {}, acces)
    S5.vieillir()
    avant = S5.signature()
    ok(bool(avant), "il y a bien un état sur le volume à surveiller")

    lectures = []
    for _ in range(10):
        lectures.append(S5.rpc("tools/list", {}, acces)[0])
    for _ in range(5):
        lectures.append(http("GET", "/mcp", S5.base,
                             entetes={"Authorization": "Bearer " + acces})[0])
    for _ in range(3):
        lectures.append(http("DELETE", "/mcp", S5.base,
                             entetes={"Authorization": "Bearer " + acces})[0])
    ensembles(lectures, [200, 405, 204],
              "les dix-huit requêtes ont bien été servies")
    egal(S5.signature(), avant,
         "et aucune n'a réécrit l'état : ni inode, ni horodatage, ni contenu")

    # Le refus aussi : un Bearer inconnu ne doit rien écrire non plus.
    for _ in range(5):
        S5.rpc("tools/list", {}, "un-jeton-qui-n-a-jamais-existe")
    egal(S5.signature(), avant, "un jeton inconnu n'écrit rien non plus")

    # L'assertion inverse : ce qui DOIT être écrit l'est toujours. Un serveur
    # devenu sans état passerait la précédente.
    vu2 = S5.flux(etat="s5-inverse")
    ok(not vu2.get("erreur"), "un nouveau flux aboutit — %s" % vu2.get("erreur", ""))
    ok(S5.signature() != avant, "et lui, il a bien écrit : le volume n'est pas gelé")
    egal(S5.rpc("tools/list", {}, acces)[0], 200,
         "et le premier jeton fonctionne toujours : ne plus écrire n'est pas "
         "ne plus voir")

    # ======================================================================
    # T3. un code non persisté n'est jamais émis
    # ======================================================================
    # « Si l'écriture échoue, on rend 500 et aucun code n'est émis. » Aucun
    # test ne le disait : forcer `durable = True` tout en laissant `oauth_save`
    # échouer laissait la suite verte. Un code non persisté est un code
    # rejouable indéfiniment — le serveur ne saura jamais qu'il l'a émis.
    print("\nT3. quand le volume refuse d'écrire, rien n'est émis")
    T3 = Kiosque("t3")
    T3.vivant("T3")

    def bloquer_ecriture(kiosque):
        """Rend `oauth_save()` inopérant sans toucher au serveur.

        Le fichier temporaire de l'écriture atomique devient un RÉPERTOIRE :
        `open(tmp, "w")` lève alors `IsADirectoryError`, qui est un `OSError`,
        que `oauth_save()` avale en rendant False. La lecture, elle, continue
        de fonctionner — c'est exactement le volume en lecture seule qu'on
        veut simuler, et ça marche même quand le banc tourne en root, ce qu'un
        `chmod` ne garantit pas."""
        os.mkdir(str(kiosque.fichier) + ".tmp")

    def liberer_ecriture(kiosque):
        shutil.rmtree(str(kiosque.fichier) + ".tmp", ignore_errors=True)

    verifier, defi = pkce()
    params = {"response_type": "code", "client_id": CLIENT,
              "redirect_uri": REDIRECT, "code_challenge": defi,
              "code_challenge_method": "S256", "state": "t3",
              "scope": SCOPES, "resource": T3.base + "/mcp"}
    statut, _, page = T3.get("/authorize?" + urllib.parse.urlencode(params), humaines())
    csrf_t3 = csrf_de(page)
    ok(bool(csrf_t3), "une demande est enregistrée pendant que le volume écrit")

    bloquer_ecriture(T3)
    avant = T3.signature()
    statut, tetes, page = T3.formulaire(
        "/consent", {"csrf": csrf_t3, "action": "autoriser"}, humaines())
    egal(statut, 500, "/consent rend 500 quand l'état ne peut pas être écrit")
    egal(code_de(tetes.get("Location")), "",
         "et AUCUN code ne part : ni dans une redirection…")
    ok("code=" not in page, "  …ni dans la page")
    egal(T3.signature(), avant, "et l'état n'a pas bougé")

    statut, _, _ = T3.get("/authorize?" + urllib.parse.urlencode(
        dict(params, state="t3b")), humaines())
    egal(statut, 500, "/authorize aussi refuse d'afficher ce qu'il ne peut pas "
                      "enregistrer")

    liberer_ecriture(T3)
    vu = T3.flux(etat="t3c", echanger=False)
    ok(bool(vu.get("code")),
       "le volume rendu, un code est de nouveau émis — %s" % vu.get("erreur", ""))

    # L'échange, maintenant : un jeton qu'on ne peut pas persister ne doit pas
    # partir non plus, et le code ne doit pas être brûlé pour autant.
    bloquer_ecriture(T3)
    statut, _, corps = T3.formulaire("/token", {
        "grant_type": "authorization_code", "code": vu["code"],
        "redirect_uri": REDIRECT, "client_id": CLIENT,
        "code_verifier": vu["verifier"]})
    egal(statut, 500, "/token rend 500 quand il ne peut pas persister la paire")
    ok(not js(corps).get("access_token"), "et ne délivre aucun jeton")
    liberer_ecriture(T3)

    resultat = T3.echange(vu["code"], vu["verifier"])
    egal(resultat["statut"], 200,
         "le code n'a pas été brûlé par l'échec : il s'échange une fois le "
         "volume revenu — un refus ne doit rien consommer")
    ok(bool(resultat["acces"]), "  et délivre bien un jeton")
    egal(T3.rpc("tools/list", {}, resultat["acces"])[0], 200,
         "  qui fonctionne")

    # ======================================================================
    # T4. la péremption du code est courte, et elle mord
    # ======================================================================
    # `CODE_TTL` n'était éprouvé par aucun test : la porter à un an laissait
    # tout vert. Un code d'autorisation qui vit un an est un code que
    # n'importe quel journal, historique de navigation ou capture de proxy
    # rend échangeable des mois plus tard.
    print("\nT4. les péremptions écrites dans l'état sont celles qu'on croit")
    T45 = Kiosque("t45")
    T45.vivant("T4")

    avant_codes = set(T45.etat_lu().get("codes", {}))
    vu = T45.flux(etat="t4", echanger=False)
    ok(bool(vu.get("code")), "un code est émis — %s" % vu.get("erreur", ""))
    etat = T45.etat_lu()
    neufs = [cle for cle in etat.get("codes", {}) if cle not in avant_codes]
    egal(len(neufs), 1, "et il en reste exactement une trace dans l'état")
    if neufs:
        reste = float(etat["codes"][neufs[0]].get("exp", 0)) - time.time()
        entre(reste, CODE_MIN, CODE_MAX,
              "un code d'autorisation vit quelques minutes, pas un an")

    for cle, entree in etat.get("pending", {}).items():
        entre(float(entree.get("exp", 0)) - time.time(), 0, 3600,
              "une demande en attente ne vit pas plus d'une heure (%s)" % cle[:8])

    # La péremption MORD : posée dans le passé, le code n'est plus échangeable.
    etat = T45.etat_lu()
    etat["codes"][neufs[0]]["exp"] = time.time() - 1
    T45.etat_ecrit(etat)
    resultat = T45.echange(vu["code"], vu["verifier"])
    egal(resultat["statut"], 400, "un code périmé n'est plus échangeable")
    ok(not resultat["acces"], "  et ne délivre rien")

    # L'assertion inverse : un code frais, lui, s'échange.
    frais = T45.flux(etat="t4-inverse")
    ok(bool(frais.get("acces")),
       "un code frais s'échange toujours — %s" % frais.get("erreur", ""))
    etat = T45.etat_lu()
    for cle, entree in etat.get("access", {}).items():
        entre(float(entree.get("exp", 0)) - time.time(), 60, ACCES_MAX,
              "un jeton d'accès vit au plus un jour (%s)" % cle[:8])
    for cle, entree in etat.get("refresh", {}).items():
        entre(float(entree.get("exp", 0)) - time.time(), 0, CHAINE_MAX,
              "une chaîne de rafraîchissement reste dans ses bornes (%s)" % cle[:8])

    # ======================================================================
    # T5. le contrôle d'audience n'est plus une tautologie
    # ======================================================================
    # `_emettre()` inscrivait `aud = MCP_URL`, et `_porteur()` comparait à
    # `MCP_URL` : deux lectures de la même variable, dans le même processus.
    # La comparaison ne POUVAIT pas échouer — et le champ `resource` que
    # /authorize prend soin d'enregistrer n'était lu par personne. L'audience
    # descend maintenant de l'AUTORISATION ; les deux valeurs peuvent donc
    # différer, et le contrôle existe.
    print("\nT5. l'audience d'un jeton vient de l'autorisation, pas de la config")
    T45.vivant("T5")

    AILLEURS = "https://ailleurs.example/mcp"
    vu = T45.flux(etat="t5", echanger=False)
    ok(bool(vu.get("code")), "un code est prêt — %s" % vu.get("erreur", ""))
    etat = T45.etat_lu()
    marque = [cle for cle, e in etat.get("codes", {}).items()
              if not e.get("used") and e.get("resource")]
    ok(bool(marque),
       "le code enregistré porte une ressource : sans elle, l'audience n'a "
       "rien d'où descendre")
    if marque:
        etat["codes"][marque[-1]]["resource"] = AILLEURS
        T45.etat_ecrit(etat)
    resultat = T45.echange(vu["code"], vu["verifier"])
    egal(resultat["statut"], 200,
         "le code s'échange : c'est l'audience du jeton qu'on éprouve, pas "
         "l'échange")
    apres = T45.etat_lu()
    portees = {e.get("aud") for e in apres.get("access", {}).values()}
    ok(AILLEURS in portees,
       "le jeton délivré porte l'audience de l'AUTORISATION — %s" % sorted(portees))
    statut, tetes, _ = T45.rpc("tools/list", {}, resultat["acces"])
    egal(statut, 401,
         "et ce jeton, présenté ici, est refusé : ce serveur ne sert pas cette "
         "ressource-là")
    ok("invalid_token" in (tetes.get("WWW-Authenticate") or ""),
       "  et le défi le dit — %s" % tetes.get("WWW-Authenticate", "(aucun)"))

    # La rotation doit transporter l'audience, sinon un jeton étranger se
    # blanchit en un rafraîchissement.
    avant_refresh = set(T45.etat_lu().get("refresh", {}))
    vu = T45.flux(etat="t5-rotation")
    ok(bool(vu.get("rafraichir")), "une chaîne existe — %s" % vu.get("erreur", ""))
    etat = T45.etat_lu()
    # Le rafraîchissement de CETTE chaîne-ci, et pas un survivant d'une section
    # précédente : ce banc a déjà servi, et confondre deux chaînes ferait
    # mesurer l'altération sur un jeton qu'on ne présentera jamais.
    vivants = [cle for cle, e in etat.get("refresh", {}).items()
               if not e.get("used") and cle not in avant_refresh]
    egal(len(vivants), 1, "un seul rafraîchissement neuf à altérer")
    if vivants:
        etat["refresh"][vivants[0]]["aud"] = AILLEURS
        T45.etat_ecrit(etat)
    statut, acces_tourne, _ = T45.rotation(vu["rafraichir"])
    egal(statut, 200, "la rotation aboutit")
    egal(T45.rpc("tools/list", {}, acces_tourne)[0], 401,
         "mais le jeton qui en sort garde l'audience étrangère : une rotation "
         "ne blanchit pas un jeton émis pour ailleurs")

    # L'assertion inverse, sans quoi « refuser tous les jetons » passerait pour
    # un correctif.
    propre = T45.flux(etat="t5-inverse")
    egal(T45.rpc("tools/list", {}, propre.get("acces"))[0], 200,
         "un jeton d'audience normale fonctionne toujours")
    statut, acces_tourne, _ = T45.rotation(propre.get("rafraichir", ""))
    egal(statut, 200, "et sa rotation aboutit")
    egal(T45.rpc("tools/list", {}, acces_tourne)[0], 200,
         "  en rendant un jeton qui fonctionne")

    # ======================================================================
    # T7. la frontière est dans la suite
    # ======================================================================
    # `tests/run.sh` ne globait que `tests/check_*.py` : `check_frontiere.sh`
    # — le SEUL test du dépôt qui interroge la production depuis dehors, sans
    # identifiants — n'était lancé par personne. Un test qu'on ne lance pas
    # n'est pas un test, c'est un fichier.
    print("\nT7. la sonde de frontière est réellement branchée")
    frontiere = RACINE / "tests" / "check_frontiere.sh"
    ok(frontiere.exists(), "tests/check_frontiere.sh existe")
    ok(os.access(str(frontiere), os.X_OK),
       "et il est exécutable — un test que le shell refuse de lancer est absent")
    lanceur = (RACINE / "tests" / "run.sh").read_text("utf-8")
    ok(re.search(r"\./tests/check_frontiere\.sh\b", lanceur) is not None,
       "tests/run.sh l'EXÉCUTE — le nommer dans un commentaire ne le lance pas, "
       "et c'est très exactement ce qui a duré des semaines")
    ok("injoignable" in lanceur,
       "et il prévoit le cas de l'hôte injoignable — un test d'intégration qui "
       "échoue faute de réseau ne doit pas rendre la suite rouge")

finally:
    for proc in PROCS:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            try:
                proc.kill()
            except Exception:                               # noqa: BLE001
                pass
    try:
        API_SERVEUR.shutdown()
    except Exception:                                       # noqa: BLE001
        pass
    for dossier in JETABLES:
        shutil.rmtree(dossier, ignore_errors=True)

print("\n%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
