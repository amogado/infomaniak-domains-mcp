#!/usr/bin/env python3
"""Les deux transports rendent exactement les mêmes outils.

    python3 tests/check_transports.py

C'est le test qui compte le plus à long terme, et le seul qu'on ne saurait pas
remplacer par de la vigilance. `infomaniak_mcp.py` sert Claude Code sur stdio ;
`serveur.py` sert Claude Chat et Cowork sur `POST /mcp`. Le jour où le second
tient sa propre liste d'outils, les deux se mettent à dériver — et la dérive ne
se voit pas en test : elle se voit en production, quand un outil manque d'un
côté ou qu'un schéma n'accepte plus le même argument.

Deux façons de l'attraper, tenues ensemble :

- **la cause** : `serveur.py` ne définit aucun outil, il importe ceux du module
  partagé. On le constate dans sa source, où une fourche se voit avant d'avoir
  produit son effet ;
- **l'effet** : les listes rendues par les deux transports, comparées comme des
  **ensembles** de noms puis comme des **schémas** entiers, jamais comme des
  longueurs. Et comparées toutes deux au module importé, troisième témoin : sans
  lui, deux transports également vides seraient « identiques ».

Les deux processus reçoivent le **même environnement**. C'est délibéré :
`instructions()` et les marques `[écrit]` / `[DÉPENSE]` dépendent de l'armement,
et la comparaison est refaite désarmée puis armée — un transport qui aurait figé
la chaîne au lieu de la calculer se trahit là.
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

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
BASIC = "Basic " + base64.b64encode(b"vincent:secret").decode()

VERIFS = 0
ECHECS = []


def ok(condition, quoi):
    global VERIFS
    VERIFS += 1
    if not condition:
        ECHECS.append(quoi)


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def ensembles(obtenu, attendu, quoi):
    """Comparer des ensembles, et nommer l'écart des deux côtés.

    Une longueur égale ne dit rien : deux listes de treize outils peuvent ne pas
    porter les mêmes. Et une appartenance isolée est verte quand rien n'est
    rendu du tout."""
    a, b = set(obtenu), set(attendu)
    ok(a == b, "%s : manquant %s, en trop %s" % (quoi, sorted(b - a), sorted(a - b)))


def canonique(objet):
    """Un schéma rendu comparable : les clés triées, les accents conservés."""
    return json.dumps(objet, sort_keys=True, ensure_ascii=False)


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

BUREAU = tempfile.mkdtemp(prefix="check-transports-")
A_NETTOYER = [BUREAU]
VIVANTS = []


def environnement(port, etat, arme=False):
    env = dict(os.environ)
    env.update({
        "INFOMANIAK_LISTEN_PORT": str(port),
        "INFOMANIAK_DATA": etat,
        "INFOMANIAK_HUMAIN": "vincent:secret",
        "INFOMANIAK_BASE": API_BASE,
        "INFOMANIAK_TOKEN": faux_api.JETON,
        "INFOMANIAK_ACCOUNT": "",
        "INFOMANIAK_RATE": "1000000",
        "PYTHONUNBUFFERED": "1",
    })
    for cle in ("INFOMANIAK_WRITE", "INFOMANIAK_ACHAT", "INFOMANIAK_TOKEN_CMD"):
        env.pop(cle, None)
    if arme:
        env["INFOMANIAK_WRITE"] = "1"
        env["INFOMANIAK_ACHAT"] = "1"
    return env


class PasDeRedirection(urllib.request.HTTPRedirectHandler):
    """La redirection du consentement part sur claude.ai : la suivre sortirait
    de la machine et masquerait ce que notre serveur a répondu."""

    def redirect_request(self, *args, **kwargs):
        return None


OUVREUR = urllib.request.build_opener(PasDeRedirection)


class Distant:
    """`serveur.py`, lancé en sous-processus, parlé en HTTP."""

    def __init__(self, arme=False):
        self.port = port_libre()
        self.base = "http://127.0.0.1:%d" % self.port
        self.etat = tempfile.mkdtemp(prefix="check-transports-etat-")
        A_NETTOYER.append(self.etat)
        self.journal = open(os.path.join(BUREAU, "distant-%d.txt" % self.port), "w+")
        self.proc = None
        self.jeton = ""
        self.client = ""
        self.humain = {}
        if (RACINE / "serveur.py").exists():
            self.proc = subprocess.Popen(
                [sys.executable, str(RACINE / "serveur.py")],
                env=environnement(self.port, self.etat, arme),
                stdout=self.journal, stderr=subprocess.STDOUT)
            VIVANTS.append(self.proc)
        else:
            ok(False, "serveur.py n'existe pas encore : rien à comparer")

    # -- HTTP ------------------------------------------------------------
    def http(self, methode, chemin, corps=None, ctype=None, entetes=None):
        requete = urllib.request.Request(self.base + chemin, data=corps, method=methode)
        if ctype:
            requete.add_header("Content-Type", ctype)
        for cle, valeur in (entetes or {}).items():
            requete.add_header(cle, valeur)
        try:
            with OUVREUR.open(requete, timeout=10) as reponse:
                return reponse.status, dict(reponse.headers), \
                    reponse.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read().decode("utf-8", "replace")
        except Exception as err:                            # noqa: BLE001
            return 0, {}, "injoignable : %s" % err

    def formulaire(self, chemin, champs, entetes=None):
        tetes = {"Content-Type": "application/x-www-form-urlencoded"}
        tetes.update(entetes or {})
        return self.http("POST", chemin, urllib.parse.urlencode(champs).encode(),
                         None, tetes)

    def attends(self):
        """Le seul sommeil de la suite, et il ne mesure rien : il attend que le
        port soit ouvert. Aucun scénario n'est éprouvé par l'attente."""
        if self.proc is None:
            return False
        limite = time.monotonic() + 15
        while time.monotonic() < limite:
            if self.proc.poll() is not None:
                ok(False, "serveur.py s'est arrêté au démarrage (code %s) — %s"
                   % (self.proc.returncode, self.sortie()[-400:]))
                return False
            if self.http("GET", "/healthz")[0] == 200:
                return True
            time.sleep(0.02)
        ok(False, "serveur.py n'a pas répondu sur /healthz en 15 s")
        return False

    def vivant(self, ou):
        """Un `/healthz` qui répond ne prouve pas que c'est le nôtre."""
        ok(self.proc is not None and self.proc.poll() is None,
           "%s : notre processus serveur.py est vivant" % ou)

    # -- OAuth, réduit à ce qu'il faut pour atteindre /mcp ----------------
    def autorise(self):
        statut, tetes, _ = self.http("GET", "/")
        if statut == 401 and "basic" in tetes.get("WWW-Authenticate", "").lower():
            self.humain = {"Authorization": BASIC}
        demande = json.dumps({"client_name": "Claude", "redirect_uris": [REDIRECT],
                              "grant_types": ["authorization_code", "refresh_token"],
                              "token_endpoint_auth_method": "none"}).encode()
        corps = self.http("POST", "/register", demande, "application/json")[2]
        try:
            self.client = json.loads(corps).get("client_id") or ""
        except ValueError:
            self.client = ""
        portees = []
        try:
            portees = json.loads(self.http(
                "GET", "/.well-known/oauth-protected-resource")[2]).get(
                    "scopes_supported") or []
        except ValueError:
            pass

        verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
        defi = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        params = {"response_type": "code", "client_id": self.client,
                  "redirect_uri": REDIRECT, "code_challenge": defi,
                  "code_challenge_method": "S256", "state": "transports",
                  "scope": " ".join(portees), "resource": self.base + "/mcp"}
        html = self.http("GET", "/authorize?" + urllib.parse.urlencode(params),
                         entetes=self.humain)[2]
        trouve = (re.search(r'name="csrf"[^>]*value="([^"]+)"', html)
                  or re.search(r'value="([^"]+)"[^>]*name="csrf"', html))
        if not trouve:
            ok(False, "le consentement n'a pas rendu de jeton anti-CSRF : "
                      "impossible d'atteindre /mcp pour comparer les transports")
            return False
        _, tetes, _ = self.formulaire("/consent",
                                      {"csrf": trouve.group(1), "action": "autoriser"},
                                      self.humain)
        code = (urllib.parse.parse_qs(urllib.parse.urlparse(
            tetes.get("Location") or "").query).get("code") or [""])[0]
        corps = self.formulaire("/token", {
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": self.client,
            "code_verifier": verifier})[2]
        try:
            self.jeton = json.loads(corps).get("access_token") or ""
        except ValueError:
            self.jeton = ""
        ok(bool(self.jeton), "une session OAuth aboutit, sans quoi rien n'est "
                             "comparable — %s" % corps[:160])
        return bool(self.jeton)

    def appelle(self, methode, params=None):
        corps = json.dumps({"jsonrpc": "2.0", "id": 1, "method": methode,
                            "params": params or {}}).encode()
        statut, _, texte = self.http("POST", "/mcp", corps, "application/json",
                                     {"Authorization": "Bearer " + (self.jeton or "x")})
        try:
            return json.loads(texte).get("result", {}) if texte.strip() else {}
        except ValueError:
            return {"_brut": texte[:200]}

    def sortie(self):
        try:
            self.journal.flush()
            self.journal.seek(0)
            return self.journal.read()
        except Exception:                                   # noqa: BLE001
            return ""

    def arrete(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:                               # noqa: BLE001
                self.proc.kill()
        try:
            self.journal.close()
        except Exception:                                   # noqa: BLE001
            pass


class Local:
    """`infomaniak_mcp.py`, lancé en sous-processus, parlé en JSON-RPC sur
    stdio — exactement comme Claude Code le fait."""

    def __init__(self, arme=False):
        self.erreurs = open(os.path.join(BUREAU, "stdio-%s.txt" % arme), "w+")
        self.proc = subprocess.Popen(
            [sys.executable, str(RACINE / "infomaniak_mcp.py")],
            env=environnement(0, BUREAU, arme),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.erreurs,
            text=True, bufsize=1)
        VIVANTS.append(self.proc)
        self.appelle("initialize", {"protocolVersion": "2025-06-18"})
        self.notifie("notifications/initialized")

    def vivant(self, ou):
        ok(self.proc.poll() is None,
           "%s : notre processus stdio est vivant" % ou)

    def notifie(self, methode):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": methode}) + "\n")
        self.proc.stdin.flush()

    def appelle(self, methode, params=None):
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": methode,
             "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        ligne = self.proc.stdout.readline()
        if not ligne.strip():
            return {}
        try:
            return json.loads(ligne).get("result", {})
        except ValueError:
            return {"_brut": ligne[:200]}

    def arrete(self):
        try:
            self.proc.stdin.close()
        except Exception:                                   # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            self.proc.kill()
        try:
            self.erreurs.close()
        except Exception:                                   # noqa: BLE001
            pass


def par_nom(reponse):
    """La liste d'outils, indexée par nom, et la liste telle quelle — l'ordre
    se compare à part."""
    outils = (reponse or {}).get("tools") or []
    table = {}
    for outil in outils:
        table[outil.get("name")] = outil
    return table, outils


DISTANT = LOCAL = None
DISTANT_ARME = LOCAL_ARME = None

try:
    # ---- 1. la cause : serveur.py ne définit aucun outil ----------------
    print("\n1. une seule définition d'outils")
    source = ""
    if (RACINE / "serveur.py").exists():
        source = (RACINE / "serveur.py").read_text("utf-8", "replace")
    ok(bool(source), "serveur.py existe")
    ok("infomaniak_mcp" in source,
       "serveur.py importe le module partagé : c'est de là que doivent venir "
       "les outils et leurs schémas")
    ok('"inputSchema":' not in source,
       "serveur.py ne fabrique aucun schéma d'outil — un second jeu de schémas "
       "diverge en silence, et la divergence se voit en production")
    ok(re.search(r"^\s*TOOLS\s*=\s*\[", source, re.M) is None,
       "serveur.py ne tient pas sa propre table d'outils")

    # ---- 2. les deux transports répondent ------------------------------
    print("\n2. les deux transports répondent")
    LOCAL = Local()
    DISTANT = Distant()
    debout = DISTANT.attends()
    LOCAL.vivant("comparaison")
    DISTANT.vivant("comparaison")
    if debout:
        DISTANT.autorise()

    stdio_outils, stdio_liste = par_nom(LOCAL.appelle("tools/list"))
    http_outils, http_liste = par_nom(DISTANT.appelle("tools/list"))
    module = {t["name"]: {k: v for k, v in t.items() if k != "handler"}
              for t in ik.TOOLS}

    # ---- 3. les mêmes noms ---------------------------------------------
    print("\n3. les mêmes outils")
    # Le module importé est le troisième témoin : sans lui, deux transports
    # également vides seraient déclarés « identiques ».
    ensembles(stdio_outils, module, "stdio rend les outils du module partagé")
    ensembles(http_outils, module, "POST /mcp rend les outils du module partagé")
    ensembles(stdio_outils, http_outils, "et les deux transports s'accordent")
    ok({"domaines", "enregistrements", "commande_domaine"} <= set(http_outils),
       "des outils connus sont bien là : une liste vide ne doit pas rendre "
       "cette comparaison verte — vu %s" % sorted(http_outils))
    ok([o.get("name") for o in stdio_liste] == [o.get("name") for o in http_liste],
       "et dans le même ordre — %s / %s"
       % ([o.get("name") for o in stdio_liste], [o.get("name") for o in http_liste]))

    # ---- 4. les mêmes schémas ------------------------------------------
    print("\n4. les mêmes schémas")
    for nom in sorted(set(stdio_outils) & set(http_outils)):
        a, b = stdio_outils[nom], http_outils[nom]
        ensembles(a.keys(), b.keys(), "%s : les mêmes champs" % nom)
        egal(a.get("description"), b.get("description"),
             "%s : la même description" % nom)
        sa = a.get("inputSchema") or {}
        sb = b.get("inputSchema") or {}
        egal(sa.get("type"), sb.get("type"), "%s : le même type de schéma" % nom)
        ensembles((sa.get("properties") or {}).keys(),
                  (sb.get("properties") or {}).keys(),
                  "%s : les mêmes arguments" % nom)
        ensembles(sa.get("required") or [], sb.get("required") or [],
                  "%s : les mêmes arguments obligatoires" % nom)
        for argument in sorted((sa.get("properties") or {}).keys()
                               & (sb.get("properties") or {}).keys()):
            egal(canonique((sa["properties"])[argument]),
                 canonique((sb["properties"])[argument]),
                 "%s.%s : la même définition" % (nom, argument))
        # La comparaison entière, en dernier : elle attrape ce que les
        # comparaisons ciblées n'ont pas nommé.
        egal(canonique(a), canonique(b), "%s : le schéma entier est identique" % nom)
        egal(canonique(a), canonique(module.get(nom)),
             "%s : et il est celui du module partagé" % nom)
        ok("handler" not in a and "handler" not in b,
           "%s : le handler ne franchit aucun des deux transports" % nom)

    # ---- 5. la même poignée de main ------------------------------------
    print("\n5. la même poignée de main")
    LOCAL.vivant("poignée de main")
    DISTANT.vivant("poignée de main")
    a = LOCAL.appelle("initialize", {"protocolVersion": "2025-06-18"})
    b = DISTANT.appelle("initialize", {"protocolVersion": "2025-06-18"})
    egal(a.get("serverInfo"), b.get("serverInfo"),
         "le même serverInfo des deux côtés")
    egal(a.get("serverInfo", {}).get("name"), ik.NAME,
         "  et c'est le nom du module partagé")
    egal(a.get("protocolVersion"), b.get("protocolVersion"),
         "la version de protocole rendue est la même")
    egal(b.get("protocolVersion"), "2025-06-18",
         "  et c'est celle que le client a demandée")
    egal(a.get("capabilities"), b.get("capabilities"), "les mêmes capacités")
    egal(a.get("instructions"), b.get("instructions"),
         "les mêmes instructions : elles annoncent l'armement, et un transport "
         "qui les figerait au lieu de les calculer se verrait ici")
    egal(LOCAL.appelle("ping"), DISTANT.appelle("ping"), "ping répond pareil")

    # ---- 6. le même comportement ---------------------------------------
    print("\n6. le même comportement")
    faux_api.remise_a_zero()
    a = LOCAL.appelle("tools/call", {"name": "domaines", "arguments": {}})
    b = DISTANT.appelle("tools/call", {"name": "domaines", "arguments": {}})
    texte_a = "".join(c.get("text", "") for c in a.get("content") or [])
    texte_b = "".join(c.get("text", "") for c in b.get("content") or [])
    ok("exemple.ch" in texte_a, "stdio lit l'API — %s" % texte_a[:120])
    egal(texte_b, texte_a, "et POST /mcp rend exactement la même chose")
    egal(a.get("isError"), b.get("isError"), "avec le même drapeau d'erreur")

    a = LOCAL.appelle("tools/call", {"name": "nexiste_pas", "arguments": {}})
    b = DISTANT.appelle("tools/call", {"name": "nexiste_pas", "arguments": {}})
    texte_a = "".join(c.get("text", "") for c in a.get("content") or [])
    texte_b = "".join(c.get("text", "") for c in b.get("content") or [])
    egal(a.get("isError"), True, "un outil inconnu est une erreur d'outil, pas de transport")
    egal(texte_b, texte_a, "et le refus est mot pour mot le même")
    ensembles([n for n in ik.BY_NAME if n in texte_b], ik.BY_NAME.keys(),
              "le refus distant énumère tous les outils, sans en oublier")

    # ---- 7. l'armement traverse les deux transports --------------------
    print("\n7. l'armement traverse les deux transports")
    LOCAL_ARME = Local(arme=True)
    DISTANT_ARME = Distant(arme=True)
    if DISTANT_ARME.attends():
        DISTANT_ARME.autorise()
    LOCAL_ARME.vivant("armé")
    DISTANT_ARME.vivant("armé")
    a = LOCAL_ARME.appelle("initialize", {"protocolVersion": "2025-06-18"})
    b = DISTANT_ARME.appelle("initialize", {"protocolVersion": "2025-06-18"})
    ok("ARMÉ" in (a.get("instructions") or ""),
       "armé, le stdio l'annonce — %s" % (a.get("instructions") or "")[:120])
    egal(b.get("instructions"), a.get("instructions"),
         "et le distant annonce exactement la même chose")
    ok((a.get("instructions") or "") != (DISTANT.appelle("initialize", {}).get(
        "instructions") or ""),
       "les instructions changent bien avec l'armement : sinon la comparaison "
       "précédente ne prouverait rien")
    armes_stdio, _ = par_nom(LOCAL_ARME.appelle("tools/list"))
    armes_http, _ = par_nom(DISTANT_ARME.appelle("tools/list"))
    ensembles(armes_stdio, armes_http, "armés, les deux transports s'accordent encore")
    ensembles(armes_stdio, stdio_outils,
              "et l'armement ne fait apparaître ni disparaître aucun outil")

except Exception as err:                                    # noqa: BLE001
    import traceback
    VERIFS += 1
    ECHECS.append("la suite s'est interrompue : %s: %s\n%s"
                  % (type(err).__name__, err, traceback.format_exc()))

finally:
    for banc in (DISTANT, DISTANT_ARME, LOCAL, LOCAL_ARME):
        if banc is not None:
            banc.arrete()
    API_SERVEUR.shutdown()
    for chemin in A_NETTOYER:
        shutil.rmtree(chemin, ignore_errors=True)

print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
