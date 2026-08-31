"""Le canari : ce qui ouvre les pages humaines, et ce qui ne l'ouvre pas.

Le point qu'éprouve ce fichier tient en une phrase : **un en-tête ne prouve
rien par lui-même.**

`X-Auth-Request-Email` porte le compte Google qu'oauth2-proxy vient de
vérifier — mais l'appelant l'écrit lui-même s'il n'existe rien pour l'écraser.
Or le pod écoute sur 8080, joignable depuis le cluster sans passer ni par
Traefik ni par le proxy : la NetworkPolicy qui fermerait ce chemin est une
dette dont la cause est établie (flannel masque l'adresse source avant que la
policy ne la regarde) mais qui n'est pas refermable ici.

Et `/config` pose le jeton d'API et arme la dépense.

D'où la règle : l'identité ne remplace pas la marque de proxy, elle s'y ajoute.
La marque est infalsifiable — un secret partagé, comparé en temps constant,
qu'un middleware Traefik écrase à l'entrée. Un voisin du cluster ne l'a pas.
"""

import http.client
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

RACINE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "tests"))
import marque_proxy                                          # noqa: E402

VERIFS = 0
ECHECS = []


def ok(c, quoi):
    global VERIFS
    VERIFS += 1
    if not c:
        ECHECS.append(quoi)


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def port_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = port_libre()
ETAT = tempfile.mkdtemp(prefix="canari-")
JOURNAL = tempfile.mkstemp(prefix="canari-", suffix=".log")[1]

env = dict(os.environ)
env.update(marque_proxy.env())
env.update({"INFOMANIAK_DATA": ETAT,
            "INFOMANIAK_PUBLIC_BASE": "http://127.0.0.1:%d" % PORT,
            "INFOMANIAK_LISTEN_PORT": str(PORT),
            "INFOMANIAK_TOKEN": "jeton-de-test",
            "PYTHONUNBUFFERED": "1"})
env.pop("INFOMANIAK_WRITE", None)
env.pop("INFOMANIAK_ACHAT", None)

with open(JOURNAL, "wb") as j:
    serveur = subprocess.Popen([sys.executable, str(RACINE / "serveur.py")],
                               stdout=j, stderr=j, env=env)

for _ in range(80):
    if serveur.poll() is not None:
        raise SystemExit("le serveur est mort au démarrage :\n%s"
                         % pathlib.Path(JOURNAL).read_text()[-800:])
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.4).close()
        break
    except OSError:
        time.sleep(0.15)

# Un port qui répond ne prouve pas que c'est le nôtre.
ok(serveur.poll() is None, "le serveur du banc est vivant")


def demande(chemin, entetes=None, methode="GET", corps=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        c.request(methode, chemin, body=corps, headers=entetes or {})
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        c.close()


NAV = marque_proxy.navigation()
# Le nom de l'en-tête vient du serveur lui-même : le recopier ici
# ferait diverger le banc du code au premier renommage.
import serveur as _srv
MARQUE = {_srv.ENTETE_MARQUE: marque_proxy.VALEUR}
EMAIL = "vi.doyon@gmail.com"
ENTETE_EMAIL = "X-Auth-Request-Email"
# Deux pages où un 200 signifie sans ambiguïté « la porte s'est ouverte ».
# /authorize est écarté : ses paramètres incomplets donnent un 400 qui
# ressemblerait à un refus alors que le canari, lui, aurait cédé.
HUMAINS = ("/config", "/")

# ---- l'identité seule n'ouvre rien -----------------------------------------
seule = dict(NAV)
seule[ENTETE_EMAIL] = EMAIL
for chemin in HUMAINS:
    code, page = demande(chemin, seule)
    ok(code != 200,
       "une identité forgée SANS la marque n'ouvre pas %s (obtenu %d) — sinon "
       "tout voisin du cluster poserait le jeton d'API et armerait la dépense"
       % (chemin, code))
    ok("Enregistrer" not in page and "jeton" not in page.lower(),
       "et %s ne rend aucun formulaire de configuration" % chemin)

code, _ = demande("/config", seule, "POST", b"")
ok(code not in (200, 303),
   "elle n'écrit rien non plus : POST /config refusé (obtenu %d)" % code)

# ---- la marque, elle, ouvre — avec ou sans identité -------------------------
avec = dict(NAV, **MARQUE)
for chemin in HUMAINS:
    code, _ = demande(chemin, avec)
    egal(code, 200, "la marque de proxy ouvre %s" % chemin)

deux = dict(avec)
deux[ENTETE_EMAIL] = EMAIL
code, _ = demande("/config", deux)
egal(code, 200, "marque ET identité ouvrent aussi — c'est le cas de production")

# ---- un en-tête vide ne vaut pas identité ----------------------------------
vide = dict(NAV)
vide[ENTETE_EMAIL] = ""
code, _ = demande("/config", vide)
ok(code != 200, "un en-tête d'identité VIDE n'ouvre rien (obtenu %d)" % code)

# ---- le secret ne fuit pas dans le journal ---------------------------------
ok(serveur.poll() is None, "le serveur a survécu à toutes ces sondes")
serveur.terminate()
try:
    serveur.wait(timeout=5)
except Exception:
    serveur.kill()

trace = pathlib.Path(JOURNAL).read_text(encoding="utf-8", errors="replace")
ok(marque_proxy.VALEUR not in trace,
   "la marque de proxy n'apparaît pas dans le journal du serveur")
ok("jeton-de-test" not in trace,
   "le jeton d'API non plus")

shutil.rmtree(ETAT, ignore_errors=True)
try:
    os.unlink(JOURNAL)
except OSError:
    pass

print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
