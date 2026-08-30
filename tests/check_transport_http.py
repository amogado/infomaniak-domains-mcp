"""Deux failles critiques trouvées par audit adverse le 2026-08-31, et leurs
gardes. Toutes deux vivaient sous le JSON-RPC, au niveau du protocole HTTP —
donc invisibles à un test qui parle en JSON et lit une réponse décodée.

1. **Le refus Bearer était du code mort.** `_json()` ne rendait rien, donc
   `_defi_bearer()` rendait None, donc `if refus is not None: return refus` ne
   se déclenchait jamais. Le 401 partait, puis le traitement continuait : un
   anonyme recevait un 200 complet sur `/mcp` — un chemin volontairement sorti
   de l'authentification.

2. **Un corps annoncé et non lu devenait une requête clandestine.** Il restait
   dans le tampon et se faisait interpréter comme une requête pipelinée :
   `GET /mcp` avec un corps faisait servir une seconde requête, choisie par
   l'appelant, sur un chemin protégé. Les sept chemins exempts devenaient un
   tunnel vers tous les autres.

On compte donc les **réponses HTTP émises**, pas le contenu de la première.
"""

import os
import pathlib
import socket
import subprocess
import sys
import tempfile

RACINE = pathlib.Path(__file__).resolve().parent.parent

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
BASE = "http://127.0.0.1:%d" % PORT
ETAT = tempfile.mkdtemp(prefix="transport-")
HOTE = ("127.0.0.1:%d" % PORT).encode()

env = dict(os.environ)
env.update({"INFOMANIAK_DATA": ETAT, "INFOMANIAK_PUBLIC_BASE": BASE,
            "INFOMANIAK_LISTEN_PORT": str(PORT), "INFOMANIAK_TOKEN": "jeton-de-test",
            "PYTHONUNBUFFERED": "1"})
env.pop("INFOMANIAK_WRITE", None)
env.pop("INFOMANIAK_ACHAT", None)

serveur = subprocess.Popen([sys.executable, str(RACINE / "serveur.py")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)


def brut(requete, attente=3.0):
    requete = requete.replace(b"HOTE", HOTE)
    """Envoie des octets tels quels et rend la réponse entière. C'est le seul
    moyen de compter les réponses : un client HTTP n'en lit qu'une."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=attente)
    s.sendall(requete)
    morceaux = []
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            morceaux.append(d)
    except socket.timeout:
        pass
    s.close()
    return b"".join(morceaux).decode("utf-8", "replace")


# Le serveur doit être VIVANT : un port qui répond ne prouve pas que c'est le nôtre.
import time                                                  # noqa: E402

for _ in range(60):
    if serveur.poll() is not None:
        raise SystemExit("le serveur est mort au démarrage : %s"
                         % serveur.stderr.read().decode("utf-8", "replace")[:800])
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.4).close()
        break
    except OSError:
        time.sleep(0.15)

ok(serveur.poll() is None, "le serveur de test est vivant")

# ---- 1. un refus doit interrompre le traitement, pas seulement s'ajouter -----
corps = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}'
r = brut(b"POST /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Type: application/json\r\n"
         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(corps) + corps)
egal(r.count("HTTP/1.1"), 1, "un /mcp anonyme ne produit QU'UNE réponse")
ok("401" in r.split("\r\n")[0], "et c'est un 401")
ok("serverInfo" not in r, "aucun résultat d'initialize ne fuit après le refus")
ok("instructions" not in r, "les instructions du serveur ne fuitent pas non plus")

# ... et le même refus sur tools/list, qui exposerait l'inventaire des outils
corps = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
r = brut(b"POST /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Type: application/json\r\n"
         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(corps) + corps)
egal(r.count("HTTP/1.1"), 1, "tools/list anonyme ne produit qu'une réponse")
ok("commande_domaine" not in r, "l'inventaire des outils ne fuit pas à un anonyme")

# ---- 2. un corps non consommé ne doit pas devenir une requête ---------------
clandestine = b"GET / HTTP/1.1\r\nHost: HOTE\r\n\r\n"
r = brut(b"GET /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Length: %d\r\n\r\n"
         % len(clandestine) + clandestine)
egal(r.count("HTTP/1.1"), 1,
     "un corps annoncé sur GET /mcp ne fait pas servir une seconde requête")
ok("Connecter Claude" not in r, "la page protégée n'a pas fuité")

# le même vecteur visant explicitement un chemin protégé
clandestine = b"GET /authorize?x=1 HTTP/1.1\r\nHost: HOTE\r\n\r\n"
r = brut(b"GET /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Length: %d\r\n\r\n"
         % len(clandestine) + clandestine)
egal(r.count("HTTP/1.1"), 1, "idem en visant /authorize")

# ---- assertion inverse : une requête légitime reste servie normalement ------
r = brut(b"GET /healthz HTTP/1.1\r\nHost: HOTE\r\nConnection: close\r\n\r\n")
egal(r.count("HTTP/1.1"), 1, "une requête ordinaire rend bien une réponse")
ok("200" in r.split("\r\n")[0], "et /healthz répond 200")

r = brut(b"GET /.well-known/oauth-authorization-server HTTP/1.1\r\n"
         b"Host: HOTE\r\nConnection: close\r\n\r\n")
ok("200" in r.split("\r\n")[0], "la découverte reste publique")
ok(BASE in r, "et elle porte bien l'adresse publique configurée")

ok(serveur.poll() is None, "le serveur a survécu à tous ces envois")

serveur.terminate()
try:
    serveur.wait(timeout=5)
except Exception:
    serveur.kill()

print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
