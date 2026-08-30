"""Le protocole MCP, de bout en bout : un vrai sous-processus, du JSON-RPC sur
stdin/stdout, une vraie fausse API en face.

On lance le serveur comme un client MCP le lancerait. Un test qui appellerait
`handle()` en direct sauterait précisément la couche qui casse le plus souvent :
le cadrage ligne par ligne, l'encodage, et le fait que le processus reste vivant.
"""

import json
import os
import pathlib
import subprocess
import sys
import threading

RACINE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "tests"))
import faux_api                                            # noqa: E402

SERVEUR, BASE = faux_api.demarre()

VERIFS = 0
ECHECS = []


def ok(condition, quoi):
    global VERIFS
    VERIFS += 1
    if not condition:
        ECHECS.append(quoi)


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


class Client:
    """Un client MCP minimal, qui parle au serveur comme le ferait Claude."""

    def __init__(self, **environnement):
        env = dict(os.environ)
        env.pop("INFOMANIAK_WRITE", None)
        env.update({"INFOMANIAK_BASE": BASE, "INFOMANIAK_TOKEN": faux_api.JETON,
                    "INFOMANIAK_ACCOUNT": "4242", "PYTHONUNBUFFERED": "1"})
        env.update({k: str(v) for k, v in environnement.items()})
        self.proc = subprocess.Popen(
            [sys.executable, str(RACINE / "infomaniak_mcp.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, bufsize=1)
        self.erreurs = []
        threading.Thread(target=self._draine, daemon=True).start()
        self.n = 0

    def _draine(self):
        for ligne in self.proc.stderr:
            self.erreurs.append(ligne.rstrip())

    def demande(self, methode, params=None):
        self.n += 1
        message = {"jsonrpc": "2.0", "id": self.n, "method": methode}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        ligne = self.proc.stdout.readline()
        if not ligne:
            raise AssertionError("le serveur n'a rien répondu à %s ; stderr : %s"
                                 % (methode, " | ".join(self.erreurs)))
        return json.loads(ligne)

    def notifie(self, methode):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": methode}) + "\n")
        self.proc.stdin.flush()

    def appelle(self, nom, arguments=None):
        return self.demande("tools/call", {"name": nom, "arguments": arguments or {}})

    def vivant(self):
        return self.proc.poll() is None

    def ferme(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def texte(reponse):
    return reponse["result"]["content"][0]["text"]


def charge(reponse):
    return json.loads(texte(reponse))


# ---------------------------------------------------------------- poignée
faux_api.remise_a_zero()
c = Client()

r = c.demande("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "test", "version": "0"}})
egal(r["result"]["protocolVersion"], "2025-06-18", "initialize : la version demandée est rendue")
egal(r["result"]["serverInfo"]["name"], "infomaniak-domains", "initialize : le nom du serveur")
ok(r["result"]["capabilities"]["tools"] is not None, "initialize : la capacité outils")
ok("LECTURE SEULE" in r["result"]["instructions"],
   "initialize : les instructions annoncent la lecture seule")
ok("achète" in r["result"]["instructions"] or "achete" in r["result"]["instructions"],
   "initialize : les instructions disent qu'aucun outil n'achète")

c.notifie("notifications/initialized")
egal(c.demande("ping")["result"], {}, "ping")

r = c.demande("tools/list")
outils = r["result"]["tools"]
ok(len(outils) >= 12, "tools/list : %d outils" % len(outils))
ok(all("handler" not in t for t in outils),
   "tools/list : aucune fonction Python ne fuit dans la réponse")
ok(all("inputSchema" in t and "description" in t for t in outils),
   "tools/list : chaque outil a un schéma et une description")
noms = {t["name"] for t in outils}
ok("disponibilite" in noms, "tools/list : la disponibilité est offerte")

# ---------------------------------------------------------------- lecture
r = c.appelle("domaines")
ok(not r["result"].get("isError"), "domaines : pas d'erreur")
egal(charge(r)["nombre"], 2, "domaines : les deux, par le protocole")

r = c.appelle("disponibilite", {"domain": "kiosquier.ch"})
d = charge(r)
egal(d["libre"], True, "disponibilité par le protocole")
egal(d["premiere_periode_ht"], 6.0, "le prix de première période traverse le protocole")
egal(d["renouvellement_ht"], 9.9, "le prix de renouvellement aussi")

# ------------------------------------------------- une erreur reste une réponse
avant = len(faux_api.requetes())
r = c.appelle("supprime_enregistrement", {"zone": "exemple.ch", "record": 101})
ok(r["result"]["isError"], "sans armement : l'appel est marqué en erreur")
ok("lecture seule" in texte(r).lower(), "sans armement : la raison est nommée")
egal(len(faux_api.requetes()), avant, "sans armement : aucune requête n'est partie")
ok(c.vivant(), "le serveur survit à un refus")

r = c.appelle("outil_qui_nexiste_pas")
ok(r["result"]["isError"], "outil inconnu : erreur")
ok("disponibilite" in texte(r), "outil inconnu : les outils disponibles sont listés")
ok(c.vivant(), "le serveur survit à un outil inconnu")

r = c.appelle("domaine", {})
ok(r["result"]["isError"], "argument manquant : erreur")
ok(c.vivant(), "le serveur survit à un argument manquant")

# une ligne illisible ne doit pas tuer la session
c.proc.stdin.write("ceci n'est pas du json\n")
c.proc.stdin.flush()
egal(c.demande("ping")["result"], {}, "le serveur survit à une ligne illisible")

egal(c.erreurs, [], "rien n'a été écrit sur stderr")

# le jeton ne doit jamais reparaître dans une réponse
tout = json.dumps(c.demande("tools/list")) + texte(c.appelle("domaines"))
ok(faux_api.JETON not in tout, "le jeton ne fuit dans aucune réponse")
c.ferme()

# ------------------------------------------------------ armé, ça écrit vraiment
faux_api.remise_a_zero()
c = Client(INFOMANIAK_WRITE="1")
c.demande("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "test", "version": "0"}})
r = c.demande("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "test", "version": "0"}})
ok("LECTURE SEULE" not in r["result"]["instructions"],
   "armé : les instructions ne parlent plus de lecture seule")

r = c.appelle("ajoute_enregistrement",
              {"zone": "exemple.ch", "type": "TXT", "source": "_test",
               "target": "bonjour", "ttl": 600})
ok(not r["result"].get("isError"), "armé : la création passe — %s" % texte(r)[:120])
egal(charge(r)["cree"]["target"], "bonjour", "armé : la cible est écrite")
egal(len(charge(c.appelle("enregistrements", {"zone": "exemple.ch"}))["enregistrements"]),
     4, "armé : la zone en compte un de plus")
c.ferme()

SERVEUR.shutdown()
print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
