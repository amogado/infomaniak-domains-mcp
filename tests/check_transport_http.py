"""Cinq failles critiques trouvées par audit adverse, et leurs gardes. Toutes
vivaient sous le JSON-RPC, au niveau du protocole HTTP — donc invisibles à un
test qui parle en JSON et lit une réponse décodée par un client tolérant.

Les deux premières datent du 2026-08-31 ; les trois dernières du second audit,
qui a montré qu'elles avaient SURVÉCU au premier correctif.

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

3. **La coupure n'était pas ANNONCÉE.** `close_connection = True` était posé
   APRÈS `end_headers()` : la réponse partait d'allure keep-alive, le proxy
   remettait la socket dans son pool, et sa requête suivante mourait sans
   réponse. La décision se prend maintenant AVANT le premier octet, et la
   réponse porte `Connection: close` quand la connexion ne survit pas. Couper
   sans le dire, c'est faire porter la panne à l'intermédiaire.

4. **La désynchronisation CL.TE.** La couche HTTP de la stdlib cadre sur le
   seul `Content-Length` et ignore `Transfer-Encoding`. Une requête portant les
   deux faisait servir DEUX réponses, dont une clandestine — prouvé en socket
   brute. Ce serveur n'implémente pas le chunked : il refuse d'être le deuxième
   avis.

5. **Le slowloris anonyme.** La lecture du corps n'était bornée que par un
   `timeout` de 30 s, qui est un délai PAR recv et non un plafond de durée. Un
   octet toutes les vingt-neuf secondes tenait un thread indéfiniment, sans
   jamais présenter d'identifiant.

On compte donc les **réponses HTTP émises**, pas le contenu de la première.

Le banc pose `INFOMANIAK_DELAI_CORPS=2` : le budget de lecture est réglable
pour que le constater ne coûte pas huit secondes à chaque exécution. Ce n'est
pas un chemin de test — le réglage existe en production, borné à [1 s, 60 s] —
mais il rend la mesure rapide, et une suite lente est une suite qu'on cesse de
lancer.
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
DELAI = 2.0                 # le budget de lecture de corps, côté serveur

env.update({"INFOMANIAK_DATA": ETAT, "INFOMANIAK_PUBLIC_BASE": BASE,
            "INFOMANIAK_LISTEN_PORT": str(PORT), "INFOMANIAK_TOKEN": "jeton-de-test",
            "INFOMANIAK_DELAI_CORPS": str(DELAI),
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

# ---- 3. une coupure doit être ANNONCÉE, pas seulement décidée --------------
# La faille n'est pas la coupure : c'est le silence. `close_connection = True`
# posé après `end_headers()` fait partir une réponse d'allure keep-alive sur
# une socket qui va se fermer. Un proxy la remet dans son pool ; la requête
# suivante qu'il y envoie meurt sans réponse, et la panne s'affiche chez lui.


def entetes_de(reponse):
    """Les en-têtes de la PREMIÈRE réponse, en minuscules, dédoublées."""
    tete = reponse.split("\r\n\r\n", 1)[0]
    paires = []
    for ligne in tete.split("\r\n")[1:]:
        if ":" in ligne:
            nom, valeur = ligne.split(":", 1)
            paires.append((nom.strip().lower(), valeur.strip().lower()))
    return paires


def annonce_la_coupure(reponse):
    return any(nom == "connection" and "close" in valeur
               for nom, valeur in entetes_de(reponse))


clandestine = b"GET / HTTP/1.1\r\nHost: HOTE\r\n\r\n"
r = brut(b"GET /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Length: %d\r\n\r\n"
         % len(clandestine) + clandestine, attente=1.5)
ok(annonce_la_coupure(r),
   "une réponse qui laisse un corps non lu ANNONCE Connection: close — "
   "sinon le proxy garde une socket que le serveur ferme ; en-têtes vus : %s"
   % (entetes_de(r),))

# L'assertion inverse, sans laquelle « toujours couper » passerait pour un
# correctif : une requête ordinaire garde sa connexion, et ne l'annonce pas.
r = brut(b"GET /healthz HTTP/1.1\r\nHost: HOTE\r\n\r\n", attente=1.0)
ok(not annonce_la_coupure(r),
   "et une requête ordinaire, elle, garde sa connexion : %s" % (entetes_de(r),))
ok("200" in r.split("\r\n")[0], "  tout en répondant normalement")

# Un corps trop gros n'est pas lu non plus : la connexion ne peut plus servir,
# et là aussi il faut le dire.
r = brut(b"POST /register HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/json\r\nContent-Length: 999999\r\n\r\n{}",
         attente=1.5)
ok(annonce_la_coupure(r),
   "un corps annoncé trop gros coupe, et l'annonce : %s" % (entetes_de(r),))
ok("413" in r.split("\r\n")[0], "  et rend 413 — %s" % r.split("\r\n")[0])

# Le témoin « ce corps a été lu » doit se REMETTRE À ZÉRO d'une requête à
# l'autre. Sur une connexion persistante il ne l'était pas : la première
# requête le posait à vrai, la seconde en héritait, et son corps non lu
# redevenait une requête clandestine — la faille n° 2, une requête plus tard.
premier = b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}'
clandestine = b"GET / HTTP/1.1\r\nHost: HOTE\r\n\r\n"
r = brut(b"POST /register HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(premier)
         + premier
         + b"GET /mcp HTTP/1.1\r\nHost: HOTE\r\nContent-Length: %d\r\n\r\n"
         % len(clandestine) + clandestine, attente=1.5)
egal(r.count("HTTP/1.1 "), 2,
     "sur une connexion persistante, deux requêtes légitimes rendent DEUX "
     "réponses — la troisième serait celle que l'appelant a glissée")
ok("Connecter Claude" not in r, "et la page protégée n'a pas fuité")

# ---- 4. Content-Length et Transfer-Encoding ensemble : la désynchronisation --
# La stdlib cadre sur Content-Length et IGNORE Transfer-Encoding. Un proxy en
# amont fait l'inverse. Là où deux couches lisent deux longueurs, l'appelant
# choisit où commence la requête suivante — et il glisse la sienne.
clandestine = b"GET /authorize?x=1 HTTP/1.1\r\nHost: HOTE\r\n\r\n"
corps = b"0\r\n\r\n"
r = brut(b"POST /token HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Content-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n" % len(corps)
         + corps + clandestine, attente=1.5)
egal(r.count("HTTP/1.1"), 1,
     "une requête portant Content-Length ET Transfer-Encoding ne fait servir "
     "QU'UNE réponse — la seconde serait la requête que l'appelant a glissée")
ok("400" in r.split("\r\n")[0],
   "et c'est un refus de cadrage : %s" % r.split("\r\n")[0])
ok(annonce_la_coupure(r),
   "qui coupe la connexion et le dit — garder un tampon qu'on vient d'admettre "
   "ne pas savoir découper serait la même faille, une requête plus tard")
ok("Connecter Claude" not in r and "code_challenge" not in r,
   "et la page clandestine n'a pas été servie")

# Le même refus sans complice : Transfer-Encoding seul, que ce serveur
# n'implémente pas davantage.
r = brut(b"POST /token HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", attente=1.5)
ok("400" in r.split("\r\n")[0],
   "Transfer-Encoding seul est refusé aussi : %s" % r.split("\r\n")[0])

# CL.CL : deux longueurs annoncées, deux découpages possibles.
clandestine = b"GET /authorize?x=2 HTTP/1.1\r\nHost: HOTE\r\n\r\n"
r = brut(b"POST /token HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Content-Length: 0\r\nContent-Length: %d\r\n\r\n" % len(clandestine)
         + clandestine, attente=1.5)
egal(r.count("HTTP/1.1"), 1,
     "deux Content-Length contradictoires ne font servir qu'une réponse")
ok("400" in r.split("\r\n")[0],
   "et c'est un refus de cadrage : %s" % r.split("\r\n")[0])

# Une longueur qui n'est pas un nombre d'octets. `int()` accepte « +5 », les
# soulignés et les chiffres non ASCII ; un proxy en amont, non.
#
# Les espaces AUTOUR de la valeur n'y figurent pas, et c'est voulu : le parseur
# d'en-têtes de la stdlib les retire avant que ce serveur ne voie quoi que ce
# soit, comme le prescrit le RFC 7230. Exiger qu'on les refuse serait exiger
# qu'on refuse « 5 » — un test qui décrit un monde qui n'existe pas.
for longueur in (b"+5", b"0x5", b"-1", b"1_0", b"\xef\xbc\x95"):
    r = brut(b"POST /register HTTP/1.1\r\nHost: HOTE\r\n"
             b"Content-Type: application/json\r\nContent-Length: " + longueur
             + b"\r\n\r\n{}", attente=1.5)
    ok("400" in r.split("\r\n")[0],
       "Content-Length %r est refusé : %s" % (longueur, r.split("\r\n")[0]))

# L'assertion inverse : un corps ordinaire, lui, est bien lu et traité.
corps = b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}'
r = brut(b"POST /register HTTP/1.1\r\nHost: HOTE\r\n"
         b"Content-Type: application/json\r\nContent-Length: %d\r\n"
         b"Connection: close\r\n\r\n" % len(corps) + corps)
ok("201" in r.split("\r\n")[0],
   "et un enregistrement ordinaire aboutit encore — %s" % r.split("\r\n")[0])

# ---- 5. le slowloris : un budget de DURÉE, pas un délai par recv ------------
# `timeout = 30` se réarme à chaque octet reçu. Un octet toutes les vingt-neuf
# secondes tenait donc un thread pour toujours, anonymement, et
# ThreadingHTTPServer ne plafonne pas ses threads.


def goutte_a_goutte(taille_annoncee, octets, pause, attente):
    """Annonce un corps, n'en envoie qu'une partie, au compte-gouttes.

    Rend (réponse, secondes écoulées). Le temps mesuré est celui du BANC, pas
    celui du serveur : c'est bien le plafond de durée qu'on regarde, et non un
    compteur interne qu'on nous rapporterait."""
    depart = time.monotonic()
    s = socket.create_connection(("127.0.0.1", PORT), timeout=attente)
    s.sendall(b"POST /register HTTP/1.1\r\nHost: " + HOTE
              + b"\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
              % taille_annoncee)
    for _ in range(octets):
        time.sleep(pause)
        try:
            s.sendall(b" ")
        except OSError:
            break
    morceaux = []
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            morceaux.append(d)
    except (socket.timeout, OSError):
        pass
    s.close()
    return b"".join(morceaux).decode("utf-8", "replace"), time.monotonic() - depart


# Le goutte-à-goutte : chaque octet réarmerait un délai par recv, jamais un
# budget total. On en envoie assez peu pour ne jamais compléter le corps.
r, mis = goutte_a_goutte(4096, 12, DELAI / 3.0, attente=DELAI + 8)
ok(bool(r), "le serveur RÉPOND à un corps au goutte-à-goutte, au lieu de tenir "
            "le thread : sans budget total, rien n'arrive avant 30 s par recv")
ok("408" in r.split("\r\n")[0],
   "et il dit que le temps imparti est écoulé : %s" % (r.split("\r\n")[0] or "(rien)"))
ok(annonce_la_coupure(r),
   "et il coupe la connexion en l'annonçant : %s" % (entetes_de(r),))
ok(mis < DELAI + 6,
   "le tout en %.1f s, sans attendre les 30 s du délai par recv" % mis)

# L'assertion inverse, et elle est indispensable : un corps qui arrive en
# plusieurs tranches mais DANS le budget doit être servi normalement. Sans
# elle, « refuser tout corps fragmenté » passerait pour un correctif.
corps = b'{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}'
s = socket.create_connection(("127.0.0.1", PORT), timeout=DELAI + 8)
s.sendall(b"POST /register HTTP/1.1\r\nHost: " + HOTE
          + b"\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
          b"Connection: close\r\n\r\n" % len(corps) + corps[:10])
time.sleep(DELAI / 4.0)
s.sendall(corps[10:])
morceaux = []
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        morceaux.append(d)
except (socket.timeout, OSError):
    pass
s.close()
r = b"".join(morceaux).decode("utf-8", "replace")
ok("201" in r.split("\r\n")[0],
   "un corps arrivé en deux tranches, dans le budget, est servi normalement — %s"
   % (r.split("\r\n")[0] or "(rien)"))

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
