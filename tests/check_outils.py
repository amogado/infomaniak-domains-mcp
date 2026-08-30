"""Les outils, contre la fausse API.

Règle qu'on se donne ici : quand on vérifie qu'un geste n'a **pas** eu lieu, on
le constate côté serveur (aucune requête reçue), pas côté message d'erreur. Un
message d'erreur peut très bien arriver après que le mal est fait.
"""

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


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def leve(fn, morceau, quoi):
    """L'appel doit échouer, et la raison doit *nommer* le problème."""
    global VERIFS
    VERIFS += 1
    try:
        fn()
    except ik.ErreurInfomaniak as err:
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
egal(r["reponse"]["available"], True, "disponibilité : libre")
egal(r["reponse"]["price"], 14.9, "disponibilité : le prix est rendu")
egal(r["domaine"], "kiosquier.ch", "disponibilité : le domaine est rappelé")

r = ik.outil_disponibilite({"domain": "  KIOSQUIER.CH  "})
egal(r["domaine"], "kiosquier.ch", "disponibilité : le nom est normalisé")

r = ik.outil_disponibilite({"domain": "exemple.ch"})
egal(r["reponse"]["available"], False, "disponibilité : pris")

r = ik.outil_disponibilite({"domain": "kiosquier.ch", "with_option_prices": True})
ok("options" in r["reponse"], "disponibilité : les options quand on les demande")
egal(faux_api.requetes(chemin_contient="/check")[-1]["corps"]["with_option_prices"], True,
     "l'option part bien dans le corps")

leve(lambda: ik.outil_disponibilite({"domain": "kiosquier"}), "extension",
     "un nom sans extension est refusé avant l'appel")
egal(len(faux_api.requetes(chemin_contient="/check")), 4,
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

faux_api.ETAT["force_code"] = 429
leve(lambda: ik.outil_comptes({}), "minute", "un 429 nomme le plafond par minute")

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
for interdit in ("/create", "/transfer"):
    coupables = [c for c in chemins_appeles if interdit in c]
    egal(coupables, [],
         "aucun appel ne vise %s — acheter ou transférer n'est pas automatisable ici"
         % interdit)
# et l'assertion inverse : l'inventaire voit bien les chemins qui existent
ok(any("/2/zones/" in c for c in chemins_appeles),
   "l'inventaire voit les chemins de zone (donc il verrait un chemin d'achat)")
ok(any("/1/accounts" in c for c in chemins_appeles),
   "l'inventaire voit le chemin des comptes")

ecrivains = {t["name"] for t in ik.TOOLS if t["description"].startswith("[écrit]")}
egal(ecrivains, {"ajoute_enregistrement", "modifie_enregistrement",
                 "supprime_enregistrement", "serveurs_de_noms"},
     "les outils qui écrivent sont exactement ceux annoncés comme tels")

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


SERVEUR.shutdown()
print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
