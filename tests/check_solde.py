"""Le solde prépayé, déduit du grand livre.

Infomaniak n'expose pas le solde : `/1/invoicing/{compte}/payment/prepay`
répond « method_not_yet_implemented ». Seul l'historique des opérations est
lisible, et le solde s'en déduit par somme.

D'où le point délicat, et la raison d'être de ce fichier : **la pagination de
cet endpoint est défectueuse.** Constaté le 2026-08-30 — `pages` annonce un
nombre incohérent, et le paramètre `page` est ignoré au-delà d'une certaine
taille, si bien que la même page revient indéfiniment. Une lecture naïve
boucle, compte deux fois, et rend un solde faux.

Un solde faux est pire qu'un solde absent : on décide dessus. La règle tenue
ici est donc **fail-closed** — si l'on ne peut pas prouver que le grand livre
est complet, on ne rend aucun chiffre, on dit pourquoi.
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
os.environ["INFOMANIAK_ACCOUNT"] = "4242"

import infomaniak_mcp as ik                                # noqa: E402

ik.BASE = BASE

VERIFS = 0
ECHECS = []
_raison = [""]


def ok(c, quoi):
    global VERIFS
    VERIFS += 1
    if not c:
        ECHECS.append(quoi)


def egal(obtenu, attendu, quoi):
    ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def leve(fn, morceau, quoi):
    global VERIFS
    VERIFS += 1
    _raison[0] = ""
    try:
        fn()
    except ik.ErreurInfomaniak as err:
        _raison[0] = str(err)
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
    if hasattr(ik, "_DOMAINES_DU_COMPTE"):
        ik._DOMAINES_DU_COMPTE.clear()
    os.environ["INFOMANIAK_ACCOUNT"] = "4242"


# ------------------------------------------------------------- le cas nominal
neuf()
r = ik.outil_solde({})
egal(r["solde"], 35.5, "le solde est la somme des opérations")
egal(r["devise"], "EUR", "la devise")
egal(r["operations"], 2, "le nombre d'opérations")
egal(r["credite"], 50.0, "le total crédité")
egal(r["depense"], -14.5, "le total dépensé")
ok(r.get("complet") is True, "le grand livre est déclaré complet")

# La pagination cassée ne doit pas faire compter deux fois. La fausse API rend
# la même page indéfiniment quand per_page est grand — exactement comme la vraie.
ok(r["solde"] == 35.5,
   "malgré une pagination qui répète la même page, rien n'est compté deux fois")

# ------------------------------------------------- un livre plus long
neuf()
faux_api.ETAT["operations"] = [
    {"id": "po-%d" % i, "amount": 10.0, "currency": "EUR",
     "status": "payed", "created_at": 1788000000 + i}
    for i in range(250)
]
r = ik.outil_solde({})
egal(r["operations"], 250, "les 250 opérations sont toutes vues, sans doublon")
egal(r["solde"], 2500.0, "et la somme est juste")

# ------------------------------------- fail-closed : livre incomplet, pas de chiffre
# On fait mentir le total annoncé : l'API prétend 500 opérations alors qu'elle
# n'en rend que 2. Impossible de prouver la complétude, donc aucun solde.
neuf()
faux_api.ETAT["total_menteur"] = 500
leve(lambda: ik.outil_solde({}), "incomplet",
     "un grand livre incomplet ne rend aucun solde")
ok("500" in _raison[0] and "2" in _raison[0],
   "le refus dit combien on attendait et combien on a vu : %r" % _raison[0][:200])
ok("solde" in _raison[0].lower(), "et il dit qu'aucun solde n'est rendu")

# ------------------------------------- plusieurs devises : pas de total unique
neuf()
faux_api.ETAT["operations"] = [
    {"id": "po-1", "amount": 50.0, "currency": "EUR", "status": "payed",
     "created_at": 1},
    {"id": "po-2", "amount": 30.0, "currency": "CHF", "status": "payed",
     "created_at": 2},
]
r = ik.outil_solde({})
ok("solde" not in r or r.get("solde") is None,
   "avec deux devises, aucun total unique n'est rendu")
egal(r.get("par_devise"), {"EUR": 50.0, "CHF": 30.0},
     "les soldes sont rendus par devise")

# ------------------------------------- les opérations non payées ne comptent pas
neuf()
faux_api.ETAT["operations"] = [
    {"id": "po-1", "amount": 50.0, "currency": "EUR", "status": "payed",
     "created_at": 1},
    {"id": "po-2", "amount": 100.0, "currency": "EUR", "status": "pending",
     "created_at": 2},
]
r = ik.outil_solde({})
egal(r["solde"], 50.0, "une opération en attente ne gonfle pas le solde")
egal(r.get("en_attente"), 1, "mais elle est signalée")

# ------------------------------------- l'épinglage vaut ici aussi
neuf()
leve(lambda: ik.outil_solde({"account": "90812"}), "épinglé",
     "le solde d'un autre compte est refusé quand l'épinglage est posé")

# ------------------------------------- l'outil est offert, en lecture
noms = {t["name"] for t in ik.TOOLS}
ok("solde" in noms, "l'outil solde existe")
d = ik.BY_NAME["solde"]["description"]
ok(not d.startswith("[écrit]") and not d.startswith("[DÉPENSE]"),
   "il est marqué comme une lecture")

SERVEUR.shutdown()
print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
