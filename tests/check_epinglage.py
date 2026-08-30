"""Le compte épinglé : une frontière, pas un défaut.

Quand `INFOMANIAK_ACCOUNT` est posé, le serveur ne doit plus rien pouvoir faire
en dehors de ce compte — ni lire, ni écrire, ni commander. Le point délicat est
que les zones DNS sont adressées **par nom de zone**, jamais par compte : sans
contrôle d'appartenance, épingler le compte ne protégerait que les chemins qui
portent un identifiant de compte, et laisserait grande ouverte la porte par
laquelle on casse vraiment quelque chose.
"""

import json
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


def deux_comptes():
    """Un compte à nous, un compte de tiers, chacun avec ses domaines."""
    faux_api.remise_a_zero()
    ik._COMPTE["valeur"] = None
    if hasattr(ik, "_DOMAINES_DU_COMPTE"):
        ik._DOMAINES_DU_COMPTE.clear()
    os.environ.pop("INFOMANIAK_WRITE", None)
    os.environ.pop("INFOMANIAK_ACHAT", None)
    faux_api.ETAT["comptes"] = [{"id": 90812, "name": "Un tiers"},
                                {"id": 607373, "name": "Le notre"}]
    faux_api.ETAT["domaines"] = [
        {"id": 1, "customer_name": "anous.fr", "account_id": 607373},
        {"id": 2, "customer_name": "autiers.fr", "account_id": 90812},
    ]
    faux_api.ETAT["zones"] = {"anous.fr": [{"id": 9, "fqdn": "anous.fr"}],
                              "autiers.fr": [{"id": 10, "fqdn": "autiers.fr"}]}
    faux_api.ETAT["enregistrements"] = {
        "anous.fr": [{"id": 1, "source": "", "type": "A", "target": "1.1.1.1",
                      "ttl": 3600, "updated_at": 1}],
        "autiers.fr": [{"id": 2, "source": "", "type": "A", "target": "2.2.2.2",
                        "ttl": 3600, "updated_at": 1}],
    }
    os.environ["INFOMANIAK_ACCOUNT"] = "607373"


# ------------------------------------- l'argument ne contourne pas l'épinglage
deux_comptes()
leve(lambda: ik.outil_disponibilite({"domain": "x.fr", "account": "90812"}),
     "épinglé", "un argument account qui diffère de l'épinglage : refus")
ok("607373" in _raison[0] and "90812" in _raison[0],
   "le refus nomme les deux comptes, l'épinglé et le demandé")
egal(len(faux_api.requetes(chemin_contient="/check")), 0,
     "et aucun appel n'est parti vers le mauvais compte")

# le même compte, redonné explicitement, ne pose pas de problème
r = ik.outil_disponibilite({"domain": "x.fr", "account": "607373"})
egal(faux_api.requetes(chemin_contient="/check")[-1]["chemin"],
     "/2/domains/accounts/607373/check", "le compte épinglé, redonné, passe")

# --------------- epingle, « comptes » ne montre plus que le compte epingle
# Trouve en balayant les quinze outils un par un : quatorze refusaient une cible
# etrangere, `comptes` rendait encore les trois — donc les noms des comptes de
# tiers. Un serveur borne a un compte n'a pas a reveler l'existence des autres.
deux_comptes()
r = ik.outil_comptes({})
egal(r["nombre"], 1, "epingle : un seul compte est rendu")
egal([str(c.get("id")) for c in r["comptes"]], ["607373"],
     "et c'est le compte epingle")
ok("Un tiers" not in json.dumps(r, ensure_ascii=False),
   "le nom d'un compte tiers n'apparait nulle part")
ok(r.get("epingle") is True, "et la reponse dit qu'elle est bornee")

# Sans epinglage, l'outil garde son role de diagnostic : il montre tout.
faux_api.remise_a_zero()
ik._COMPTE["valeur"] = None
ik._DOMAINES_DU_COMPTE.clear()
os.environ["INFOMANIAK_ACCOUNT"] = ""
faux_api.ETAT["comptes"] = [{"id": 90812, "name": "Un tiers"},
                            {"id": 607373, "name": "Le notre"}]
r = ik.outil_comptes({})
egal(r["nombre"], 2, "sans epinglage, les comptes visibles sont tous rendus")

# ------------------- l'argument account ne contourne AUCUN outil, pas juste un
# Trouvé par audit adverse le 2026-08-31, et c'était réel : `outil_domaines`
# écrivait `args.get("account") or compte_epingle()`, court-circuitant
# `compte_par_defaut()` — seule fonction qui tient la frontière. Le test
# précédent n'éprouvait que `disponibilite`, donc la brèche restait verte.
#
# La leçon vaut au-delà du correctif : une frontière ne se teste pas sur un
# point de passage, elle se teste sur TOUS. On énumère donc les outils qui
# acceptent un compte, et on exige que chacun refuse.
deux_comptes()
for nom, args in (
    ("domaines", {"account": "90812"}),
    ("disponibilite", {"domain": "x.fr", "account": "90812"}),
    ("contacts", {"account": "90812"}),
    ("solde", {"account": "90812"}),
):
    outil = ik.BY_NAME[nom]["handler"]
    leve(lambda o=outil, a=args: o(a), "épinglé",
         "%s : un compte étranger est refusé" % nom)

# Et on constate côté serveur qu'aucune requête n'a visé le compte du tiers.
fuites = [r for r in faux_api.requetes()
          if "90812" in r["chemin"] or ["90812"] == r["params"].get("account_id")]
egal(fuites, [], "aucune requête n'a atteint le compte du tiers")

# Assertion inverse : l'inventaire des outils à compte est-il complet ? Si un
# outil accepte « account » dans son schéma sans figurer ci-dessus, il n'est
# gardé par rien.
a_compte = {t["name"] for t in ik.TOOLS if "account" in t["inputSchema"]["properties"]}
egal(a_compte, {"domaines", "disponibilite", "contacts", "solde", "commande_domaine"},
     "l'inventaire des outils acceptant un compte est complet")

# --------------------------------------- la liste ne montre que notre compte
deux_comptes()
r = ik.outil_domaines({})
egal([d["customer_name"] for d in r["domaines"]], ["anous.fr"],
     "la liste des domaines est bornée au compte épinglé")
egal(faux_api.requetes(chemin_contient="/2/domains/domains")[-1]["params"].get("account_id"),
     ["607373"], "le filtre part bien à l'API, il n'est pas seulement appliqué après")

# ------------------------- les zones d'un tiers sont hors d'atteinte, en lecture
deux_comptes()
r = ik.outil_enregistrements({"zone": "anous.fr"})
egal(r["nombre"], 1, "notre zone se lit normalement")

leve(lambda: ik.outil_enregistrements({"zone": "autiers.fr"}), "épinglé",
     "lire la zone d'un tiers : refus")
ok("autiers.fr" in _raison[0], "le refus nomme la zone refusée")
leve(lambda: ik.outil_zones({"domain": "autiers.fr"}), "épinglé",
     "les zones d'un domaine de tiers : refus")
leve(lambda: ik.outil_domaine({"domain": "autiers.fr"}), "épinglé",
     "la fiche d'un domaine de tiers : refus")
leve(lambda: ik.outil_dnssec({"domain": "autiers.fr"}), "épinglé",
     "le dnssec d'un domaine de tiers : refus")

# ------------------------- et surtout hors d'atteinte en écriture
deux_comptes()
os.environ["INFOMANIAK_WRITE"] = "1"
avant = len(faux_api.requetes(methode="POST")) + len(faux_api.requetes(methode="DELETE"))

leve(lambda: ik.outil_ajoute_enregistrement(
        {"zone": "autiers.fr", "type": "A", "target": "6.6.6.6"}),
     "épinglé", "créer dans la zone d'un tiers : refus")
leve(lambda: ik.outil_supprime_enregistrement({"zone": "autiers.fr", "record": 2}),
     "épinglé", "supprimer dans la zone d'un tiers : refus")
leve(lambda: ik.outil_modifie_enregistrement(
        {"zone": "autiers.fr", "record": 2, "target": "6.6.6.6"}),
     "épinglé", "modifier dans la zone d'un tiers : refus")
leve(lambda: ik.outil_serveurs_de_noms(
        {"domain": "autiers.fr", "nameservers": ["a.test.", "b.test."]}),
     "épinglé", "changer les serveurs de noms d'un tiers : refus")

apres = len(faux_api.requetes(methode="POST")) + len(faux_api.requetes(methode="DELETE"))
egal(apres, avant, "aucune écriture n'a été tentée sur le compte du tiers")
egal(len(faux_api.ETAT["enregistrements"]["autiers.fr"]), 1,
     "la zone du tiers est intacte")

# ... alors que la nôtre reste modifiable
r = ik.outil_ajoute_enregistrement({"zone": "anous.fr", "type": "TXT", "target": "ok"})
egal(len(faux_api.ETAT["enregistrements"]["anous.fr"]), 2,
     "notre zone reste écrivable")

# ------------------------- une sous-zone déléguée de notre domaine est à nous
deux_comptes()
faux_api.ETAT["enregistrements"]["interne.anous.fr"] = []
r = ik.outil_enregistrements({"zone": "interne.anous.fr"})
egal(r["nombre"], 0, "une sous-zone de notre domaine est acceptée")

# mais pas un nom qui se contente de finir pareil : le contrôle porte sur le
# suffixe de domaine, pas sur une comparaison de chaînes
leve(lambda: ik.outil_enregistrements({"zone": "pasanous.fr"}), "épinglé",
     "un nom qui finit par le nôtre sans en être un sous-domaine : refus")

# ------------------------- la commande ne peut viser qu'un compte
deux_comptes()
os.environ["INFOMANIAK_ACHAT"] = "1"
leve(lambda: ik.outil_commande_domaine(
        {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
         "amount_total_excl_tax": 6.0, "account": "90812"}),
     "épinglé", "commander sur le compte d'un tiers : refus")
egal(faux_api.ETAT.get("commandes"), [], "aucune commande sur le compte d'un tiers")

# état neuf : sans épinglage, l'appel précédent aboutirait et rendrait le
# domaine indisponible pour le cas suivant — ce qui masquerait le vrai résultat.
deux_comptes()
os.environ["INFOMANIAK_ACHAT"] = "1"
r = ik.outil_commande_domaine(
    {"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
     "amount_total_excl_tax": 6.0})
egal(r["compte"], "607373", "sans argument, la commande va sur le compte épinglé")

# ------------------------- une variable vide ou blanche n'épingle rien
# Le piège : sans normalisation, « INFOMANIAK_ACCOUNT="   " » épinglerait le
# serveur sur un compte dont l'identifiant est fait d'espaces. Tous les appels
# partiraient vers un chemin absurde, et le message d'erreur parlerait d'un
# compte invisible à l'œil nu.
for blanc in ("", "   ", "\t", "\n  "):
    os.environ["INFOMANIAK_ACCOUNT"] = blanc
    ok(ik.compte_epingle() is None,
       "une valeur blanche %r n'épingle rien" % blanc)
os.environ["INFOMANIAK_ACCOUNT"] = "  607373  "
egal(ik.compte_epingle(), "607373",
     "les espaces autour d'un identifiant réel sont retirés")

# ------------------------- sans épinglage, le comportement d'avant est intact
faux_api.remise_a_zero()
ik._COMPTE["valeur"] = None
if hasattr(ik, "_DOMAINES_DU_COMPTE"):
    ik._DOMAINES_DU_COMPTE.clear()
os.environ["INFOMANIAK_ACCOUNT"] = ""
os.environ.pop("INFOMANIAK_WRITE", None)
r = ik.outil_enregistrements({"zone": "exemple.ch"})
egal(r["nombre"], 3, "sans épinglage, aucune restriction d'appartenance")
egal(len(faux_api.requetes(chemin_contient="/2/domains/domains")), 0,
     "et aucun appel d'appartenance n'est fait pour rien")

# L'appartenance n'est demandée qu'une fois, pas à chaque outil.
# On compte le chemin EXACT : « /2/domains/domains/anous.fr/zones » contient
# « /2/domains/domains », et un filtre par sous-chaîne compterait l'appel de
# zones comme une relecture d'appartenance. C'est le même piège que celui du
# filtre de source : comparer des égalités, pas des sous-chaînes.
def lectures_appartenance():
    return len([r for r in faux_api.requetes() if r["chemin"] == "/2/domains/domains"])


deux_comptes()
ik.outil_enregistrements({"zone": "anous.fr"})
n1 = lectures_appartenance()
egal(n1, 1, "une seule lecture d'appartenance au premier besoin")
ik.outil_enregistrements({"zone": "anous.fr"})
ik.outil_zones({"domain": "anous.fr"})
ik.outil_domaine({"domain": "anous.fr"})
egal(lectures_appartenance(), n1,
     "la liste d'appartenance est retenue, pas redemandée à chaque appel")

# ... et une commande réussie la périme, sinon le domaine tout juste acquis
# serait refusé au geste suivant.
os.environ["INFOMANIAK_ACHAT"] = "1"
ik.outil_commande_domaine({"domain": "kiosquier.ch", "confirmation": "kiosquier.ch",
                           "amount_total_excl_tax": 6.0})
faux_api.ETAT["domaines"].append({"id": 3, "customer_name": "kiosquier.ch",
                                  "account_id": 607373})
faux_api.ETAT["enregistrements"]["kiosquier.ch"] = []
r = ik.outil_enregistrements({"zone": "kiosquier.ch"})
egal(r["nombre"], 0, "le domaine tout juste commandé est immédiatement utilisable")
ok(lectures_appartenance() > n1,
   "la liste a bien été relue après la commande")

SERVEUR.shutdown()
print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
for e in ECHECS:
    print("  ✗", e)
sys.exit(1 if ECHECS else 0)
