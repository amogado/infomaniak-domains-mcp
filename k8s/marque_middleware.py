#!/usr/bin/env python3
"""Le Middleware qui pose la marque du proxy — rendu au déploiement, jamais écrit.

Pourquoi ce fichier existe au lieu d'un simple manifeste
--------------------------------------------------------
`serveur.py` n'ouvre les pages humaines qu'à une requête portant
`X-Infomaniak-Proxy` avec la valeur exacte de `INFOMANIAK_MARQUE_PROXY`
(dette D1). Cette valeur est un secret partagé : Traefik la pose, le conteneur
la vérifie. Il faut donc que Traefik la connaisse.

Or le Middleware de Traefik ne sait pas lire un Secret : `customRequestHeaders`
ne prend qu'une valeur littérale. Écrire ce littéral dans `k8s/networking.yaml`
mettrait le secret partagé dans le dépôt, c'est-à-dire nulle part où il puisse
tourner — et un secret qu'on ne peut pas tourner n'en est plus un.

D'où ce générateur : la marque va du Secret à `kubectl` par un tuyau, et le
dépôt ne contient que la FORME du manifeste, jamais sa valeur. Voir `deploy.sh`.

Ce que ce rendu laisse quand même en clair, et pourquoi on l'accepte
--------------------------------------------------------------------
L'objet Middleware appliqué contient la marque en clair dans etcd : qui peut
faire `kubectl get middleware` dans ce namespace la lit. C'est vrai, et ce
n'est pas une régression — cette même personne peut faire `kubectl get secret`.
La menace que D1 ferme est ailleurs : un pod voisin qui joint le port 8080 en
direct, sans passer par Traefik. Ce pod-là n'a aucun accès à l'API Kubernetes
(le connecteur lui-même monte `automountServiceAccountToken: false`). Le
garde-fou tient donc entier contre ce qu'il vise.

Les trois noms qui doivent s'accorder, et qui ne peuvent pas diverger
---------------------------------------------------------------------
Le nom de l'en-tête, le nom de la variable d'environnement et le manifeste qui
l'injecte sont trois écritures d'une même chose. Deux orthographes — l'une dans
`serveur.py`, l'autre dans le middleware — donneraient un serveur qui refuse
TOUT LE MONDE, sans qu'aucun test du dépôt vire au rouge, parce qu'aucun test
ne parle à la fois au proxy et au serveur.

On ne recopie donc rien : ce générateur LIT les deux noms dans l'AST de
`serveur.py` — la seule et unique définition — et vérifie que
`k8s/deployment.yaml` injecte bien celui-là. Un renommage dans `serveur.py`
fait échouer le déploiement au lieu de produire un connecteur muet.

    python3 k8s/marque_middleware.py serveur.py k8s/deployment.yaml < <marque en base64>
"""

import ast
import base64
import json
import sys

# Le nom de l'objet Traefik. Il est référencé par l'annotation
# `router.middlewares` de l'Ingress HUMAIN, dans k8s/networking.yaml.
NOM = "infomaniak-domains-marque"

# Une marque trop courte se devine ; `deploy.sh` en fabrique 40 caractères tirés
# du hasard. Ce plancher n'est pas une politique de mot de passe, c'est un
# garde-fou contre une clé de Secret remplie à la main « pour essayer ».
LONGUEUR_MINIMALE = 24


def echoue(message):
    """Refuser de rendre un manifeste vaut mieux qu'en rendre un de travers.

    Un manifeste faux ici ne casse rien de visible : il pose une marque que le
    serveur refusera, et Vincent constatera qu'aucun mot de passe n'ouvre plus
    ses pages. On préfère l'échec bruyant du déploiement.
    """
    print("marque_middleware : " + message, file=sys.stderr)
    raise SystemExit(1)


def constante(arbre, nom):
    """La valeur littérale d'une affectation de module `nom = "..."`."""
    for noeud in arbre.body:
        if not isinstance(noeud, ast.Assign):
            continue
        for cible in noeud.targets:
            if isinstance(cible, ast.Name) and cible.id == nom:
                if isinstance(noeud.value, ast.Constant) and \
                        isinstance(noeud.value.value, str):
                    return noeud.value.value
                echoue("%s n'est plus une chaîne littérale dans serveur.py" % nom)
    return None


def variable_lue(arbre, nom):
    """Le nom d'environnement que lit l'affectation de module `nom = ...`.

    On cherche la première chaîne en MAJUSCULES du sous-arbre plutôt que la
    forme exacte `os.environ.get(...)` : `.strip()`, un `or`, un défaut ajouté
    plus tard enveloppent l'appel sans changer ce qu'on veut lire.
    """
    for noeud in arbre.body:
        if not isinstance(noeud, ast.Assign):
            continue
        if not any(isinstance(c, ast.Name) and c.id == nom for c in noeud.targets):
            continue
        for sous in ast.walk(noeud.value):
            if isinstance(sous, ast.Constant) and isinstance(sous.value, str):
                texte = sous.value
                if texte.isupper() and texte.replace("_", "").isalnum():
                    return texte
    return None


def main(argv):
    if len(argv) != 3:
        echoue("usage : marque_middleware.py <serveur.py> <deployment.yaml>")
    chemin_serveur, chemin_deploiement = argv[1], argv[2]

    # ---- la marque, lue sur l'entrée standard --------------------------------
    # `kubectl get secret -o jsonpath` rend du base64 ; on le décode ici plutôt
    # que par `base64 -d`, dont l'option de décodage ne s'écrit pas pareil selon
    # les systèmes. Une commande absente ferait passer du base64 pour la marque,
    # et le serveur refuserait tout le monde sans qu'on sache pourquoi.
    #
    # On retire tout blanc AVANT de décoder : `kubectl` n'en met pas, mais
    # `base64` en met — un saut de ligne final, et un repli tous les 76
    # caractères sur certains systèmes. Refuser ces blancs ferait échouer une
    # vérification faite à la main avec le même tuyau, et « ça marche par
    # kubectl mais pas à la main » est le genre d'écart qui coûte une soirée.
    # Un blanc n'appartient jamais à la charge base64 : le retirer ne peut rien
    # laisser passer.
    brut = b"".join(sys.stdin.buffer.read().split())
    try:
        marque = base64.b64decode(brut, validate=True).decode("utf-8")
    except Exception:
        echoue("l'entrée n'est pas du base64 valide — attendu la sortie de "
               "`kubectl get secret infomaniak-marque-proxy -o jsonpath='{.data.marque}'`")

    # Le serveur fait `.strip()` des deux côtés de la comparaison : on strippe
    # ici aussi, sans quoi un saut de ligne resté dans le Secret donnerait un
    # en-tête HTTP coupé en deux là où le serveur, lui, comparerait la valeur
    # nettoyée. Les deux côtés doivent nettoyer pareil.
    marque = marque.strip()

    if len(marque) < LONGUEUR_MINIMALE:
        echoue("la marque fait %d caractère(s), moins que le plancher de %d — "
               "sa création est documentée en tête de deploy.sh"
               % (len(marque), LONGUEUR_MINIMALE))
    if not marque.isascii() or not marque.isprintable() or any(c.isspace() for c in marque):
        echoue("la marque doit être de l'ASCII imprimable sans espace : c'est "
               "une valeur d'en-tête HTTP, et `hmac.compare_digest` lève sur "
               "une chaîne non-ASCII")

    # ---- les noms, lus dans serveur.py --------------------------------------
    with open(chemin_serveur, "r", encoding="utf-8") as f:
        arbre = ast.parse(f.read(), filename=chemin_serveur)

    entete = constante(arbre, "ENTETE_MARQUE")
    if not entete:
        echoue("ENTETE_MARQUE est introuvable dans %s : le nom de l'en-tête "
               "n'a plus de source unique, on ne devine pas" % chemin_serveur)

    variable = variable_lue(arbre, "MARQUE_PROXY")
    if not variable:
        echoue("impossible de lire dans %s le nom d'environnement de la marque"
               % chemin_serveur)

    with open(chemin_deploiement, "r", encoding="utf-8") as f:
        deploiement = f.read()
    if variable not in deploiement:
        echoue("serveur.py lit « %s », que %s n'injecte pas. Sans cette "
               "variable le serveur n'ouvre les pages humaines qu'à la boucle "
               "locale — c'est-à-dire à personne, derrière un proxy."
               % (variable, chemin_deploiement))

    # ---- le manifeste --------------------------------------------------------
    # La valeur passe par json.dumps : JSON est un sous-ensemble de YAML 1.2, et
    # c'est le seul échappement dont on soit sûr qu'il tienne quel que soit le
    # caractère tiré au sort dans la marque.
    print("# RENDU par k8s/marque_middleware.py — ne pas commiter le résultat.")
    print("# En-tête et variable viennent de l'AST de %s ; la valeur, du Secret" % chemin_serveur)
    print("# infomaniak-marque-proxy. Voir deploy.sh.")
    print("apiVersion: traefik.io/v1alpha1")
    print("kind: Middleware")
    print("metadata:")
    print("  name: %s" % NOM)
    print("spec:")
    print("  headers:")
    print("    customRequestHeaders:")
    print("      %s: %s" % (entete, json.dumps(marque)))

    # Ce qui est dit sur stderr ne va pas dans kubectl, et ne contient pas la
    # marque : de quoi lire le déploiement sans lire le secret.
    print("marque_middleware : en-tête %s, variable %s, %d caractères posés"
          % (entete, variable, len(marque)), file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
