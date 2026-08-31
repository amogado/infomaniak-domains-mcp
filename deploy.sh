#!/usr/bin/env bash
# Déploie le connecteur dans le tenant homa `infomaniak-domains`.
#
# Le ConfigMap est régénéré depuis les fichiers du dépôt à chaque passage :
# c'est ce qui fait que le dépôt reste la source de vérité, et qu'aucune
# variante ne peut survivre dans le cluster sans être ici.
#
# ---------------------------------------------------------------------------
# Les trois Secrets, à créer UNE FOIS, hors dépôt
# ---------------------------------------------------------------------------
#
# 1. Le jeton d'API Infomaniak. Jamais dans un fichier, jamais dans une sortie
#    lisible, jamais en argument : on le fait passer du coffre à kubectl par un
#    tuyau, et il ne s'arrête nulle part entre les deux.
#
#      export BW_SESSION=$(bw unlock --raw)        # tapé par Vincent lui-même
#      bw get password infomaniak-api --session "$BW_SESSION" | tr -d '\n' \
#        | kubectl -n infomaniak-domains-default create secret generic \
#            infomaniak-token --from-file=token=/dev/stdin
#
#    --from-literal serait la voie évidente et c'est la mauvaise : l'argument
#    est visible dans `ps` pendant l'exécution, et reste dans l'historique du
#    shell après. /dev/stdin ne laisse ni l'un ni l'autre.
#    Le `tr -d` retire le saut de ligne final : le serveur le tolère, mais un
#    en-tête Authorization coupé en deux est un incident qu'on ne voit qu'en
#    lisant les octets.
#
#    Pour tourner le jeton : `kubectl delete secret infomaniak-token` puis
#    rejouer. Surtout pas `create --dry-run=client -o yaml | apply`, qui
#    imprimerait le secret en base64 sur le terminal.
#
# 2. Le htpasswd de l'authentification humaine. htpasswd -n demande le mot de
#    passe sans l'afficher et n'imprime que le condensat :
#
#      htpasswd -nB vincent \
#        | kubectl -n infomaniak-domains-default create secret generic \
#            infomaniak-domains-basicauth --from-file=users=/dev/stdin
#
#    La clé s'appelle `users` : c'est celle que le middleware Traefik lit.
#
# 3. La marque du proxy (dette D1) — le secret partagé entre Traefik et le
#    conteneur. Personne n'a besoin de la connaître : ni vous, ni Vincent. Elle
#    n'est lue que par le Middleware et par le pod, tous deux depuis ce Secret.
#    On la tire donc du hasard, et on ne la regarde jamais :
#
#      head -c 32 /dev/urandom | base64 | tr -d '\n=+/' \
#        | kubectl -n infomaniak-domains-default create secret generic \
#            infomaniak-marque-proxy --from-file=marque=/dev/stdin
#
#    Elle ne traverse ni fichier ni sortie lisible : /dev/urandom va dans le
#    tuyau, le tuyau va dans kubectl, et rien ne s'arrête entre les deux — pas
#    d'argument visible dans `ps`, pas de ligne dans l'historique du shell, pas
#    de fichier temporaire. Le `tr` retire le saut de ligne, le remplissage et
#    les deux caractères de base64 qui ne sont pas alphanumériques : ce qui
#    reste est ~40 caractères sûrs à la fois dans un en-tête HTTP, dans du YAML
#    et dans un shell. `marque_middleware.py` refuse tout le reste.
#
#    Pour la tourner : `kubectl delete secret infomaniak-marque-proxy`, rejouer
#    la commande ci-dessus, puis `./deploy.sh` — qui re-rend le Middleware ET
#    redémarre le pod. Les deux côtés changent ensemble parce qu'ils lisent la
#    même clé ; les tourner séparément fermerait les pages humaines jusqu'au
#    second geste.
# ---------------------------------------------------------------------------
set -euo pipefail

NS="${INFOMANIAK_NS:-infomaniak-domains-default}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="kubectl -n $NS"

echo "==> Vérifications"

# Fail-closed : mieux vaut refuser de déployer que laisser tourner un pod qui
# boucle en CrashLoop parce qu'un Secret manque. L'absence tombe du côté qui
# alarme.
#
# `infomaniak-marque-proxy` mérite un mot de plus que les deux autres. Sans lui,
# le déploiement ne planterait PAS : le pod démarrerait, /healthz répondrait, le
# connecteur MCP marcherait — et /, /authorize, /consent et /revoke seraient
# fermés à tout le monde, Vincent compris, parce que `_humain_present()` retombe
# alors sur la boucle locale. Personne ne pourrait plus autoriser Claude, et
# rien n'aurait l'air cassé. C'est exactement le genre de panne qu'on paye une
# demi-journée ; on la refuse ici, en une ligne.
for s in infomaniak-token infomaniak-domains-basicauth infomaniak-marque-proxy; do
  if ! $K get secret "$s" >/dev/null 2>&1; then
    echo "   Secret « $s » absent du namespace $NS." >&2
    echo "   Sa création est documentée en tête de ce fichier." >&2
    exit 1
  fi
done

# serveur.py et infomaniak_mcp.py partent dans le MÊME ConfigMap, donc dans le
# même répertoire : c'est ce qui fait que `import infomaniak_mcp` trouve la
# seule et unique définition des outils. Les séparer casserait l'import — et
# le rétablir en recopiant les schémas ferait exactement la divergence
# silencieuse qu'on cherche à rendre impossible.
SRC=("$HERE/serveur.py" "$HERE/infomaniak_mcp.py")
for f in "${SRC[@]}"; do
  [ -f "$f" ] || { echo "   Fichier manquant : $f" >&2; exit 1; }
done

# Un ConfigMap plafonne à 1 Mio, côté etcd. Le dépassement se manifeste par un
# refus de l'API au pire moment ; le dire ici coûte une ligne.
OCTETS=$(cat "${SRC[@]}" | wc -c | tr -d ' ')
if [ "$OCTETS" -ge 1000000 ]; then
  echo "   Le code fait $OCTETS octets : trop près du plafond de 1 Mio d'un ConfigMap." >&2
  exit 1
fi

echo "==> ConfigMap ($OCTETS octets)"
$K create configmap infomaniak-domains-app \
  --from-file="${SRC[0]}" --from-file="${SRC[1]}" \
  --dry-run=client -o yaml | $K apply -f -

echo "==> La marque du proxy"
# AVANT networking.yaml, et l'ordre n'est pas cosmétique : l'Ingress humain
# référence ce Middleware par annotation, et Traefik rend 500 sur une route dont
# un middleware manque. Le poser d'abord, c'est ne jamais traverser un état où
# le site est ouvert-mais-cassé.
#
# La valeur ne s'arrête nulle part : le Secret va dans le tuyau, le tuyau va
# dans le générateur, le générateur va dans kubectl. Pas de fichier
# intermédiaire, pas d'argument visible dans `ps`, rien d'imprimé sur le
# terminal — `marque_middleware.py` ne dit sur sa sortie d'erreur que le nom de
# l'en-tête et le NOMBRE de caractères. `set -o pipefail` fait qu'un refus du
# générateur arrête le déploiement au lieu d'appliquer un manifeste tronqué.
#
# Le générateur lit le nom de l'en-tête et celui de la variable dans l'AST de
# serveur.py, et vérifie que k8s/deployment.yaml injecte bien cette variable :
# les trois écritures d'un même nom ne peuvent donc pas diverger. C'est le seul
# écart qu'aucun test du dépôt ne verrait — il faudrait un test qui parle à la
# fois au proxy et au serveur, et il n'en existe pas.
#
# Le Secret existe — la boucle ci-dessus l'a vérifié — mais rien ne dit qu'il
# porte la bonne CLÉ : `--from-file=marque=/dev/stdin` mal recopié donne un
# Secret d'apparence normale et de contenu vide. On ne canalise pas cette
# vérification dans un `grep -q` : sous `pipefail`, un `grep` qui a trouvé
# ferme le tuyau, kubectl prend un SIGPIPE, et le succès se met à ressembler à
# un échec. La substitution de commande n'a pas ce défaut.
if [ -z "$($K get secret infomaniak-marque-proxy -o jsonpath='{.data.marque}')" ]; then
  echo "   Le Secret infomaniak-marque-proxy n'a pas de clé « marque » non vide." >&2
  echo "   Sa création est documentée en tête de ce fichier." >&2
  exit 1
fi
$K get secret infomaniak-marque-proxy -o jsonpath='{.data.marque}' \
  | python3 "$HERE/k8s/marque_middleware.py" \
      "$HERE/serveur.py" "$HERE/k8s/deployment.yaml" \
  | $K apply -f -

echo "==> Manifests"
$K apply -f "$HERE/k8s/networking.yaml"
# k8s/reseau.yaml n'est PAS appliqué : en l'état il coupe Traefik (502).
# Voir la dette D13 — le fichier reste au dépôt avec ce qui a été mesuré,
# parce qu'un manifeste retiré emporte le diagnostic avec lui.
$K apply -f "$HERE/k8s/deployment.yaml"

echo "==> Rollout"
# Le ConfigMap a peut-être changé sans que le Deployment bouge : sans restart,
# le pod garderait l'ancien code et le déploiement se dirait réussi.
$K rollout restart deploy/infomaniak-domains
$K rollout status  deploy/infomaniak-domains --timeout=120s

echo "==> OK — https://domains.mcp.ephais.eu"
echo "    La frontière ne se vérifie que de l'extérieur, sans mot de passe :"
echo "    ./tests/check_frontiere.sh https://domains.mcp.ephais.eu"
