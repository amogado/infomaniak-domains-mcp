#!/usr/bin/env bash
# Déploie le connecteur dans le tenant homa `infomaniak-domains`.
#
# Le ConfigMap est régénéré depuis les fichiers du dépôt à chaque passage :
# c'est ce qui fait que le dépôt reste la source de vérité, et qu'aucune
# variante ne peut survivre dans le cluster sans être ici.
#
# ---------------------------------------------------------------------------
# Les deux Secrets, à créer UNE FOIS, hors dépôt
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
# ---------------------------------------------------------------------------
set -euo pipefail

NS="${INFOMANIAK_NS:-infomaniak-domains-default}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K="kubectl -n $NS"

echo "==> Vérifications"

# Fail-closed : mieux vaut refuser de déployer que laisser tourner un pod qui
# boucle en CrashLoop parce qu'un Secret manque. L'absence tombe du côté qui
# alarme.
for s in infomaniak-token infomaniak-domains-basicauth; do
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

echo "==> Manifests"
$K apply -f "$HERE/k8s/networking.yaml"
$K apply -f "$HERE/k8s/deployment.yaml"

echo "==> Rollout"
# Le ConfigMap a peut-être changé sans que le Deployment bouge : sans restart,
# le pod garderait l'ancien code et le déploiement se dirait réussi.
$K rollout restart deploy/infomaniak-domains
$K rollout status  deploy/infomaniak-domains --timeout=120s

echo "==> OK — https://domaines.ephais.eu"
echo "    La frontière ne se vérifie que de l'extérieur, sans mot de passe :"
echo "    ./tests/check_frontiere.sh https://domaines.ephais.eu"
