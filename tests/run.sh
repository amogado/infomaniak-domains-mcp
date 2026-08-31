#!/usr/bin/env bash
# Toute la suite. Aucun réseau, aucun jeton : la fausse API tient le rôle.
#
# Sauf une : `check_frontiere.sh` interroge la PRODUCTION depuis dehors, sans
# identifiants. C'est le seul angle qui prouve quelque chose sur la frontière —
# un `curl -u` ne dit rien de ce qu'un inconnu peut atteindre — et il n'était
# lancé par personne, le glob ne prenant que `check_*.py`. Voir la section
# « la frontière » plus bas pour ce qui compte, et ce qui ne compte pas, dans
# le code de sortie.
set -uo pipefail
cd "$(dirname "$0")/.."

# La cadence est éprouvée à part, avec un `dormir` injecté. Ici on la
# désarme : sans ça, un mutant qui casse l'élagage fait dormir la suite
# soixante secondes par appel, et un blocage ressemble alors à un mutant
# qui survit. Deux signaux distincts ne doivent pas se confondre.
export INFOMANIAK_RATE=1000000

total=0
casse=0
for check in tests/check_*.py; do
  sortie=$(python3 "$check" 2>&1) || casse=1
  echo "$sortie" | tail -20
  n=$(echo "$sortie" | grep -oE '^[0-9]+ vérifications' | grep -oE '^[0-9]+') || n=0
  total=$(( total + ${n:-0} ))
done

python3 -c "import ast; ast.parse(open('infomaniak_mcp.py').read())" || casse=1

# ---------------------------------------------------------------------------
# la frontière — le seul test qui sort de la machine
# ---------------------------------------------------------------------------
#
# Trois issues, et elles ne pèsent pas le même poids :
#
#   1. le script ABSENT ou non exécutable → ROUGE. Sa disparition serait
#      exactement ce qui vient de durer des semaines en silence : il existait,
#      et personne ne le lançait. On ne remplace pas un oubli muet par un
#      autre.
#   2. l'hôte INJOIGNABLE → ignoré, mais dit. Un test d'intégration qui échoue
#      faute de réseau ne mesure que le réseau.
#   3. l'hôte JOIGNABLE → la sonde tourne, et sa sortie s'affiche en entier.
#
# Dans le troisième cas, son verdict ne compte dans le code de sortie que si
# l'artefact déployé est CELUI DE CE WORKING TREE — comparaison d'empreintes
# par /_whoami, qui n'existe que pour cette question. C'est la seule règle
# honnête : ce code de sortie répond à « ce working tree est-il vert ? », et
# une production qui sert un autre artefact ne peut pas répondre à celle-là.
# Un écart de déploiement est donc annoncé en toutes lettres, et le verdict
# redevient bloquant à la seconde où la prod sert ce qu'on vient d'écrire.
#
# `INFOMANIAK_FRONTIERE=-` coupe la sonde. Le harnais de mutants s'en sert : il
# mesure si les tests LOCAUX mordent, et la réponse d'un hôte distant n'est pas
# ce signal-là — même raison que `INFOMANIAK_RATE` plus haut.
HOTE_FRONTIERE="${INFOMANIAK_FRONTIERE-https://domains.mcp.ephais.eu}"

echo
echo "== la frontière, depuis dehors et sans mot de passe =="
if [ ! -x tests/check_frontiere.sh ]; then
  echo "  ROUGE : tests/check_frontiere.sh est absent ou non exécutable."
  echo "  C'est le seul test du dépôt qui prouve quelque chose sur ce qu'un"
  echo "  inconnu peut atteindre. Son absence n'est pas une économie."
  casse=1
elif [ -z "$HOTE_FRONTIERE" ] || [ "$HOTE_FRONTIERE" = "-" ]; then
  echo "  ignorée : aucun hôte demandé (INFOMANIAK_FRONTIERE=${HOTE_FRONTIERE:-vide})."
elif ! curl -sS -m 4 -o /dev/null "$HOTE_FRONTIERE/healthz" 2>/dev/null; then
  echo "  ignorée : $HOTE_FRONTIERE est injoignable."
  echo "  Un test d'intégration qui échoue faute de réseau ne mesure que le réseau."
else
  sortie=$(./tests/check_frontiere.sh "$HOTE_FRONTIERE" 2>&1); verdict=$?
  echo "$sortie"
  # Quel artefact répond ? On compare des empreintes ; on ne suppose pas.
  distante=$(curl -sS -m 8 "$HOTE_FRONTIERE/_whoami" 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("code", ""))
except Exception:
    print("")' 2>/dev/null)
  locale=$(python3 -c '
import sys
sys.path.insert(0, ".")
import serveur
print(serveur.EMPREINTE_CODE)' 2>/dev/null)
  echo
  if [ -n "$distante" ] && [ "$distante" = "$locale" ]; then
    echo "  la production sert bien ce working tree — ce verdict compte."
    [ "$verdict" -eq 0 ] || casse=1
  else
    echo "  ÉCART DE DÉPLOIEMENT : la production ne sert pas ce working tree."
    echo "    dépôt      : ${locale:-inconnue}"
    echo "    production : ${distante:-aucune empreinte servie (/_whoami absent ?)}"
    echo "  Le verdict ci-dessus porte donc sur un AUTRE artefact que celui qu'on"
    echo "  vient d'écrire : il s'affiche, il ne compte pas dans le code de sortie,"
    echo "  et il redeviendra bloquant dès le prochain déploiement."
    if [ "$verdict" -ne 0 ]; then
      echo "  (sonde ROUGE sur l'artefact déployé — à lire avant de déployer)"
    fi
  fi
fi

echo
if [ "$casse" -eq 0 ]; then
  echo "TOUT EST VERT — $total vérifications"
else
  echo "IL Y A DU ROUGE"
fi
exit "$casse"
