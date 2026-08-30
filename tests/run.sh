#!/usr/bin/env bash
# Toute la suite. Aucun réseau, aucun jeton : la fausse API tient le rôle.
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

if [ "$casse" -eq 0 ]; then
  echo "TOUT EST VERT — $total vérifications"
else
  echo "IL Y A DU ROUGE"
fi
exit "$casse"
