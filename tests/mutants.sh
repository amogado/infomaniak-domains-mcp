#!/usr/bin/env bash
# Abîme délibérément le code, une fois par mutant, et exige que la suite vire au
# rouge. Un mutant qui survit nomme un trou dans les tests.
#
# ⚠️ La restauration se fait par `git checkout`, donc depuis l'index : ne jamais
# lancer ce script sur un travail non commité, sous peine d'effacer le travail
# et non le mutant. Le garde ci-dessous refuse de démarrer dans ce cas, et le
# trap restaure quoi qu'il arrive — interruption comprise.
set -uo pipefail
cd "$(dirname "$0")/.."

CIBLE=infomaniak_mcp.py

if ! git diff --quiet -- "$CIBLE" || ! git diff --cached --quiet -- "$CIBLE"; then
  echo "REFUS : $CIBLE a des modifications non commitées."
  echo "Commiter le vert d'abord — sinon la restauration efface le correctif."
  exit 2
fi

restaure() { git checkout -- "$CIBLE" 2>/dev/null; }
trap restaure EXIT INT TERM

survivants=0
teste=0

mutant() {
  local nom="$1" avant="$2" apres="$3"
  teste=$(( teste + 1 ))
  restaure
  python3 - "$CIBLE" "$avant" "$apres" <<'PY' || { echo "  ?? $nom : motif introuvable"; survivants=$(( survivants + 1 )); return; }
import sys, pathlib
fichier, avant, apres = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(fichier); s = p.read_text(encoding="utf-8")
if s.count(avant) != 1:
    sys.exit("le motif apparaît %d fois" % s.count(avant))
p.write_text(s.replace(avant, apres), encoding="utf-8")
PY
  if ./tests/run.sh >/dev/null 2>&1; then
    echo "  SURVIT  $nom"
    survivants=$(( survivants + 1 ))
  else
    echo "  tue     $nom"
  fi
  restaure
}

echo "mutants :"

mutant "le garde-fou d'écriture ne garde plus rien" \
  '    if not ecriture_armee():' \
  '    if False:'

mutant "n'importe quelle valeur arme l'écriture" \
  'return os.environ.get("INFOMANIAK_WRITE", "").strip() in ("1", "oui", "yes", "true")' \
  'return bool(os.environ.get("INFOMANIAK_WRITE", "").strip())'

mutant "la borne haute du ttl disparaît" \
  '    if not 60 <= ttl <= 86400:' \
  '    if not 60 <= ttl:'

mutant "la borne basse du ttl disparaît" \
  '    if not 60 <= ttl <= 86400:' \
  '    if not ttl <= 86400:'

mutant "le filtre de source devient une sous-chaîne" \
  'liste = [r for r in liste if str(r.get("source", "")) == source_voulue]' \
  'liste = [r for r in liste if source_voulue in str(r.get("source", ""))]'

mutant "le filtre de type devient sensible à la casse" \
  'type_voulu = (args.get("type") or "").strip().upper()' \
  'type_voulu = (args.get("type") or "").strip()'

mutant "un seul serveur de noms suffit" \
  '    if len(serveurs) < 2:' \
  '    if len(serveurs) < 1:'

mutant "l'enveloppe d'erreur est ignorée quand le code HTTP est bon" \
  '    if enveloppe.get("result") != "success" or code >= 400:' \
  '    if code >= 400:'

mutant "le compte est re-résolu à chaque appel" \
  $'    if _COMPTE["valeur"]:\n        return _COMPTE["valeur"]' \
  $'    if False:\n        return _COMPTE["valeur"]'

mutant "un compte fixé par l'environnement est ignoré" \
  '    fixe = os.environ.get("INFOMANIAK_ACCOUNT", "").strip()' \
  '    fixe = ""'

mutant "l'absence de jeton n'arrête plus rien" \
  $'    if not cle:\n        raise ErreurInfomaniak(' \
  $'    if False:\n        raise ErreurInfomaniak('

mutant "la cadence laisse passer la requête de trop" \
  '            if len(self.appels) >= self.plafond:' \
  '            if len(self.appels) > self.plafond:'

mutant "la fenêtre de cadence cesse de glisser" \
  $'            self.appels = [a for a in self.appels if t - a < self.fenetre]\n            if len' \
  $'            self.appels = list(self.appels)\n            if len'

mutant "le nom de domaine n'est plus normalisé" \
  'nom = (args.get("domain") or "").strip().lower()' \
  'nom = args.get("domain") or ""'

mutant "un nom sans extension part quand même sur le réseau" \
  '    if "." not in nom:' \
  '    if False:'

mutant "la description des enregistrements n'est plus demandée" \
  'params = {"with": "records_description", "per_page"' \
  'params = {"per_page"'

mutant "un 401 devient un message générique" \
  '        if code == 401:' \
  '        if False:'

mutant "le type n'est plus mis en capitales à la création" \
  '    type_ = (args.get("type") or "").strip().upper()' \
  '    type_ = (args.get("type") or "").strip()'

mutant "une modification vide part quand même" \
  $'    if not corps:\n        raise ErreurInfomaniak("rien à modifier' \
  $'    if False:\n        raise ErreurInfomaniak("rien à modifier'

mutant "les handlers fuitent dans tools/list" \
  '{k: v for k, v in t.items() if k != "handler"}' \
  'dict(t)'

echo
echo "$teste mutants, $survivants survivant(s)"
[ "$survivants" -eq 0 ]
