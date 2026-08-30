#!/usr/bin/env bash
# La frontière : qu'est-ce qui est public, et qu'est-ce qui ne l'est pas ?
#
# Le seul test du dépôt qui interroge la PRODUCTION depuis l'extérieur, SANS
# identifiants. C'est le seul angle qui prouve quelque chose : un curl avec
# « -u » ne dit rien de ce qu'un inconnu peut atteindre, et le faux positif
# n° 1 documenté par Anthropic est « ça marche dans Claude Code ou en curl,
# mais pas dans claude.ai ».
#
# Il reste dans la suite APRÈS le correctif : c'est lui qui détectera une
# régression de l'Ingress, qui se fait en YAML, loin des tests Python.
#
#   ./tests/check_frontiere.sh [https://hote]
set -uo pipefail
HOTE="${1:-https://domaines.ephais.eu}"
VERTS=0; ROUGES=0; ECHECS=()

sonde () {  # sonde <méthode> <chemin> <attendu> <motif www-authenticate|-> <pourquoi> [type]
  local methode="$1" chemin="$2" attendu="$3" motif="$4" pourquoi="$5" type="${6:-json}"
  local sortie code auth
  if [ "$methode" = "POST" ] && [ "$type" = "form" ]; then
    # /token n'accepte que du form-urlencoded : lui envoyer du JSON rendrait un
    # 415 parfaitement correct, et la sonde accuserait le code à tort.
    sortie=$(curl -sS -m 15 -o /dev/null -D - -X POST \
             -H 'Content-Type: application/x-www-form-urlencoded' \
             --data '' "$HOTE$chemin" 2>/dev/null)
  elif [ "$methode" = "POST" ]; then
    sortie=$(curl -sS -m 15 -o /dev/null -D - -X POST \
             -H 'Content-Type: application/json' \
             --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
             "$HOTE$chemin" 2>/dev/null)
  else
    sortie=$(curl -sS -m 15 -o /dev/null -D - "$HOTE$chemin" 2>/dev/null)
  fi
  code=$(printf '%s' "$sortie" | awk 'toupper($0) ~ /^HTTP\// {print $2}' | tail -1)
  auth=$(printf '%s' "$sortie" | tr -d '\r' | awk 'tolower($0) ~ /^www-authenticate:/ {sub(/^[^:]*: */,""); print; exit}')
  local ok=1
  [ "$code" = "$attendu" ] || ok=0
  if [ "$motif" != "-" ]; then
    case "$auth" in $motif) ;; *) ok=0 ;; esac
  fi
  if [ $ok -eq 1 ]; then
    VERTS=$((VERTS+1)); printf '  ok   %-6s %-46s %s\n' "$methode" "$chemin" "$code"
  else
    ROUGES=$((ROUGES+1))
    printf '  FAIL %-6s %-46s %s (attendu %s%s)\n' "$methode" "$chemin" "${code:-aucun}" "$attendu" \
      "$([ "$motif" != '-' ] && printf ', www-authenticate %s' "$motif")"
    printf '       %s\n' "$pourquoi"
    [ -n "$auth" ] && printf '       reçu : www-authenticate: %s\n' "$auth"
    ECHECS+=("$methode $chemin")
  fi
}

echo "== ce qui doit RESTER fermé à un inconnu =="
for chemin in / /read/x /s/x /m/x /api/documents /api/stats /api/library /api/highlights/x /connect; do
  sonde GET "$chemin" 401 'Basic*' \
    "ce chemin expose la lecture, les notes ou les statistiques : il doit rendre 401 Basic"
done
sonde GET /authorize 401 'Basic*' \
  "la page de consentement doit être atteinte par un navigateur qui a déjà le mot de passe"
sonde POST /consent 401 'Basic*' \
  "le seul endroit qui émet un code d'autorisation ne doit jamais être joignable sans identifiants"

echo
echo "== ce qui doit être OUVERT, pour que le connecteur existe =="
sonde POST /mcp 401 'Bearer*' \
  "Claude appelle /mcp depuis le cloud sans identifiants Basic ; il doit recevoir un défi Bearer \
portant resource_metadata, pas un défi Basic — sinon il abandonne sur « Couldn't reach the MCP server »"
for chemin in /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/mcp \
              /.well-known/oauth-authorization-server; do
  sonde GET "$chemin" 200 - \
    "sans ce document, Claude ne sait pas où demander un jeton et abandonne"
done
# Divergence assumée avec kiosquier, d'où ce test est copié : kiosquier rend un
# 404 explicite sur ce chemin, ce serveur-ci le SERT — la spec le range parmi
# les documents de découverte exposés. Ce qui compte des deux côtés est
# identique : la réponse est applicative et non un 401 du Basic Auth, donc le
# chemin est bien hors du middleware.
sonde GET /.well-known/openid-configuration 200 - \
  "il est dans la liste des chemins exposés ; surtout, ce n'est pas un 401 Basic"
sonde POST /register 400 - \
  "l'enregistrement doit répondre applicativement (400 sur un corps vide), pas 401 Basic"
sonde POST /token 400 - \
  "l'échange de jeton doit répondre applicativement, pas 401 Basic" form
sonde POST /token 415 - \
  "et refuser un type de corps qu'il n'accepte pas, applicativement aussi"

echo
echo "== l'exemption doit être EXACTE, pas un préfixe =="
for chemin in /mcpXXX /tokenXXX /registerXXX /.well-known/oauth-authorization-serverXXX; do
  sonde GET "$chemin" 401 'Basic*' \
    "un pathType Prefix exempterait aussi ce chemin — Traefik traduit Prefix en préfixe de CHAÎNE, \
pas de segment, et toute route future sous un chemin exempté deviendrait publique en silence"
done

echo
echo "$((VERTS+ROUGES)) sondes, $ROUGES échec(s)"
if [ $ROUGES -gt 0 ]; then
  printf '  - %s\n' "${ECHECS[@]}"
  exit 1
fi
echo "la frontière est celle qu'on croit"
