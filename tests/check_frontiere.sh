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
HOTE="${1:-https://domains.mcp.ephais.eu}"
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
echo "== ce qui doit être LISIBLE du dehors, pour savoir ce qui tourne =="
# L'empreinte du code chargé, lue SANS mot de passe. C'est le seul angle qui
# vaut : une empreinte qu'on ne peut lire qu'en s'authentifiant est une
# empreinte lue de l'intérieur, et le 29 août c'est justement la vue de
# l'intérieur qui a menti pendant des heures — le ConfigMap servait une
# variante divergente. Voir la dette D12.
sonde GET /_whoami 200 - \
  "sans lui, « quel artefact tourne ? » n'a pas de réponse constatable du dehors, \
et l'on retombe sur un ETAT.md qui affirme que la prod correspond au dépôt"

echo
echo "== la marque du proxy est-elle ARMÉE, là-bas, maintenant ? =="
# D1 ne se voit pas de l'extérieur : la marque est posée par Traefik ENTRE le
# proxy et le pod, donc aucun client d'Internet ne peut l'observer. Un serveur
# déployé sans `INFOMANIAK_MARQUE_PROXY` rendrait EXACTEMENT les mêmes codes que
# celui-ci sur toutes les sondes ci-dessus — et /authorize, la page qui émet les
# codes d'autorisation, serait joignable par n'importe quel voisin du cluster.
# C'est pour ça que /_whoami l'annonce : c'est le seul angle depuis lequel on
# peut constater qu'un déploiement est fermé.
#
# Le dire ne donne rien à personne : un serveur sans marque REFUSE tout ce qui
# ne vient pas de lui-même. Une réponse `false` n'ouvre pas une porte, elle
# signale une porte murée.
marque=$(curl -sS -m 15 "$HOTE/_whoami" 2>/dev/null)
if printf '%s' "$marque" | grep -qE '"marque_proxy"[[:space:]]*:[[:space:]]*true'; then
  VERTS=$((VERTS+1)); printf '  ok   %-6s %-46s %s\n' GET '/_whoami → marque_proxy' true
else
  ROUGES=$((ROUGES+1))
  printf '  FAIL %-6s %-46s %s\n' GET '/_whoami → marque_proxy' 'pas true'
  printf '       %s\n' "le connecteur tourne SANS la marque de D1 : /, /authorize, /consent et \
/revoke ne s'ouvrent qu'à la boucle locale, et rien d'autre ne le montrerait. Vérifier le \
Secret infomaniak-marque-proxy et le Middleware que deploy.sh en tire"
  ECHECS+=("GET /_whoami marque_proxy")
fi

# Et la marque ne doit pas s'obtenir en la demandant. Traefik ÉCRASE l'en-tête
# entrant — `customRequestHeaders` compile en `req.Header.Set`, mesuré le
# 2026-08-31 contre le Traefik 3.6.25 de ce cluster — donc une copie forgée ne
# survit pas à la traversée du proxy. Cette sonde-ci ne prouve pas
# l'écrasement : le Basic Auth répond avant, et ce qui se passe derrière lui est
# invisible d'Internet. Elle prouve ce qui compte pour un inconnu — écrire
# soi-même la marque n'ouvre rien. Le jour où elle rendrait 200, la frontière
# humaine serait tombée, quelle qu'en soit la raison.
sonde_forgee () {
  local chemin="$1" code
  code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
         -H 'X-Infomaniak-Proxy: marque-forgee-par-un-inconnu' \
         -H 'X-Forwarded-User: vincent' \
         "$HOTE$chemin" 2>/dev/null)
  if [ "$code" = "401" ]; then
    VERTS=$((VERTS+1)); printf '  ok   %-6s %-46s %s\n' GET "$chemin (en-têtes forgés)" "$code"
  else
    ROUGES=$((ROUGES+1))
    printf '  FAIL %-6s %-46s %s (attendu 401)\n' GET "$chemin (en-têtes forgés)" "${code:-aucun}"
    printf '       %s\n' "un inconnu qui écrit lui-même la marque du proxy entre : c'est \
exactement la faille que D1 ferme, et elle serait rouverte"
    ECHECS+=("GET $chemin forgé")
  fi
}
sonde_forgee /
sonde_forgee /authorize

echo
echo "== l'exemption doit être EXACTE, pas un préfixe =="
for chemin in /mcpXXX /tokenXXX /registerXXX /_whoamiXXX /.well-known/oauth-authorization-serverXXX; do
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
