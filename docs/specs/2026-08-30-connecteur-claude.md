# Faire de ce MCP un connecteur Claude.ai

**État : spec. Rien n'est déployé.** Écrit le 2026-08-30.

## Ce qu'on veut

Que Claude Chat et Cowork puissent piloter les domaines et zones DNS Infomaniak
comme n'importe quel connecteur — sans installation locale, sans stdio.

Aujourd'hui, `infomaniak_mcp.py` ne parle que **stdio** : il ne sert que Claude
Code sur cette machine. Un connecteur exige un transport HTTP distant et un
serveur d'autorisation OAuth 2.1.

## Décisions prises

| Décision | Raison |
|---|---|
| Tenant homa dédié `infomaniak-domains` | Choix de Vincent : un service, un connecteur, un dépôt. Une panne de kiosquier n'emporte pas la gestion des domaines. ~0,11 €/mois. |
| Hôte `domains.mcp.ephais.eu` | Sous-domaine d'un domaine déjà possédé : rien à acheter, et le nom dit la fonction sans mélanger avec kiosquier. |
| **Un seul jeu d'outils, deux transports** | `infomaniak_mcp.py` reste la source de vérité des outils et de leurs schémas. Le serveur HTTP les importe. Deux définitions divergeraient, et la divergence se verrait en production, pas en test. |
| Couche OAuth calquée sur kiosquier | Elle est éprouvée par 431 lignes de tests de bout en bout, et ses pièges sont documentés. Réécrire de zéro un serveur d'autorisation, c'est réintroduire les mêmes failles une par une. |
| L'état OAuth sur un PVC | Un code non persisté est un code rejouable indéfiniment. |

## Ce qui reste ouvert, et qui doit être tranché avant de brancher

**Le connecteur OAuth de kiosquier n'a jamais abouti** : six codes émis, zéro
jeton échangé. Claude.ai n'appelle jamais `POST /token`. L'hypothèse — fenêtre
d'autorisation ouverte en onglet plutôt qu'en fenêtre surgissante, donc pas
d'`opener` à qui rendre la main — n'est ni confirmée ni réfutée.

Bâtir ce second connecteur sur la même base **double l'inconnue**. La mesure qui
tranche appartient à Vincent : rebrancher kiosquier sur `https://kiosquier.app/mcp`
avec les popups autorisés pour claude.ai.

- Si l'échange part → la base est bonne, répliquer est mécanique.
- Sinon → c'est notre redirection ou nos documents de découverte, et il faut le
  corriger **une fois**, pas deux.

D'où l'ordre : on construit et on éprouve localement, on ne branche qu'après.

## Le contrat

### Ce que le serveur expose

```
GET  /healthz                                    sonde
GET  /                                           page « Connecter Claude »
POST /mcp                                        transport MCP (Bearer obligatoire)
GET  /authorize                                  page de consentement — n'émet JAMAIS de code
POST /consent                                    le SEUL endroit qui émet un code
POST /token                                      échange du code, rotation du rafraîchissement
POST /register                                   enregistrement de client, sans état
GET  /.well-known/oauth-protected-resource       découverte
GET  /.well-known/oauth-protected-resource/mcp   idem
GET  /.well-known/oauth-authorization-server     idem
GET  /.well-known/openid-configuration           idem
```

### Ce qui est refusé sans exception

Repris de kiosquier, où chacun de ces points a son test :

- un `code_verifier` absent — le contournement le plus fréquent des serveurs
  d'autorisation écrits à la main ;
- un code rejoué : **révoque toute la famille** de jetons ;
- un jeton de rafraîchissement déjà tourné : même conduite ;
- un jeton présenté pour une autre ressource ;
- une portée élargie au rafraîchissement ;
- `GET /authorize` qui émettrait un code : il rend un formulaire, rien d'autre.

### Deux pièges à ne pas réintroduire

1. L'échange du code tient dans **une seule** prise de verrou. Le découper
   laisserait deux requêtes concurrentes porteuses du même code passer toutes
   deux la vérification avant qu'aucune n'ait écrit.
2. Un code **non persisté** est rejouable indéfiniment. Si l'écriture échoue, on
   rend 500 et aucun code n'est émis.

### La frontière

Claude appelle depuis le cloud, sans identifiants. Sept chemins — et eux seuls —
sortent de l'authentification humaine :

```
/mcp  /token  /register
/.well-known/oauth-protected-resource       (+ /mcp)
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

**`pathType: Exact`, jamais `Prefix`.** Traefik traduit `Prefix` en
`PathPrefix()`, préfixe de *chaîne* et non de segment : exempter `/mcp` en
`Prefix` exempterait aussi `/mcpXXX`.

L'Ingress du connecteur vise un Service **distinct** de celui de la page
humaine, pour qu'un futur oauth2-proxy ne capture pas les chemins machine.

### Les secrets côté serveur

Le jeton Infomaniak ne peut pas venir du trousseau macOS : le serveur tourne
dans un conteneur. Il vient d'un **Secret Kubernetes**, hors dépôt, monté en
variable d'environnement. `INFOMANIAK_ACCOUNT` reste posé — la frontière de
compte vaut ici aussi, et davantage : le serveur est joignable depuis Internet.

`INFOMANIAK_WRITE` et `INFOMANIAK_ACHAT` restent **désarmés par défaut**. Les
armer se décide par un patch explicite du Deployment, pas par oubli.

## Critères de sortie — des commandes qui rendent vrai ou faux

```bash
# 1. la découverte répond, sans authentification, depuis l'extérieur
curl -s https://domains.mcp.ephais.eu/.well-known/oauth-authorization-server \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])'
# doit imprimer https://domains.mcp.ephais.eu

# 2. la frontière est exacte, pas préfixée
./tests/check_frontiere.sh https://domains.mcp.ephais.eu
# 0 échec, et /mcpXXX doit répondre 401

# 3. l'OAuth de bout en bout, sur un serveur jetable
python3 tests/check_oauth.py
# consentement, PKCE, rejeu, rotation, portées, audience

# 4. les outils sont les mêmes des deux côtés
python3 tests/check_transports.py
# la liste et les schémas rendus par stdio et par /mcp sont identiques
```

Le critère 4 est le plus important à long terme : c'est lui qui empêche les deux
transports de diverger en silence.
