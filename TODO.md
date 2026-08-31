# TODO — les dettes ouvertes

Écrit **uniquement** par `todo`, sur `origin/main`, quelle que soit la branche.
Ne pas éditer à la main : `todo --help`.

- L'**identifiant** `D<n>` est stable — il est cité dans les commits. Jamais réutilisé.
- Le **rang** est la priorité ; il bouge à chaque révision (`todo move`).
- Une **décision** remplie veut dire « travaillable sans revenir demander un arbitrage ».
- Une dette se ferme avec `todo done`, qui l'inscrit dans `DONE.md` avec sa preuve.

Révisé le 2026-08-31.

## Rangs

| # | ID | Sujet | Spec | Décision | Pourquoi ce rang |
|---|---|---|---|---|---|
| 1 | D4 | Chaque /token anonyme réécrit tout l'état OAuth sur le PVC | `docs/specs/2026-08-30-connecteur-claude.md` | Ne persister que si le ménage a réellement retiré quelque chose. | /token est l'un des sept chemins volontairement sortis de l'authentification : n'importe qui l'atteint. Six chemins de refus appellent `oauth_save` sans que rien n'ait changé, sous le verrou global que /mcp doit prendre pour valider le moindre Bearer. Usure disque et déni de service, sans aucun identifiant. |
| 2 | D5 | `POST /revoke` n'a ni jeton anti-CSRF ni contrôle d'origine | `docs/specs/2026-08-30-connecteur-claude.md` | Traiter /revoke comme /consent : jeton à usage unique, contrôle Origin, contrôle Sec-Fetch-Site. | Le Basic Auth est un credential ambiant : le navigateur le rejoue seul sur une soumission inter-site. Une page hostile révoque toutes les autorisations du connecteur. /consent, juste au-dessus, a les trois contrôles — l'écart n'est pas voulu. |
| 3 | D6 | `canoniser_ressource()` lève sur un port malformé : /token plante sans réponse | `docs/specs/2026-08-30-connecteur-claude.md` | Attraper le ValueError et le traiter comme une ressource inconnue. | Un chemin public et non authentifié qui coupe la socket et crache une trace de pile dans le journal du pod. Le contrôle d'audience devient une porte de déni de service. |
| 4 | D7 | PKCE : `encode('ascii','ignore')` tronque, donc accepte un verifier différent | `docs/specs/2026-08-30-connecteur-claude.md` | Refuser avant de hacher : `[A-Za-z0-9._~-]{43,128}`, puis encoder sans 'ignore'. | Le contrôle cesse de prouver « le client est celui qui a demandé le code » — c'est la seule chose que PKCE existe pour prouver. Et la forme du RFC 7636 n'est jamais vérifiée. |
| 5 | D8 | Le contrôle de portée de /mcp plante sur des params malformés | `docs/specs/2026-08-30-connecteur-claude.md` | — | `params` non-objet ou `name` non-hachable lèvent AVANT le contrôle de portée : connexion coupée, trace de pile, et le contrôle n'est jamais atteint. Deux lignes le rendent inconditionnel. |
| 6 | D9 | `GET /authorize` écrit dans l'état persistant sans borne ni contrôle d'origine | `docs/specs/2026-08-30-connecteur-claude.md` | Refuser ce qui n'est pas une navigation (Sec-Fetch-Dest/Site), et borner le nombre d'entrées. | Tous les paramètres sont publics. Une page hostile boucle sur une balise `<img>`, le navigateur rejoue le Basic, et chaque requête ajoute une entrée et réécrit tout le JSON. |
| 7 | D10 | Le contrôle d'audience survit à sa mutation : il n'est pas éprouvé | `docs/specs/2026-08-30-connecteur-claude.md` | Émettre sous un INFOMANIAK_PUBLIC_BASE et présenter sous un autre. | Signalé par l'agent qui a écrit le serveur, pas par un auditeur — donc d'autant plus crédible. Un contrôle qu'aucun test ne mord est un contrôle dont on ne sait rien. |

Fin.
