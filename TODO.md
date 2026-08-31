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
| 1 | D6 | `canoniser_ressource()` lève sur un port malformé : /token plante sans réponse | `docs/specs/2026-08-30-connecteur-claude.md` | Attraper le ValueError et le traiter comme une ressource inconnue. | Un chemin public et non authentifié qui coupe la socket et crache une trace de pile dans le journal du pod. Le contrôle d'audience devient une porte de déni de service. |
| 2 | D9 | `GET /authorize` écrit dans l'état persistant sans borne ni contrôle d'origine | `docs/specs/2026-08-30-connecteur-claude.md` | Refuser ce qui n'est pas une navigation (Sec-Fetch-Dest/Site), et borner le nombre d'entrées. | Tous les paramètres sont publics. Une page hostile boucle sur une balise `<img>`, le navigateur rejoue le Basic, et chaque requête ajoute une entrée et réécrit tout le JSON. |
| 3 | D10 | Le contrôle d'audience survit à sa mutation : il n'est pas éprouvé | `docs/specs/2026-08-30-connecteur-claude.md` | Émettre sous un INFOMANIAK_PUBLIC_BASE et présenter sous un autre. | Signalé par l'agent qui a écrit le serveur, pas par un auditeur — donc d'autant plus crédible. Un contrôle qu'aucun test ne mord est un contrôle dont on ne sait rien. |

Fin.
