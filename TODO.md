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

Fin.
