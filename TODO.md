# TODO — les dettes ouvertes

Écrit **uniquement** par `todo`, sur `origin/main`, quelle que soit la branche.
Ne pas éditer à la main : `todo --help`.

- L'**identifiant** `D<n>` est stable — il est cité dans les commits. Jamais réutilisé.
- Le **rang** est la priorité ; il bouge à chaque révision (`todo move`).
- Une **décision** remplie veut dire « travaillable sans revenir demander un arbitrage ».
- Une dette se ferme avec `todo done`, qui l'inscrit dans `DONE.md` avec sa preuve.

Révisé le 2026-08-30.

## Rangs

| # | ID | Sujet | Spec | Décision | Pourquoi ce rang |
|---|---|---|---|---|---|
| 1 | D1 | `_humain_present()` croit un en-tête que l'appelant écrit lui-même | `docs/specs/2026-08-30-connecteur-claude.md` | Comparer une marque que seul le proxy peut produire, avec hmac.compare_digest ; middleware Traefik qui la pose ET écrase toute copie entrante. | C'est le filet qui garde la page émettant les codes d'autorisation. Aujourd'hui `Authorization: Basic n'importe-quoi` ou `X-Forwarded-User: x` le franchit, et le pod écoute sur 8080 sans NetworkPolicy : tout voisin du cluster atteint /authorize sans passer par Traefik. Gravité haute, et c'est la dernière avant déploiement. |

Fin.
