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
| 1 | D14 | Slowloris sur la phase d'en-têtes : le budget de durée ne couvre que le corps | `docs/specs/2026-08-30-connecteur-claude.md` | Armer une échéance absolue dès l'acceptation de la connexion, couvrant ligne de requête et en-têtes, et lire ces phases contre ce budget. | Le chronomètre est armé APRÈS que BaseHTTPRequestHandler a lu la ligne de requête et tous les en-têtes ; DELAI_CORPS ne borne donc que la lecture du corps. Un client qui distille des octets d'en-tête tient un thread indéfiniment, sans aucun identifiant. Le correctif du second tour est incomplet, et l'auditeur l'a prouvé en socket brute. |
| 2 | D15 | Les tables access et refresh grossissent sans plafond d'espace | `docs/specs/2026-08-30-connecteur-claude.md` | Plafonner access et refresh comme les autres tables, avec éviction de la plus proche de sa péremption. | TOMBE_TTL les borne dans le TEMPS (1 h) mais pas dans l'espace. Un seul porteur qui fait tourner son jeton en série ajoute deux entrées par rotation ; la classe OOM que le correctif prétendait fermer reste ouverte, et l'état vit sur le PVC — un redémarrage ne répare rien. |

Fin.
