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
| 2 | D2 | Le code d'autorisation est persisté en clair dans oauth.json pendant 300 s | `docs/specs/2026-08-30-connecteur-claude.md` | Sortir la fenêtre de grâce du fichier : la garder en mémoire de processus, bornée, avec la même péremption. | Contredit l'invariant que `empreinte()` énonce noir sur blanc — « le fichier d'état volé ne donne aucun jeton utilisable ». Les jetons sont bien hachés ; l'URL de réponse de la fenêtre de grâce, elle, recopie le code tel quel. Chemins de fuite réels : instantané du PVC, kubectl exec, kubectl cp. |
| 3 | D3 | La fenêtre de grâce de /consent re-livre un code déjà consommé | `docs/specs/2026-08-30-connecteur-claude.md` | Mémoriser l'empreinte du code à l'émission et ne re-livrer que s'il est encore vierge. | Le geste même pour lequel la grâce existe — recharger la page — renvoie un code déjà échangé ; l'échanger une seconde fois révoque toute la famille et tue l'autorisation qui marchait. Prouvé de bout en bout par l'audit. |

Fin.
