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
| 4 | D4 | Chaque /token anonyme réécrit tout l'état OAuth sur le PVC | `docs/specs/2026-08-30-connecteur-claude.md` | Ne persister que si le ménage a réellement retiré quelque chose. | /token est l'un des sept chemins volontairement sortis de l'authentification : n'importe qui l'atteint. Six chemins de refus appellent `oauth_save` sans que rien n'ait changé, sous le verrou global que /mcp doit prendre pour valider le moindre Bearer. Usure disque et déni de service, sans aucun identifiant. |
| 5 | D5 | `POST /revoke` n'a ni jeton anti-CSRF ni contrôle d'origine | `docs/specs/2026-08-30-connecteur-claude.md` | Traiter /revoke comme /consent : jeton à usage unique, contrôle Origin, contrôle Sec-Fetch-Site. | Le Basic Auth est un credential ambiant : le navigateur le rejoue seul sur une soumission inter-site. Une page hostile révoque toutes les autorisations du connecteur. /consent, juste au-dessus, a les trois contrôles — l'écart n'est pas voulu. |
| 6 | D6 | `canoniser_ressource()` lève sur un port malformé : /token plante sans réponse | `docs/specs/2026-08-30-connecteur-claude.md` | Attraper le ValueError et le traiter comme une ressource inconnue. | Un chemin public et non authentifié qui coupe la socket et crache une trace de pile dans le journal du pod. Le contrôle d'audience devient une porte de déni de service. |
| 7 | D7 | PKCE : `encode('ascii','ignore')` tronque, donc accepte un verifier différent | `docs/specs/2026-08-30-connecteur-claude.md` | Refuser avant de hacher : `[A-Za-z0-9._~-]{43,128}`, puis encoder sans 'ignore'. | Le contrôle cesse de prouver « le client est celui qui a demandé le code » — c'est la seule chose que PKCE existe pour prouver. Et la forme du RFC 7636 n'est jamais vérifiée. |
| 8 | D8 | Le contrôle de portée de /mcp plante sur des params malformés | `docs/specs/2026-08-30-connecteur-claude.md` | — | `params` non-objet ou `name` non-hachable lèvent AVANT le contrôle de portée : connexion coupée, trace de pile, et le contrôle n'est jamais atteint. Deux lignes le rendent inconditionnel. |
| 9 | D9 | `GET /authorize` écrit dans l'état persistant sans borne ni contrôle d'origine | `docs/specs/2026-08-30-connecteur-claude.md` | Refuser ce qui n'est pas une navigation (Sec-Fetch-Dest/Site), et borner le nombre d'entrées. | Tous les paramètres sont publics. Une page hostile boucle sur une balise `<img>`, le navigateur rejoue le Basic, et chaque requête ajoute une entrée et réécrit tout le JSON. |

Fin.
