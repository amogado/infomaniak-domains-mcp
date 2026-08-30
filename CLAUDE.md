# infomaniak-domains-mcp — notes pour l'agent

## Ce que c'est
Un serveur MCP stdio, stdlib Python uniquement, qui opère les domaines et les
zones DNS d'un compte Infomaniak. Un seul fichier : `infomaniak_mcp.py`.

## Le modus operandi, branché sur ce dépôt

Le skill `modus-operandi` est agnostique ; voici ses réponses **pour ici**. Une
case vide se suppose, et une supposition coûte plus cher qu'une question.

| Question | Réponse |
|---|---|
| Rouge / vert ? | `./tests/run.sh` — 671 vérifications, sans réseau ni jeton |
| Les tests mordent-ils ? | `./tests/mutants.sh` — 43 mutants, 0 survivant |
| Déployer ? | `./deploy.sh` (tenant `infomaniak-domains`) — **jamais utilisé à ce jour** |
| Hôte canonique | `domaines.ephais.eu` — DNS posé, rien de déployé dessus |
| Quel artefact tourne ? | **non établi** — voir D12 |
| Où vit la dette ? | `TODO.md`, écrit **uniquement** par le binaire `todo`, sur `origin/main` |
| Gestes irréversibles | écriture DNS, enregistrement de domaine, révocation d'autorisation |
| Où sont les garde-fous ? | `tests/`, et `tests/mutants.sh` qui les éprouve |
| Hook d'audit adverse | **aucun** — voir D12 |

Le tableau se corrige quand une réponse change. Un `CLAUDE.md` qui décrit un état
révolu est pire qu'un `CLAUDE.md` absent.

### Ce que la dette contient aujourd'hui

Douze entrées, dont onze viennent d'un audit adverse mené le 2026-08-31 sur
`serveur.py` — qui n'est **pas déployé**. `todo list` fait autorité, pas la copie
de votre worktree.

### Trois leçons payées cher, à ne pas réapprendre

**Une frontière ne se teste pas sur un point de passage, mais sur tous.**
`INFOMANIAK_ACCOUNT` était éprouvé par 43 mutants dont aucun ne survivait — et
il avait deux trous, parce que je n'avais éprouvé qu'un outil sur quinze. Les
mutants prouvent que les tests mordent là où ils regardent ; ils ne disent rien
de ce qu'on n'a pas regardé. `check_epinglage.py` énumère désormais tous les
outils, **et vérifie que cet inventaire est complet**.

**Une fausse API bâtie sur la spec peut être une fiction.** L'OpenAPI ne décrit
pas la réponse du contrôle de disponibilité ; la mienne était inventée, et
masquait le prix de renouvellement — celui sur lequel on décide. Confronter au
réel dès qu'un jeton existe.

**Un message d'erreur ne doit pas affirmer une cause qu'on n'a pas mesurée.**
Le 429 disait « plafond de 60 par minute atteint » quoi que réponde l'API — et
il est arrivé après trois requêtes, sur un endpoint qui a sa propre limite. On
rend ce que l'API dit, détail de validation compris.

## Rendre rouge / vert
```bash
./tests/run.sh          # 164 vérifications, sans réseau ni jeton
```
La fausse API vit dans `tests/faux_api.py`. Elle **enregistre chaque requête**
(`faux_api.requetes()`) : c'est l'instrument qui permet de prouver qu'un geste
n'a *pas* eu lieu. Ne jamais se contenter d'un message d'erreur pour affirmer
qu'une écriture a été bloquée.

## Deux invariants à ne pas casser
1. **Aucun outil n'achète ni ne transfère de domaine.** Un test parcourt l'AST
   et vérifie qu'aucun `appel(...)` ne vise `/create` ou `/transfer`. Ne pas
   « corriger » ce test en cherchant les chaînes dans la source : la prose du
   module cite ces chemins pour expliquer qu'on ne les emprunte pas.
2. **Le refus d'écriture précède l'appel réseau.** `exige_ecriture()` est
   appelée après la validation des arguments mais avant `appel()`.

## Pièges connus
- Les tests manipulent `os.environ` ; `neuf()` remet l'état à zéro. Un test qui
  oublie `neuf()` hérite de l'armement du précédent.
- `_COMPTE` est un cache de module : le vider dans `neuf()`, sinon la résolution
  automatique du compte n'est plus observable.
- L'API impose un TTL entre 60 et 86400. On le refuse côté client pour ne pas
  brûler une requête du plafond de 60/minute.

## L'API
Spec OpenAPI 3.1 : <https://developer.infomaniak.com/openapi.json>. Les chemins
employés en sont tirés. Enveloppe `{"result","data"}` ; `result != "success"`
est une erreur même en HTTP 200.
