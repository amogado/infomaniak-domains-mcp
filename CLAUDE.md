# infomaniak-domains-mcp — notes pour l'agent

## Ce que c'est
Un serveur MCP stdio, stdlib Python uniquement, qui opère les domaines et les
zones DNS d'un compte Infomaniak. Un seul fichier : `infomaniak_mcp.py`.

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
