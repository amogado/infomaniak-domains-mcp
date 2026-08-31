# DONE — les dettes fermées

Écrit **uniquement** par `todo done`, sur `origin/main`. Une ligne par dette
fermée, avec le commit qui la ferme et la **preuve constatée** — ce qu'on a vu,
pas ce qu'on a fait. Un identifiant fermé n'est jamais réutilisé : il reste une
adresse valide vers cette ligne.

| ID | Titre | Commit | Preuve |
|---|---|---|---|
| D11 | La portée d'un outil est déduite d'une marque dans sa description | `70826bc` | https://domains.mcp.ephais.eu/_whoami rend marque_proxy: true et l'empreinte serveur.py 57978f0c6b0d7bfb, identique au dépôt ; check_frontiere.sh contre la prod : 28 sondes, 0 échec ; ./tests/run.sh : 922 vérifications ; ./tests/mutants.sh : 79 mutants, 0 survivant |
| D12 | Amorçage §0 du modus operandi : établir ce que le dépôt ne dit pas | `70826bc` | https://domains.mcp.ephais.eu/_whoami rend marque_proxy: true et l'empreinte serveur.py 57978f0c6b0d7bfb, identique au dépôt ; check_frontiere.sh contre la prod : 28 sondes, 0 échec ; ./tests/run.sh : 922 vérifications ; ./tests/mutants.sh : 79 mutants, 0 survivant |
| D13 | La NetworkPolicy coupe Traefik : cause non établie, donc non appliquée | `70826bc` | Cause établie et mesurée : k3s en flannel VXLAN, aucun contrôleur de NetworkPolicy en pod ; le paquet arrive masqué derrière le flannel.1 du nœud émetteur (10.42.0.0) AVANT que la policy ne le regarde, donc un namespaceSelector ne peut pas reconnaître une source dont l'adresse de pod a disparu. Une policy qui marche existe mais exige la co-localisation avec le nœud d'entrée, que la plateforme refuse à l'admission (tenant-no-nodename). D1, opérante depuis ce commit, ferme le même trou dans l'application, quel que soit le placement. Tout est écrit dans k8s/reseau.yaml. |

Fin.
