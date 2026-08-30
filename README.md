# infomaniak-domains-mcp

Un serveur MCP pour opérer ses domaines et ses zones DNS chez [Infomaniak](https://www.infomaniak.com) :
lister ses domaines, savoir si un nom est libre et ce qu'il coûte, lire et
modifier les enregistrements DNS.

Stdlib Python uniquement. Un fichier, un `python3`. Pas d'environnement
virtuel, pas de dépendance à tenir à jour.

## Trois choix tenus exprès

**Lecture seule par défaut.** Une zone DNS est visible de tout le réseau, et un
enregistrement de travers retire un site sans que personne l'apprenne avant
qu'un utilisateur se plaigne. Les outils qui écrivent refusent d'agir tant que
`INFOMANIAK_WRITE=1` n'est pas posé — et le refus arrive *avant* l'appel
réseau, pas après.

**Dépenser n'est pas écrire.** Enregistrer un domaine engage de l'argent et ne
se défait pas. C'est donc un geste d'une autre classe, avec quatre barrières
indépendantes : un armement propre (`INFOMANIAK_ACHAT=1`, distinct de
`INFOMANIAK_WRITE`), un plafond en euros appliqué au total période comprise, un
montant **obligatoire et jamais deviné** — c'est ce qui donne sa valeur au
contrôle `invalid_expected_amount` de l'API — et une confirmation qui répète le
nom du domaine. Le transfert n'est pas exposé, et un test le vérifie sur l'AST.

**`INFOMANIAK_ACCOUNT` est une frontière, pas un défaut.** Un jeton voit souvent
plusieurs comptes. Épinglé, le serveur ne touche plus rien d'autre : l'argument
`account` ne peut que répéter l'épinglage, la liste des domaines est bornée à ce
compte, et **tout domaine ou zone nommé est vérifié comme lui appartenant**.
C'est ce dernier point qui compte : les zones DNS sont adressées par nom et non
par compte, donc sans ce contrôle, épingler ne protégerait que la moitié des
chemins — et pas celle par laquelle on casse le site d'un client.

## Installation

```bash
git clone https://github.com/amogado/infomaniak-domains-mcp.git ~/repos-mcp/infomaniak-domains-mcp
```

Il n'y a rien à installer.

## Le jeton

Il se crée sur <https://manager.infomaniak.com/v3/infomaniak-api>, avec les
portées minimales :

| Portée | Pour quoi |
|---|---|
| `accounts` | résoudre l'identifiant de compte — le contrôle de disponibilité en dépend |
| `domain:read` | lister les domaines, contrôler une disponibilité |
| `dns:read` | lire les zones et les enregistrements |
| `dns:write` | modifier les enregistrements — inutile si on reste en lecture |

Pour **enregistrer** un domaine, l'API en exige quatre de plus, relevé sur son
propre refus le 2026-08-30 :

```
domain:write   invoicing:prepaid:read   invoicing:order:write   invoicing:payment:write
```

À peser avant de les cocher : les deux dernières donnent au jeton le droit de
passer des commandes et d'effectuer des paiements sur le compte — pas seulement
d'acheter *ce* domaine. Un jeton porteur de `invoicing:payment:write` est une
clé de paiement, pas une clé de DNS.

Et surtout, **la commande par l'API tire sur le crédit prépayé du compte**, pas
sur un moyen de paiement enregistré. Solde vide, l'API répond
`insufficient_funds_prepaid_balance` — constaté le 2026-08-30. Aucun endpoint
public ne permet de lire ni de recharger ce solde. Pour un achat isolé, le
manager reste donc le chemin le plus court ; ces portées et ce crédit ne se
justifient que si l'on commande régulièrement par l'API.

Le serveur ne veut pas du jeton lui-même : il veut une **commande qui
l'imprime**, `INFOMANIAK_TOKEN_CMD`, exécutée au dernier moment. Le secret ne
figure alors dans aucun fichier de configuration, et il n'est jamais journalisé
ni renvoyé dans une réponse d'outil.

**Sur macOS, le trousseau est la meilleure source.** Il s'ouvre avec la session
de l'utilisateur, donc la lecture ne demande aucun déverrouillage séparé et
fonctionne depuis n'importe quel shell :

```bash
# le ranger — copier le jeton dans le presse-papier d'abord, pour qu'il
# n'apparaisse ni dans la ligne de commande ni dans l'historique
security add-generic-password -U -a "$USER" -s infomaniak-api -w "$(pbpaste)"

export INFOMANIAK_TOKEN_CMD='security find-generic-password -w -s infomaniak-api'
```

Avec un gestionnaire de mots de passe déverrouillable par session, comme
Bitwarden, la commande marche aussi — mais attention au piège : `bw` exige un
`BW_SESSION`, et une variable exportée dans un shell **n'atteint pas** un
processus lancé ailleurs. Le jeton de session doit exister dans
l'environnement qui démarre le client MCP, pas dans un shell voisin.

```bash
export INFOMANIAK_TOKEN_CMD='bw get password infomaniak-api --session "$BW_SESSION"'
```

En dernier recours, `INFOMANIAK_TOKEN` accepte le jeton en clair — au prix
d'un secret qui traîne dans un fichier.

## Configuration MCP

```json
{
  "mcpServers": {
    "infomaniak": {
      "command": "python3",
      "args": ["/Users/vous/repos-mcp/infomaniak-domains-mcp/infomaniak_mcp.py"],
      "env": {
        "INFOMANIAK_TOKEN_CMD": "bw get password infomaniak-api --session \"$BW_SESSION\""
      }
    }
  }
}
```

Pour armer les écritures, ajouter `"INFOMANIAK_WRITE": "1"`. Le serveur annonce
son état dans ses `instructions` d'`initialize`, donc le modèle sait dès la
poignée de main s'il peut écrire ou non.

## Variables d'environnement

| Variable | Effet |
|---|---|
| `INFOMANIAK_TOKEN` | le jeton, en clair |
| `INFOMANIAK_TOKEN_CMD` | une commande qui l'imprime — à préférer |
| `INFOMANIAK_WRITE` | `1` arme les outils qui écrivent ; absent, lecture seule |
| `INFOMANIAK_ACHAT` | `1` arme l'enregistrement de domaine ; distinct du précédent |
| `INFOMANIAK_ACHAT_MAX` | plafond en € HT, 50 par défaut ; illisible ⇒ refus |
| `INFOMANIAK_ACCOUNT` | **borne** le serveur à ce compte ; sinon résolu, et refusé s'il y en a plusieurs |
| `INFOMANIAK_BASE` | l'URL de l'API (pour les tests) |
| `INFOMANIAK_RATE` | le plafond par minute, 60 par défaut |

## Les outils

### Lecture

| Outil | Ce qu'il rend |
|---|---|
| `comptes` | les comptes visibles avec ce jeton |
| `domaines` | les domaines, filtrables par recherche ou extension |
| `domaine` | la fiche d'un domaine : expiration, statut, serveurs de noms |
| `disponibilite` | ce nom est-il libre, et à quel prix — n'engage rien |
| `zones` | les zones DNS d'un domaine |
| `enregistrements` | les enregistrements d'une zone, filtrables par type ou source |
| `verifie_enregistrement` | l'enregistrement est-il *servi* par les serveurs de noms |
| `dnssec` | l'état DNSSEC d'un domaine |
| `contacts` | les contacts du compte, pour renseigner une commande |

`verifie_enregistrement` mérite un mot : « écrit dans la zone » et « servi au
réseau » ne sont pas la même chose, et c'est exactement l'écart qui fait perdre
une demi-heure quand un certificat ne se renouvelle pas.

### Écriture — armées par `INFOMANIAK_WRITE=1`

| Outil | Ce qu'il fait |
|---|---|
| `ajoute_enregistrement` | crée un enregistrement |
| `modifie_enregistrement` | change la cible ou le TTL |
| `supprime_enregistrement` | supprime un enregistrement |
| `serveurs_de_noms` | remplace les serveurs de noms — au moins deux, jamais un |

### Dépense — armée par `INFOMANIAK_ACHAT=1`

| Outil | Ce qu'il fait |
|---|---|
| `commande_domaine` | enregistre un domaine ; exige montant lu, confirmation, et reste sous plafond |

Sur une coupure réseau, cet outil ne rend pas une erreur ordinaire : il annonce
une **issue indéterminée** et interdit le rejeu. Un délai dépassé ne prouve pas
que la commande n'est pas passée, et rejouer paierait deux fois.

## Les tests

```bash
./tests/run.sh
```

269 vérifications, sans réseau et sans jeton : une fausse API Infomaniak est
servie en local, et elle **enregistre chaque requête reçue**. C'est le point
important — quand un test vérifie qu'un garde-fou a bloqué une écriture, il
constate qu'aucune requête n'est partie, pas seulement qu'un message d'erreur
est revenu. Les deux ne disent pas la même chose : le second reste vert si
l'écriture est faite puis regrettée.

## Un pré-tri sans jeton

Avant même d'avoir un jeton, `outils/pre-tri-whois.py` dégrossit une liste de
candidats :

```bash
python3 outils/pre-tri-whois.py exemple.ch exemple.fr exemple.press
```

Il rend « libre / pris / incertain ». Un piège y est corrigé, et il vaut d'être
connu : quand le client whois ne suit pas la délégation vers le registre, il
rend la fiche du **TLD** au lieu de celle du domaine — « domain: CH »,
« organisation: SWITCH… » — et une détection naïve y voit un titulaire, donc
déclare occupé un nom parfaitement libre. Le script le repère et retombe sur
les serveurs de noms.

Cela dit, whois ne donne pas le prix et ne dit pas si le nom est réservable :
c'est l'outil `disponibilite` qui tranche.

## L'API en face

Base `https://api.infomaniak.com`, `Authorization: Bearer …`, enveloppe
`{"result": "success", "data": …}`. Plafond de **60 requêtes par minute**, qui
ne se relève pas — le client tient lui-même la cadence avec une fenêtre
glissante plutôt que d'essuyer un 429 au milieu d'une série d'écritures.

La spec complète est publiée en OpenAPI 3.1 sur
<https://developer.infomaniak.com/openapi.json> (4,5 Mo, 1069 chemins). Les
chemins employés ici en sont tirés, pas devinés.

## Licence

MIT.
