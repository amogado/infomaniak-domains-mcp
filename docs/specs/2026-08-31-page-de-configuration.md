# Une page pour configurer le connecteur

**État : spec.** Écrite le 2026-08-31.

## Ce qu'on veut

Que tout ce qui fait fonctionner ce connecteur se règle **depuis une page web
authentifiée**, et non par des `kubectl` que seul celui qui les a écrits sait
rejouer. Aujourd'hui : jeton d'API, compte épinglé, armements — tout vit dans
des variables d'environnement et des Secrets Kubernetes. Changer le jeton
demande de connaître une commande à tuyau ; armer l'écriture demande de patcher
un Deployment.

## La décision qui ne se rattrape pas : où vivent les réglages

**Sur le volume, dans `/data/config.json`, en `0600`.** Les variables
d'environnement deviennent des **valeurs d'amorçage** : elles servent au premier
démarrage, puis le fichier fait autorité dès qu'il existe.

L'alternative — laisser les secrets dans les Secrets Kubernetes et donner au pod
le droit de les modifier — a été écartée. Elle exigerait de monter un jeton de
compte de service dans un pod **joignable depuis Internet**, c'est-à-dire de
troquer un risque de fuite de configuration contre un risque d'accès à l'API du
cluster. Le second est bien pire.

**Ce qu'il faut savoir, et qui n'est pas agréable :** un Secret Kubernetes n'est
pas chiffré, il est encodé en base64. Quiconque peut faire `kubectl get secret`
ou `kubectl exec` dans ce namespace lit déjà le jeton aujourd'hui. Le volume ne
change donc rien pour cet adversaire-là. Il ajoute **une** exposition distincte :
les instantanés et sauvegardes de volume. C'est le prix, il est assumé, et il
est écrit ici plutôt que découvert plus tard.

Pas de chiffrement maison : écrire son propre chiffrement avec la seule
bibliothèque standard, c'est fabriquer la faille suivante. Si le besoin devient
réel, la réponse est une brique éprouvée, pas dix lignes de XOR.

## Ce que la page montre, et ce qu'elle ne montre jamais

**Un secret n'est jamais rendu.** Une fois posé, la page affiche :

- présent ou absent ;
- sa longueur ;
- ses quatre derniers caractères ;
- une empreinte courte (SHA-256 tronqué).

Assez pour distinguer deux jetons et vérifier qu'on a posé le bon. Inutile à qui
le vole.

Corollaire : **aucun champ pré-rempli**. Un formulaire qui réaffiche le secret
le met dans le cache du navigateur, dans le gestionnaire de mots de passe, et
dans la mémoire de la page. Le champ est vide, et un envoi vide ne change rien.

## Ce qui se règle

| Réglage | Nature | Effet |
|---|---|---|
| Jeton d'API Infomaniak | secret | remplaçable ; jamais réaffiché |
| Compte épinglé | choix | **liste déroulante** alimentée par l'API, pas un champ libre |
| Écriture DNS armée | bascule | interrupteur, avec ce qu'il autorise écrit à côté |
| Enregistrement de domaine armé | bascule | idem, avec avertissement de dépense |
| Plafond de dépense | nombre | en euros HT ; illisible ⇒ refus, comme aujourd'hui |

**Le compte est une liste, pas un champ.** Taper un identifiant à la main, c'est
exactement l'erreur qui a fait lister les domaines d'un tiers pendant cette
session. La page appelle l'API, montre les comptes visibles avec leur nom, et on
choisit.

**Un bouton « éprouver le jeton »** qui appelle l'API en lecture et rend ce
qu'il voit : les comptes, et le nombre de domaines du compte épinglé. C'est la
différence entre « j'ai collé quelque chose » et « ça marche » — trois jetons ont
été perdus en une soirée faute de cette vérification.

## Ce qui est journalisé

Chaque changement, dans `/data/journal.json`, borné :

- quoi a changé (le **nom** du réglage, jamais la valeur) ;
- quand ;
- quelle identité Google l'a fait.

Un armement de dépense qui apparaît sans qu'on sache qui l'a posé est une
question sans réponse. C'est le seul endroit où l'on peut la répondre.

## L'authentification

La page est un **chemin humain** : derrière le compte Google, derrière la marque
de proxy, avec jeton anti-CSRF à usage unique et contrôle de navigation — les
mêmes gardes que `/consent`, pour les mêmes raisons.

Elle exige donc de brancher Google sur cet hôte, comme sur le voisin. Nouveau
client OAuth Google, URI de redirection exactement :

```
https://domains.mcp.ephais.eu/oauth2/callback
```

Liste nominative : `vi.doyon@gmail.com`.

**Le canari : la marque ET l'identité, jamais l'identité seule.**

Première rédaction de cette spec — et elle avait tort : « le canari devra
accepter aussi l'identité transmise par oauth2-proxy ». Le constructeur l'a
appliquée, puis signalé le trou qu'elle ouvrait, et il avait raison.

`X-Auth-Request-Email` est un en-tête que l'appelant écrit lui-même s'il
n'existe rien pour l'écraser. Le pod écoute sur 8080, joignable depuis le
cluster sans traverser ni Traefik ni le proxy — la NetworkPolicy qui fermerait
ce chemin est une dette dont la cause est établie mais non refermable ici.
Accepter cet en-tête seul donnerait donc `/config` à tout voisin du cluster,
c'est-à-dire le pouvoir de poser le jeton d'API et d'armer la dépense.

La marque de proxy, elle, est infalsifiable : un secret partagé, comparé en
temps constant, qu'un middleware Traefik écrase à l'entrée.

**Le canari exige donc la marque.** L'identité est lue pour *journaliser qui
agit*, jamais pour décider s'il en a le droit. Et cela ne ferme aucune porte
légitime : en production les deux arrivent ensemble, Traefik posant la marque
avant le proxy, qui la transmet en amont.

## Ce qui NE se règle pas depuis la page

- **L'adresse publique.** Elle est gravée dans le connecteur enregistré chez
  Claude ; la changer par une page web donnerait un moyen simple de tout casser.
- **La marque de proxy.** Elle est la barrière qui protège la page elle-même :
  se laisser modifier par ce qu'on protège est un cercle.
- **Les autorisations OAuth.** Elles se révoquent, elles ne se règlent pas.

## Critères de sortie

```bash
# la page existe et exige une identité humaine
curl -s -o /dev/null -w '%{http_code}\n' https://domains.mcp.ephais.eu/config
# → 302 vers Google (ou 401), jamais 200

# un secret posé n'est jamais rendu
python3 tests/check_config.py     # dont : la page ne contient pas le jeton

# le fichier de configuration n'est lisible que par le service
kubectl -n infomaniak-domains-default exec deploy/infomaniak-domains -- \
  stat -c '%a' /data/config.json          # → 600

# les réglages survivent à un redémarrage
kubectl -n infomaniak-domains-default rollout restart deploy/infomaniak-domains
curl -s https://domains.mcp.ephais.eu/_whoami | jq '.ecriture_armee, .achat_arme'

# et la frontière n'a pas bougé
./tests/check_frontiere.sh https://domains.mcp.ephais.eu     # 0 échec
```

Le dernier est le plus important : ajouter une page humaine ne doit rien changer
aux chemins machine. C'est exactement le piège 2 du skill.
