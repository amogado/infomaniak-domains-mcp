# Commander un domaine par l'API Infomaniak — ce qui bloque, dans l'ordre

Retour d'expérience du 2026-08-30, `kiosquier.app` enregistré au bout de six
refus successifs. **L'API ne révèle ses exigences qu'une par une** : chaque
correctif fait apparaître l'obstacle suivant. D'où cette fiche — pour les
franchir tous d'un coup au lieu de les découvrir en série.

L'appel qui a fini par passer est en bas. Si vous êtes pressé, allez-y, puis
remontez sur le refus que vous obtenez.

---

## Obstacle 1 — les portées du jeton

La commande exige **quatre portées de plus** que la lecture. L'API les nomme
elle-même dans son 403 ; ne les devinez pas :

```
domain:write   invoicing:prepaid:read   invoicing:order:write   invoicing:payment:write
```

Plus, pour tout le reste : `accounts` (sans elle, impossible de résoudre
l'identifiant de compte, et le contrôle de disponibilité en dépend),
`domain:read`, `dns:read`, `dns:write`.

Les portées se choisissent **à la création** du jeton ; la page ne permet pas de
re-porter un jeton existant. Il faut donc en créer un nouveau sur
<https://manager.infomaniak.com/v3/ng/profile/user/token/list>.

**À peser** : `invoicing:payment:write` donne au jeton le droit d'effectuer des
paiements sur le compte — pas seulement d'acheter *ce* domaine. Pour un achat
isolé, le manager reste le chemin le plus sobre.

### Éprouver les portées sans rien dépenser

Envoyez la commande avec un montant volontairement faux. L'API vérifie le
montant, donc elle refuse — mais le refus vous dit si les portées sont là :

```python
ik.appel("/2/domains/accounts/<compte>/create", methode="POST",
         corps={"domain": "exemple.app", "registration_period": 1,
                "amount_total_excl_tax": 0.01})
```

- `invalid_expected_amount` → **les portées sont bonnes**, rien n'a été commandé.
- un 403 nommant une portée → il en manque une, et elle est nommée.

---

## Obstacle 2 — le solde prépayé

`insufficient_funds_prepaid_balance`, en HTTP 500.

**La commande par l'API se paie sur le crédit prépayé du compte, jamais sur un
moyen de paiement enregistré.** C'est le piège le plus contre-intuitif : une
carte enregistrée ne sert à rien ici.

Créditer : <https://manager.infomaniak.com/v3/invoicing/payment-methods>,
bouton « Créditer le compte ».

Aucun endpoint public ne donne ce solde — `/1/invoicing/{compte}/payment/prepay`
répond `method_not_yet_implemented`. En revanche l'**historique** se lit :

```
GET /1/invoicing/{compte}/payment/prepay/history?per_page=500
```

Le solde s'en déduit par somme. **Attention, sa pagination est cassée** :
`pages` ment, et le paramètre `page` est ignoré quand `per_page` est grand —
la même page revient indéfiniment. Dédoublonnez par `id`, et ne rendez un solde
que si le nombre d'entrées distinctes égale le `total` annoncé. Un solde faux
est pire qu'un solde absent : on décide dessus.

---

## Obstacle 3 — les contacts

`contact_id_missing` : *« The id of the contact 'owner' is required on
registration »*.

```
GET /2/domains/accounts/{compte}/contacts
```

Prenez l'identifiant d'un contact **validé** (`is_validated: true`). Le plus sûr
est de regarder ce qu'un domaine existant du compte emploie déjà :

```
GET /2/domains/domains/<un-domaine-existant>
```

et de reprendre le même — il rend `contacts: {owner, admin, tech, billing}`.
Éviter de choisir au hasard : c'est le titulaire légal du domaine.

---

## Obstacle 4 — les champs additionnels du TLD

`invalid_additional_field` : *« There was an error validating the additional
fields »* — sans dire lesquels.

Ils se lisent ici, et la valeur du paramètre `with` n'est **pas** documentée :

```
GET /2/tld/{tld}?with=fields
```

Si vous cherchez cette valeur, envoyez n'importe quoi : le 422 vous rend la
liste des valeurs acceptées dans `error.errors[].context.values` —
`length, periods, groups, transfer_method, fields, is_idn, idn, support, delays`.
C'est le réflexe qui fait gagner le plus de temps sur cette API : **lire le
corps complet des erreurs de validation**, qui nomme l'attribut fautif et
souvent les valeurs possibles.

Pour **`.app`**, un seul champ est requis à l'enregistrement :

| champ | type | valeur |
|---|---|---|
| `x-accept-ssl-requirement` | case à cocher, motif `^1$` | `"1"` |

C'est la reconnaissance que `.app` impose HTTPS. Ce qui est vrai et vous
concernera ensuite : **le TLD `.app` est préchargé HSTS**, donc aucun repli en
clair et **aucun avertissement cliquable** si le certificat manque. Émettez le
certificat *avant* d'ouvrir la page dans un navigateur.

---

## Obstacle 5 — la cadence propre à l'endpoint

`Too many request`, en 429, **après trois ou quatre tentatives seulement**.

L'endpoint de commande a sa propre limite, bien plus serrée que le plafond
général de 60 requêtes par minute. Ne martelez pas : espacez de plusieurs
minutes.

Et surtout : **ne rejouez jamais une commande dont l'issue est inconnue.** Un
429 ou un délai dépassé ne prouvent pas que la requête n'a pas abouti. Avant de
retenter, constatez l'état réel :

```python
noms = [d["customer_name"] for d in ik.appel("/2/domains/domains",
                                             params={"account_id": compte})]
"exemple.app" in noms          # déjà commandé ?
ik.outil_disponibilite({"domain": "exemple.app"})["libre"]
```

---

## Obstacle 6 — le montant doit correspondre exactement

`invalid_expected_amount`. C'est une **fonctionnalité**, pas une gêne : l'API
refuse si le montant annoncé ne correspond pas au prix qu'elle calcule. C'est ce
qui empêche d'acheter un nom à un prix qu'on n'a pas vu.

Lisez-le juste avant, et prenez le bon :

```python
r = ik.outil_disponibilite({"domain": "exemple.app"})
r["libre"]                 # is_available
r["premiere_periode_ht"]   # ← CELUI-CI : le prix de la première période
r["renouvellement_ht"]     # le coût annuel ensuite, souvent bien plus élevé
```

Le prix d'appel et le prix de renouvellement diffèrent presque toujours —
`kiosquier.app` : 14,50 € puis 19,60 €/an. Le pluriannuel ne fait généralement
rien gagner.

---

## L'appel qui passe

Avec le MCP <https://github.com/amogado/infomaniak-domains-mcp> :

```python
ik.outil_commande_domaine({
    "domain": "exemple.app",
    "confirmation": "exemple.app",          # doit répéter le domaine, à l'identique
    "amount_total_excl_tax": 14.5,          # lu avec disponibilite, jamais deviné
    "registration_period": 1,
    "contacts": {"owner": 642793, "admin": 642793,
                 "tech": 642793, "billing": 642793},
    "additional_fields": {"x-accept-ssl-requirement": "1"},   # propre à .app
})
```

Environnement, côté serveur MCP :

```
INFOMANIAK_TOKEN_CMD='security find-generic-password -w -s infomaniak-api'
INFOMANIAK_ACCOUNT=607373        # le compte est ÉPINGLÉ : le serveur refuse tout autre
INFOMANIAK_ACHAT=1               # armement propre, distinct de INFOMANIAK_WRITE
INFOMANIAK_ACHAT_MAX=50          # plafond en € HT, appliqué au TOTAL période comprise
```

Les quatre barrières du MCP, à connaître pour ne pas s'y cogner : l'armement
d'achat est **distinct** de celui d'écriture DNS ; le plafond porte sur le total
et non sur le prix unitaire ; le montant est **obligatoire et jamais deviné** ;
et `confirmation` doit répéter le domaine exactement.

En cas de coupure réseau, l'outil rend **« issue indéterminée, ne pas rejouer »**
plutôt qu'une erreur ordinaire — allez vérifier dans le manager avant toute
nouvelle tentative.

---

## Après la commande

```python
# la zone existe déjà, avec les serveurs de noms Infomaniak et DNSSEC actif
ik.outil_zones({"domain": "exemple.app"})

# pointer le A (demande INFOMANIAK_WRITE=1)
ik.outil_ajoute_enregistrement({"zone": "exemple.app", "type": "A",
                                "source": ".", "target": "<votre IP>", "ttl": 3600})
```

`source: "."` désigne la racine — c'est la convention qu'emploient les
enregistrements que l'API crée elle-même.

Enfin : **écrit dans la zone ≠ servi au réseau**. Vérifiez la propagation
plutôt que de la supposer :

```bash
dig +short A exemple.app @1.1.1.1
dig +short A exemple.app @8.8.8.8
```

---

## Le résumé, si vous ne lisez qu'un paragraphe

Créez un jeton portant les **huit** portées. Créditez le **compte prépayé** —
la carte ne sert à rien. Reprenez les **contacts** d'un domaine existant.
Ajoutez `x-accept-ssl-requirement: "1"` pour un `.app`. Lisez le prix de
**première période** et reportez-le tel quel. Et espacez les tentatives : cet
endpoint a sa propre cadence, et une commande dont l'issue est inconnue ne se
rejoue jamais — on va d'abord regarder si elle est passée.
