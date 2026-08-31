# Enregistrer un `.app` — le champ additionnel

Vérifié en direct contre l'API le 2026-09-01.

Si vous butez sur ce refus :

```json
{"result": "error", "error": {"code": "invalid_additional_field",
 "description": "There was an error validating the additional fields"}}
```

...il manque **un seul champ**, et le message ne dit pas lequel. Le voici.

---

## Le champ, et sa valeur

| | |
|---|---|
| nom | `x-accept-ssl-requirement` |
| type | case à cocher |
| requis | **oui** |
| motif accepté | `^1$` — donc la chaîne `"1"`, rien d'autre |

C'est la reconnaissance que `.app` impose HTTPS : *« L'extension .APP requiert
l'activation du HTTPS pour être utilisée avec un site Web. »*

Le TLD expose aussi un champ de type `info` portant ce texte, au nom
illisible (`6a9600f69f30f4.48581568`). Il n'est **pas requis** : c'est le
paragraphe à afficher, pas une donnée à envoyer. Ne cherchez pas à le remplir.

---

## Le piège qui coûte le plus de temps

**La spec OpenAPI déclare `additional_fields` comme un tableau de chaînes.**

```json
"additional_fields": {"type": "array", "items": {"type": "string"}}
```

**Ce qui passe réellement est un objet nom → valeur** :

```json
"additional_fields": {"x-accept-ssl-requirement": "1"}
```

Envoyer un tableau — `["x-accept-ssl-requirement=1"]`, `["1"]`, ou toute autre
variante — laisse le champ requis non renseigné, et l'API redit
`invalid_additional_field` sans plus d'explication. C'est le genre de
contradiction sur laquelle on tourne longtemps, parce que la documentation est
formellement fausse et qu'on la croit.

---

## Comment on retrouve ça soi-même

```
GET /2/tld/app?with=fields
```

La réponse porte `fields.registration` (ce qu'il faut à l'enregistrement),
`fields.contacts` et `fields.transfer`.

**La valeur `fields` n'est documentée nulle part.** Pour la trouver, envoyez
n'importe quoi : le 422 rend la liste des valeurs acceptées.

```bash
curl -s -H "Authorization: Bearer $JETON" \
     'https://api.infomaniak.com/2/tld/app?with=peu-importe' | python3 -m json.tool
```

```json
"errors": [{"code": "validation_rule_in",
  "context": {"attribute": "with.0",
    "values": ["length","periods","groups","transfer_method",
               "fields","is_idn","idn","support","delays"]}}]
```

**C'est le réflexe qui fait gagner le plus de temps sur cette API** : lire le
corps *complet* d'une erreur de validation. `error.errors[]` nomme l'attribut
fautif et, très souvent, les valeurs possibles. Le résumé de premier niveau
(`error.description`) ne dit presque rien.

---

## Les quatre contacts sont requis aussi

`.app` exige les **quatre** rôles — `owner`, `admin`, `tech`, `billing` — tous
marqués requis. En omettre un donne `contact_id_missing`, un refus distinct qui
apparaîtra juste après si vous corrigez seulement le champ SSL.

```
GET /2/domains/accounts/{compte}/contacts
```

Prenez un contact **validé** (`is_validated: true`). Le plus sûr est de
reprendre ceux d'un domaine existant du compte :

```
GET /2/domains/domains/<un-domaine-du-compte>     → contacts: {owner, admin, tech, billing}
```

---

## L'appel complet qui passe

```json
POST /2/domains/accounts/{compte}/create
{
  "domain": "exemple.app",
  "registration_period": 1,
  "amount_total_excl_tax": 14.5,
  "contacts": {"owner": 642793, "admin": 642793,
               "tech": 642793, "billing": 642793},
  "additional_fields": {"x-accept-ssl-requirement": "1"}
}
```

Avec le MCP <https://github.com/amogado/infomaniak-domains-mcp> :

```python
ik.outil_commande_domaine({
    "domain": "exemple.app",
    "confirmation": "exemple.app",     # doit répéter le domaine à l'identique
    "amount_total_excl_tax": 14.5,     # lu avec disponibilite, jamais deviné
    "registration_period": 1,
    "contacts": {"owner": 642793, "admin": 642793,
                 "tech": 642793, "billing": 642793},
    "additional_fields": {"x-accept-ssl-requirement": "1"},
})
```

Le montant se lit juste avant, et c'est **le prix de première période** :

```python
r = ik.outil_disponibilite({"domain": "exemple.app"})
r["premiere_periode_ht"]     # ← celui-ci
r["renouvellement_ht"]       # le coût annuel ensuite, souvent bien plus élevé
```

Un montant qui ne correspond pas donne `invalid_expected_amount` — et c'est une
protection, pas une gêne : elle empêche d'acheter à un prix qu'on n'a pas vu.

---

## Après l'enregistrement, une conséquence de `.app`

Le TLD `.app` est **préchargé HSTS**. Donc : aucun repli en HTTP, et surtout
**aucun avertissement cliquable** si le certificat manque ou n'est pas encore
émis — le navigateur rend une erreur dure, sans contournement possible.

L'ordre des gestes compte : posez le `A`, attendez que le certificat soit
**émis**, et seulement ensuite ouvrez la page. La validation ACME en HTTP-01
continue de fonctionner, elle est serveur-à-serveur.

---

## Si le refus suivant n'est pas celui-là

Les autres codes de cet endpoint, tous dans `error.code` :

| code | ce qu'il veut dire |
|---|---|
| `invalid_expected_amount` | le montant ne correspond pas au prix calculé |
| `contact_id_missing` / `invalid_contact_field` | un rôle de contact manque ou est invalide |
| `insufficient_funds_prepaid_balance` | **le crédit prépayé, jamais une carte** — voir la fiche générale |
| `invalid_tld_registration_period` | la durée n'est pas offerte pour ce TLD |
| `payment_profile_not_set` | aucun profil de paiement sur le compte |
| `too_many_request` | cet endpoint a sa **propre** cadence, très serrée — espacer, et ne jamais rejouer une commande dont l'issue est inconnue |

La marche complète, obstacle par obstacle, est dans
[commander-un-domaine.md](commander-un-domaine.md).
