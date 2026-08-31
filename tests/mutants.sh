#!/usr/bin/env bash
# Abîme délibérément le code, une fois par mutant, et exige que la suite vire au
# rouge. Un mutant qui survit nomme un trou dans les tests.
#
# TROIS fichiers sont mutés, et c'est le second audit qui l'a imposé : le
# harnais ne visait qu'`infomaniak_mcp.py`, si bien que `serveur.py` — le
# serveur d'autorisation, exposé sur Internet, celui dont une faille coûte des
# domaines — n'était éprouvé par AUCUN mutant. Les tests qui le couvrent
# existaient ; rien ne disait qu'ils mordaient.
#
# ⚠️ La restauration se fait depuis une COPIE prise au démarrage, plus depuis
# `git checkout`. La raison est celle-là même qui interdisait de lancer ce
# script sur du travail non commité : restaurer depuis l'index efface le
# correctif au lieu du mutant. Une copie, elle, rend exactement ce qui était là
# — commité ou non. Le garde qui refusait de démarrer disparaît donc avec sa
# cause.
#
# ⚠️ Un SIGKILL court-circuite quand même le trap : le mutant resterait appliqué.
# C'est arrivé le 2026-08-30. La copie est laissée sur le disque et son chemin
# est affiché au démarrage — c'est de là qu'on restaure, à la main, si une
# exécution est tuée de force. N'y recourir qu'après un SIGTERM resté sans effet.
#
# ⚠️ Ce script ÉCRIT dans les fichiers du dépôt. Deux agents qui travaillent en
# parallèle sur les mêmes fichiers se marcheraient dessus : avant chaque
# mutation, on vérifie que la cible est bien celle qu'on a copiée. Si elle a
# changé sous nos pieds, on s'arrête SANS restaurer — le travail de l'autre
# vaut mieux que notre copie périmée.
set -uo pipefail
cd "$(dirname "$0")/.."

# Les fichiers que ce harnais a le droit d'abîmer. `CIBLE` désigne celui que
# les mutants suivants visent ; il change en cours de route.
CIBLES=(infomaniak_mcp.py serveur.py tests/run.sh)
CIBLE=infomaniak_mcp.py

# `./tests/mutants.sh serveur.py` ne mute que ce fichier-là. Sans argument, on
# les mute tous — c'est le seul mode qui rend un verdict sur le dépôt. Le
# filtre sert à itérer sur un fichier, et à ne pas écrire dans celui qu'un
# autre agent tient en main.
FILTRE="${1:-}"

# La sonde de frontière interroge un hôte distant. Ici on la coupe : ce harnais
# mesure si les tests LOCAUX mordent, et la réponse d'une production qu'aucun
# mutant ne touche n'est pas ce signal-là. Même raison qu'`INFOMANIAK_RATE`
# dans run.sh — deux signaux distincts ne doivent pas se confondre.
export INFOMANIAK_FRONTIERE=-

SAUVE="$(mktemp -d -t mutants-sauvegarde)"
for f in "${CIBLES[@]}"; do
  mkdir -p "$SAUVE/$(dirname "$f")"
  cp -p "$f" "$SAUVE/$f" || { echo "REFUS : $f est illisible."; exit 2; }
done
echo "sauvegarde des cibles : $SAUVE"

restaure() {
  local f
  for f in "${CIBLES[@]}"; do
    cp -p "$SAUVE/$f" "$f" 2>/dev/null
  done
}

# La copie ne survit qu'aux sorties qui court-circuitent le trap — c'est-à-dire
# au SIGKILL, le seul cas où elle sert. Une sortie ordinaire, même interrompue,
# a déjà restauré : garder la copie n'apporterait qu'un répertoire de plus dans
# /tmp, et un répertoire de plus à chaque exécution.
sortir() { restaure; rm -rf "$SAUVE"; }
trap sortir EXIT INT TERM

# Personne d'autre n'a-t-il écrit dans la cible pendant qu'on tournait ?
intacte() {
  cmp -s "$SAUVE/$1" "$1"
}

survivants=0
teste=0

# mutant <nom> <avant> <apres> [occurrence]
# Sans occurrence, le motif doit être unique — un motif ambigu est une erreur,
# pas une invitation à muter au hasard. Avec, on vise la Nième, ce qui sert
# quand la même garde existe dans deux fonctions.
mutant() {
  local nom="$1" avant="$2" apres="$3" rang="${4:-0}"
  if [ -n "$FILTRE" ] && [ "$CIBLE" != "$FILTRE" ]; then
    return
  fi
  teste=$(( teste + 1 ))
  # AVANT de restaurer, sinon la vérification porterait sur la copie qu'on
  # vient d'écrire et ne dirait plus rien. Le mutant précédent a restauré en
  # sortant : à cet instant, la cible DOIT être identique à la sauvegarde.
  if ! intacte "$CIBLE"; then
    echo
    echo "ARRÊT : $CIBLE a changé depuis le démarrage, et pas par nous."
    echo "Quelqu'un d'autre y écrit. On ne restaure pas : sa version reste."
    echo "Notre copie de départ, si jamais : $SAUVE"
    trap - EXIT INT TERM
    exit 3
  fi
  restaure
  python3 - "$CIBLE" "$avant" "$apres" "$rang" <<'PY' || { echo "  ?? $nom : motif introuvable"; survivants=$(( survivants + 1 )); return; }
import sys, pathlib
fichier, avant, apres, rang = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
p = pathlib.Path(fichier); s = p.read_text(encoding="utf-8")
combien = s.count(avant)
if combien == 0:
    sys.exit("le motif est absent")
if rang == 0:
    if combien != 1:
        sys.exit("le motif apparait %d fois : preciser l'occurrence" % combien)
    p.write_text(s.replace(avant, apres), encoding="utf-8")
    raise SystemExit(0)
if rang > combien:
    sys.exit("occurrence %d demandee, %d presente(s)" % (rang, combien))
# on coupe juste avant la Nième occurrence, on remplace la première d'après
pos = -1
for _ in range(rang):
    pos = s.index(avant, pos + 1)
p.write_text(s[:pos] + apres + s[pos + len(avant):], encoding="utf-8")
PY
  # macOS n'a pas `timeout`. Une limite est indispensable : un mutant peut
  # faire boucler ou dormir la suite, et l'attente serait alors confondue avec
  # une survie.
  python3 - <<'LIMITE' >/dev/null 2>&1
import subprocess, sys
try:
    r = subprocess.run(["./tests/run.sh"], capture_output=True, timeout=120)
    sys.exit(r.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
LIMITE
  issue=$?
  if [ "$issue" -eq 0 ]; then
    echo "  SURVIT  $nom"
    survivants=$(( survivants + 1 ))
  elif [ "$issue" -eq 124 ]; then
    echo "  tue     $nom  (par blocage : la suite ne rend plus la main)"
  else
    echo "  tue     $nom"
  fi
  restaure
}

echo "mutants :"

mutant "le garde-fou d'écriture ne garde plus rien" \
  '    if not ecriture_armee():' \
  '    if False:'

mutant "n'importe quelle valeur arme l'écriture" \
  'return os.environ.get("INFOMANIAK_WRITE", "").strip() in ("1", "oui", "yes", "true")' \
  'return bool(os.environ.get("INFOMANIAK_WRITE", "").strip())'

mutant "la borne haute du ttl disparaît" \
  '    if not 60 <= ttl <= 86400:' \
  '    if not 60 <= ttl:'

mutant "la borne basse du ttl disparaît" \
  '    if not 60 <= ttl <= 86400:' \
  '    if not ttl <= 86400:'

mutant "le filtre de source devient une sous-chaîne" \
  'liste = [r for r in liste if str(r.get("source", "")) == source_voulue]' \
  'liste = [r for r in liste if source_voulue in str(r.get("source", ""))]'

mutant "le filtre de type devient sensible à la casse" \
  'type_voulu = (args.get("type") or "").strip().upper()' \
  'type_voulu = (args.get("type") or "").strip()'

mutant "un seul serveur de noms suffit" \
  '    if len(serveurs) < 2:' \
  '    if len(serveurs) < 1:'

mutant "l'enveloppe d'erreur est ignorée quand le code HTTP est bon" \
  '    if enveloppe.get("result") != "success" or code >= 400:' \
  '    if code >= 400:'

mutant "le compte est re-résolu à chaque appel" \
  $'    if _COMPTE["valeur"]:\n        return _COMPTE["valeur"]' \
  $'    if False:\n        return _COMPTE["valeur"]'

mutant "l'epinglage n'est plus employe comme compte" \
  $'        return epingle\n    if donne:' \
  $'        pass\n    if donne:'

mutant "l'absence de jeton n'arrête plus rien" \
  $'    if not cle:\n        raise ErreurInfomaniak(' \
  $'    if False:\n        raise ErreurInfomaniak('

mutant "la cadence laisse passer la requête de trop" \
  '            if len(self.appels) >= self.plafond:' \
  '            if len(self.appels) > self.plafond:'

mutant "la fenêtre de cadence cesse de glisser" \
  $'            self.appels = [a for a in self.appels if t - a < self.fenetre]\n            if len' \
  $'            self.appels = list(self.appels)\n            if len'

mutant "le nom n'est plus normalise (disponibilite)" \
  'nom = (args.get("domain") or "").strip().lower()' \
  'nom = args.get("domain") or ""' 1

mutant "le nom n'est plus normalise (commande)" \
  'nom = (args.get("domain") or "").strip().lower()' \
  'nom = args.get("domain") or ""' 2

mutant "un nom sans extension part sur le reseau (disponibilite)" \
  '    if "." not in nom:' \
  '    if False:' 1

mutant "un nom sans extension part sur le reseau (commande)" \
  '    if "." not in nom:' \
  '    if False:' 2

mutant "la description des enregistrements n'est plus demandée" \
  'params = {"with": "records_description", "per_page"' \
  'params = {"per_page"'

mutant "un 401 devient un message générique" \
  '        if code == 401:' \
  '        if False:'

mutant "le type n'est plus mis en capitales à la création" \
  '    type_ = (args.get("type") or "").strip().upper()' \
  '    type_ = (args.get("type") or "").strip()'

mutant "une modification vide part quand même" \
  $'    if not corps:\n        raise ErreurInfomaniak("rien à modifier' \
  $'    if False:\n        raise ErreurInfomaniak("rien à modifier'

mutant "les handlers fuitent dans tools/list" \
  '{k: v for k, v in t.items() if k != "handler"}' \
  'dict(t)'

# --- les barrières de la commande ------------------------------------------
# Ce sont celles qui coûtent de l'argent quand elles cèdent. Chacune doit
# mourir seule : un mutant qui survit ici est une dépense qui passe.

mutant "l'armement de dépense ne garde plus rien" \
  '    if not achat_arme():' \
  '    if False:'

mutant "INFOMANIAK_WRITE arme aussi la dépense" \
  'return os.environ.get("INFOMANIAK_ACHAT", "").strip() in ("1", "oui", "yes", "true")' \
  'return ecriture_armee() or os.environ.get("INFOMANIAK_ACHAT", "").strip() == "1"'

mutant "le plafond ignore la période" \
  '    total = montant * periode' \
  '    total = montant'

mutant "le plafond laisse passer l'égalité stricte en trop" \
  '    if total > plafond:' \
  '    if total > plafond * 2:'

mutant "un plafond illisible retombe sur le défaut au lieu de refuser" \
  $'    except ValueError:\n        raise ErreurInfomaniak(\n            "INFOMANIAK_ACHAT_MAX vaut %r' \
  $'    except ValueError:\n        return ACHAT_MAX_DEFAUT\n    if False:\n        raise ErreurInfomaniak(\n            "INFOMANIAK_ACHAT_MAX vaut %r'

mutant "un plafond nul autorise tout" \
  '    if valeur <= 0:' \
  '    if False:'

mutant "la confirmation n'est plus comparée au domaine" \
  '    if confirmation != nom:' \
  '    if False:'

mutant "la confirmation accepte une sous-chaîne" \
  '    if confirmation != nom:' \
  '    if confirmation not in nom:'

mutant "le montant devient facultatif" \
  '    if args.get("amount_total_excl_tax") in (None, ""):' \
  '    if False:'

mutant "un montant nul est accepté" \
  '    if montant <= 0:' \
  '    if montant < 0:'

mutant "la période haute n'est plus bornée" \
  '    if not 1 <= periode <= PERIODE_MAX:' \
  '    if not 1 <= periode:'

mutant "une coupure réseau n'avertit plus du rejeu" \
  '        if "injoignable" in str(err):' \
  '        if False:'

mutant "toute erreur devient une issue indéterminée" \
  '        if "injoignable" in str(err):' \
  '        if True:'

# --- la frontiere du compte epingle -----------------------------------------
# Celles-ci protegent le compte d'autrui. Un survivant ici, c'est la zone DNS
# d'un client qu'on peut atteindre.

mutant "l'argument account franchit l'epinglage" \
  '        if donne and str(donne).strip() != epingle:' \
  '        if False:'

mutant "l'appartenance ne verifie plus rien" \
  $'    if not epingle:\n        return\n    nom = (cible' \
  $'    if True:\n        return\n    nom = (cible'

mutant "l'appartenance se contente d'un suffixe de chaine" \
  '        if propre and (nom == propre or nom.endswith("." + propre)):' \
  '        if propre and nom.endswith(propre):'

mutant "l'appartenance accepte tout ce qui contient le nom" \
  '        if propre and (nom == propre or nom.endswith("." + propre)):' \
  '        if propre and propre in nom:'

mutant "la liste des domaines n'est plus bornee au compte" \
  $'        "account_id": compte_par_defaut(args.get("account")) if (\n            args.get("account") or compte_epingle()) else None,' \
  $'        "account_id": args.get("account"),'

mutant "l'epinglage ne normalise plus les espaces" \
  '    return os.environ.get("INFOMANIAK_ACCOUNT", "").strip() or None' \
  '    return os.environ.get("INFOMANIAK_ACCOUNT", "") or None'

mutant "la liste d'appartenance n'est jamais retenue" \
  '    if epingle in _DOMAINES_DU_COMPTE:' \
  '    if False:'

mutant "une commande ne perime plus la liste d'appartenance" \
  '    _DOMAINES_DU_COMPTE.pop(str(compte), None)' \
  '    pass'

# La cloison lecture/écriture du connecteur se déduit d'une MARQUE en tête de
# description : `portee_outil()`, dans serveur.py, ne voit rien d'autre. La
# renommer ici ferait basculer tous les outils du côté lecture, en silence, et
# un jeton de lecture pourrait alors demander une écriture. C'est la dette D11 ;
# `check_durcissement.py` la garde en exigeant les deux ensembles nommés.

mutant "la marque d'ecriture est renommee dans les descriptions" \
  'marque = "[DÉPENSE] " if depense else ("[écrit] " if ecrit else "")' \
  'marque = "[depense] " if depense else ("[ecrit] " if ecrit else "")'

mutant "un outil d'ecriture n'est plus declare comme tel" \
  'outil_serveurs_de_noms, ecrit=True' \
  'outil_serveurs_de_noms'

# --- la source de vérité se défend elle-même --------------------------------
# `serveur.py` se garde des params malformés de son côté. Ça ne dit rien de
# `handle()`, qui est aussi appelé sur stdio, où personne ne le protège.

mutant "handle() reprend son 'or {}' sur params" \
  $'    params = message.get("params")\n    params = params if isinstance(params, dict) else {}' \
  $'    params = message.get("params") or {}\n    params = params'

mutant "un nom d'outil non hachable retourne dans la table" \
  '        outil = BY_NAME.get(nom) if isinstance(nom, str) else None' \
  '        outil = BY_NAME.get(nom)'

# ===========================================================================
# serveur.py — le serveur d'autorisation, exposé sur Internet
# ===========================================================================
# Aucun mutant ne le visait jusqu'ici. Ses tests existaient, et rien ne disait
# qu'ils mordaient : c'est exactement la situation qui a laissé passer six
# failles au premier audit.

CIBLE=serveur.py

# --- le cadrage HTTP : ce qui décide où commence la requête suivante ---------

mutant "Transfer-Encoding n'est plus refusé (désynchronisation CL.TE)" \
  '        if self.headers.get_all("Transfer-Encoding"):' \
  '        if False:'

mutant "deux Content-Length contradictoires passent" \
  '        if len(longueurs) > 1:' \
  '        if False:'

mutant "un Content-Length qui n'est pas un nombre d'octets passe" \
  '        if longueurs and not re.fullmatch(r"[0-9]{1,15}", longueurs.pop()):' \
  '        if False:'

# --- la coupure doit être ANNONCÉE, pas seulement décidée -------------------

mutant "la coupure n'est plus annoncée du tout" \
  '        coupe = self.close_connection or self._corps_en_suspens()' \
  '        coupe = False'

mutant "le témoin de corps lu n'est pas remis à zéro entre deux requêtes" \
  $'        self._debut_requete = time.monotonic()\n        self._corps_consomme = False' \
  $'        self._debut_requete = time.monotonic()'

mutant "un corps annoncé et non lu ne fait plus annoncer la coupure" \
  '        coupe = self.close_connection or self._corps_en_suspens()' \
  '        coupe = self.close_connection'

# --- le slowloris : un budget de durée, pas un délai par recv ---------------

mutant "le budget de lecture du corps devient une heure" \
  '        echeance = getattr(self, "_debut_requete", time.monotonic()) + DELAI_CORPS' \
  '        echeance = getattr(self, "_debut_requete", time.monotonic()) + 3600'

mutant "le budget se réarme à chaque tranche (redevient un délai par recv)" \
  '                reste = echeance - time.monotonic()' \
  '                reste = DELAI_CORPS'

mutant "le budget n'est plus borné, donc un réglage de zéro refuse tout corps" \
  '    return min(60.0, max(1.0, voulu))' \
  '    return voulu'

# --- l'état ne doit plus enfler sans borne ----------------------------------

mutant "la pierre tombale du rafraîchissement revit quatre-vingt-dix jours" \
  '            entree["exp"] = min(peremption(entree, tombe), tombe)' \
  '            entree["exp"] = peremption(entree, tombe)'

mutant "révoquer ne pose plus de péremption sur l'autorisation" \
  '        grant["exp"] = min(peremption(grant, fin), fin)' \
  '        grant["exp"] = peremption(grant, fin)'

mutant "les autorisations périmées ne sont plus retirées" \
  $'        if fin > now:\n            grants[gid] = grant' \
  $'        if True:\n            grants[gid] = grant'

mutant "un état sans péremption est jeté au lieu d'être réparé" \
  '        if not fin:' \
  '        if False:'

# --- une lecture n'est pas une écriture -------------------------------------

mutant "l'horodatage d'activité est réécrit à chaque requête" \
  '                if maintenant - dernier >= ACTIVITE_PAS:' \
  '                if True:'

mutant "l'état est persisté même quand rien n'a changé" \
  $'            if change:\n                oauth_save(data)\n        return set(' \
  $'            if True:\n                oauth_save(data)\n        return set('

# --- la page d'accueil et le jeton de révocation de Vincent -----------------

mutant "la page d'accueil perd son contrôle de navigation" \
  $'        refus = self._exige_navigation()\n        if refus is not None:\n            return refus\n        csrf = jeton()' \
  $'        csrf = jeton()'

mutant "/authorize perd son contrôle de navigation" \
  $'        refus = self._exige_navigation()\n        if refus is not None:\n            return refus\n\n        q = self._query_stricte()' \
  $'        q = self._query_stricte()'

mutant "le contrôle de navigation ne regarde plus la destination" \
  '        if (dest and dest != "document") or (mode and mode != "navigate"):' \
  '        if False:'

# --- une seule prise de verrou ---------------------------------------------

mutant "l'échange du code prend le verrou en deux fois" \
  $'        with _oauth_lock:\n            data, retire = oauth_frais()\n            entree = data["codes"].get(empreinte(code))' \
  $'        with _oauth_lock:\n            data, retire = oauth_frais()\n        with _oauth_lock:\n            entree = data["codes"].get(empreinte(code))'

# --- /consent ne lit rien de son corps --------------------------------------

mutant "/consent relit le code_challenge depuis le formulaire" \
  '                "code_challenge": demande["code_challenge"], "scope": demande["scope"],' \
  '                "code_challenge": form.get("code_challenge") or demande["code_challenge"], "scope": demande["scope"],'

mutant "/consent relit l'adresse de retour depuis le formulaire" \
  '            reponse = demande["redirect_uri"] + joint + urlencode(champs)' \
  '            reponse = (form.get("redirect_uri") or demande["redirect_uri"]) + joint + urlencode(champs)'

mutant "/consent relit la portée depuis le formulaire" \
  '                "code_challenge": demande["code_challenge"], "scope": demande["scope"],' \
  '                "code_challenge": demande["code_challenge"], "scope": form.get("scope") or demande["scope"],'

# --- un code non persisté ne doit pas être émis -----------------------------

mutant "/consent émet un code que le volume n'a pas gardé" \
  $'            durable = oauth_save(data)\n            if durable:' \
  $'            durable = oauth_save(data) or True\n            if durable:'

mutant "/token délivre une paire que le volume n'a pas gardée" \
  $'        if not durable:\n            return self._json(500, {"error": "server_error"})\n        return self._json(200, {"access_token": acces, "token_type": "Bearer",\n                                "expires_in": ACCESS_TTL, "refresh_token": rafraichir,' \
  $'        if False:\n            return self._json(500, {"error": "server_error"})\n        return self._json(200, {"access_token": acces, "token_type": "Bearer",\n                                "expires_in": ACCESS_TTL, "refresh_token": rafraichir,'

mutant "/authorize affiche une demande qu'il n'a pas enregistrée" \
  $'            durable = oauth_save(data)\n        if not durable:\n            return self._send(500, page_refus(' \
  $'            durable = oauth_save(data) or True\n        if not durable:\n            return self._send(500, page_refus('

# --- les péremptions ---------------------------------------------------------

mutant "un code d'autorisation vit un an" \
  'CODE_TTL = 300' \
  'CODE_TTL = 31536000'

mutant "les codes échappent au ménage" \
  '    for cle in ("pending", "codes", "access", "refresh"):' \
  '    for cle in ("pending", "access", "refresh"):'

# --- l'audience : le contrôle qui était une tautologie ----------------------

mutant "l'audience du jeton est reconstruite depuis la configuration" \
  '            "grant_id": grant_id, "scope": scope, "aud": aud,' \
  '            "grant_id": grant_id, "scope": scope, "aud": MCP_URL,'

mutant "l'audience du code n'est plus lue dans l'autorisation" \
  '                entree.get("resource") or MCP_URL)' \
  '                MCP_URL)'

mutant "la rotation ne transporte plus l'audience" \
  '                                        entree.get("aud") or MCP_URL,' \
  '                                        MCP_URL,'

mutant "le contrôle d'audience disparaît" \
  '            if entree.get("aud") != MCP_URL:' \
  '            if False:'

# --- la page de configuration ------------------------------------------------
#
# Éprouvés contre `tests/check_config.py`, qui a été écrit contre la SPEC et
# non contre ce code — les deux ont été rédigés en parallèle, exprès. Ces
# mutants disent la seule chose qu'un test ne peut pas dire de lui-même : qu'il
# mord. Les dix-huit ont été vus tuer, un par un.
#
# Ce qu'ils NE disent pas, et qu'il faut avoir en tête : ils prouvent que les
# gardes ÉCRITES sont tenues, jamais que rien ne manque. C'est la leçon
# d'`INFOMANIAK_ACCOUNT`, éprouvé par 43 mutants dont aucun ne survivait, et
# qui avait deux trous.

# la frontière humaine, élargie à l'identité que pose oauth2-proxy
mutant "le canari n'accepte plus l'identité transmise par oauth2-proxy" \
  $'        if self._identite():\n            return True' \
  $'        if False:\n            return True'

mutant "un en-tête d'identité présent mais VIDE vaut identité" \
  '        return "".join(c for c in recus[0].strip() if c.isprintable())[:200]' \
  '        return "".join(c for c in recus[0].strip() if c.isprintable())[:200] or "personne"'

mutant "/config s'ouvre sans identité humaine" \
  $'        if not self._humain_present():\n            return self._defi_humain()\n        # Le même contrôle que /authorize' \
  $'        # Le même contrôle que /authorize'

mutant "la page de configuration perd son contrôle de navigation" \
  $'        refus = self._exige_navigation()\n        if refus is not None:\n            return refus\n        q = self._query_stricte() or {}' \
  $'        q = self._query_stricte() or {}'

# le jeton anti-CSRF — exigé, et à usage unique
mutant "le jeton anti-CSRF de /config n'est plus exigé" \
  $'        if not self._config_jeton_csrf(form):\n            return self._config_perime()' \
  $'        if False:\n            return self._config_perime()' \
  1

mutant "le jeton anti-CSRF de /config resservirait indéfiniment" \
  $'            return memoire_consommer(\n                _csrf_config, empreinte(form.get("csrf", ""))) is not None' \
  $'            return memoire_lire(\n                _csrf_config, empreinte(form.get("csrf", ""))) is not None'

# le fichier : son mode, et son autorité sur l'environnement
mutant "le fichier de réglages devient lisible par tous" \
  '            os.fchmod(fd, 0o600)' \
  '            os.fchmod(fd, 0o644)'

mutant "le fichier ne fait plus autorité : l'environnement reprend la main" \
  $'    return ({nom: data[nom] for nom in NOMS_REGLAGES\n             if nom in data and data[nom] is not None}, "lu")' \
  '    return {}, "absent"'

mutant "une variable d'amorçage ne sert plus de départ" \
  '    return _AMORCE["ecriture_armee"]()' \
  '    return False'

# le secret : jamais rendu, jamais effacé par mégarde
mutant "la page rend le secret en entier" \
  '            % (len(valeur), valeur[-4:], empreinte(valeur)[:12]))' \
  '            % (len(valeur), valeur, empreinte(valeur)[:12]))'

mutant "un envoi vide efface le jeton" \
  $'        propose = (form.get("jeton") or "").strip()\n        if propose:' \
  $'        propose = (form.get("jeton") or "").strip()\n        if True:'

mutant "/_whoami rend le jeton d'API" \
  '            "marque_proxy": bool(MARQUE_PROXY),' \
  '            "marque_proxy": bool(MARQUE_PROXY), "jeton": infomaniak_mcp.jeton(),'

mutant "/_whoami annonce l'armement d'AMORÇAGE, pas l'effectif" \
  '            "ecriture_armee": infomaniak_mcp.ecriture_armee(),' \
  '            "ecriture_armee": _AMORCE["ecriture_armee"](),'

# le journal : borné, nominatif, et muet sur les valeurs
mutant "le journal garde cent mille entrées" \
  'JOURNAL_MAX = 128          #' \
  'JOURNAL_MAX = 100000       #'

mutant "le journal n'inscrit plus qui a fait le changement" \
  '            journalise = journal_ajouter(self._qui(), sorted(change)) if durable else False' \
  '            journalise = journal_ajouter("", sorted(change)) if durable else False'

mutant "le journal inscrit la VALEUR du réglage au lieu de l'identité" \
  '            journalise = journal_ajouter(self._qui(), sorted(change)) if durable else False' \
  '            journalise = journal_ajouter(str(change), sorted(change)) if durable else False'

# le plafond de dépense : illisible ⇒ refus, jamais le défaut
#
# Le premier de ces trois mutants remet la faille que `check_config.py` a
# trouvée en naissant : `float("1e400")` rend l'infini, `float("nan")` rend
# nan, et `<= 0` est faux pour les deux. Un plafond qui n'est pas un montant
# autorisait donc n'importe quel montant.
mutant "un plafond infini ou « nan » repasse pour un montant" \
  '    if not math.isfinite(nombre):' \
  '    if False:'

mutant "un plafond nul ou négatif est accepté" \
  '    if nombre <= 0:' \
  '    if False:'

mutant "un plafond illisible retombe sur le défaut au lieu de refuser" \
  $'    except ValueError:\n        raise ErreurInfomaniak(\n            "le plafond de dépense vaut %r, qui n\'est pas un nombre. Aucune "' \
  $'    except ValueError:\n        return infomaniak_mcp.ACHAT_MAX_DEFAUT\n        raise ErreurInfomaniak(\n            "le plafond de dépense vaut %r, qui n\'est pas un nombre. Aucune "'

# ===========================================================================
# tests/run.sh — le lanceur lui-même
# ===========================================================================
# `check_frontiere.sh` a existé des semaines sans que personne ne le lance. Un
# test qu'on ne lance pas n'est pas un test, c'est un fichier — et rien, dans
# la suite, ne s'en apercevait.

CIBLE=tests/run.sh

mutant "run.sh cesse de lancer la sonde de frontière" \
  '  sortie=$(./tests/check_frontiere.sh "$HOTE_FRONTIERE" 2>&1); verdict=$?' \
  '  sortie="(sonde desactivee)"; verdict=0'

echo
if [ -n "$FILTRE" ]; then
  echo "$teste mutants sur $FILTRE seulement, $survivants survivant(s)"
  echo "(verdict PARTIEL : sans argument, le harnais mute les trois cibles)"
else
  echo "$teste mutants, $survivants survivant(s)"
fi
[ "$survivants" -eq 0 ]
