#!/usr/bin/env python3
"""Le transport HTTP distant et le serveur d'autorisation OAuth 2.1.

Même serveur MCP, deuxième transport. `infomaniak_mcp.py` reste la **source de
vérité** des outils : ce fichier les importe et n'en définit aucun. Deux listes
divergeraient, et la divergence se verrait en production, pas en test.

Stdlib uniquement, comme le reste du dépôt : rien à installer dans le
conteneur, qui est une image Python nue sans réseau garanti au démarrage.

Configuration propre à ce transport :

    INFOMANIAK_PUBLIC_BASE   l'URL publique, sans slash final. **Toutes** les
                             URL absolues en sortent — jamais l'en-tête Host,
                             qu'un client forge à volonté et qui empoisonnerait
                             les documents de découverte.
    INFOMANIAK_LISTEN_PORT   le port d'écoute, 8080 par défaut. Nommé ainsi
                             parce que Kubernetes injecte des variables
                             `<SERVICE>_PORT` de la forme « tcp://ip:80 » : un
                             `INFOMANIAK_PORT` se ferait écraser par le
                             cluster, et le serveur écouterait ailleurs qu'où
                             on croit.
    INFOMANIAK_DATA          le répertoire d'état, /data par défaut. C'est un
                             volume : un code d'autorisation non persisté est
                             un code rejouable indéfiniment.
    INFOMANIAK_REDIRECTS     les adresses de retour acceptées, séparées par des
                             virgules. Égalité stricte, jamais de préfixe.
    INFOMANIAK_MARQUE_PROXY  le secret partagé avec Traefik, sans lequel aucune
                             page humaine ne s'ouvre. Le proxy le POSE et
                             ÉCRASE toute copie entrante ; c'est ce qui rend la
                             marque infalsifiable par l'appelant, là où un
                             `Authorization: Basic` ou un `X-Forwarded-User`
                             s'écrivent tout seuls. Absent, le serveur ne sert
                             les pages humaines qu'à la boucle locale : voir
                             `_humain_present()`.

La configuration de l'API (jeton, compte épinglé, armements) est celle de
`infomaniak_mcp` et n'est pas redite ici. Le jeton Infomaniak ne traverse
jamais ce transport : Claude reçoit un jeton d'accès **de ce serveur**, qui
n'ouvre que les outils, et le secret Infomaniak reste dans le conteneur.

Ce qu'on refuse, sans exception — chaque point vient de la couche éprouvée de
kiosquier, où il a son test :

  - un `code_verifier` absent : le contournement le plus fréquent des serveurs
    d'autorisation écrits à la main ;
  - un code rejoué : révoque **toute la famille** de jetons ;
  - un jeton de rafraîchissement déjà tourné : même conduite ;
  - un jeton présenté pour une autre ressource ;
  - une portée élargie au rafraîchissement ;
  - `GET /authorize` qui émettrait un code : il rend un formulaire, rien d'autre.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlparse

# La source de vérité des outils. On importe, on ne recopie pas : `handle()`
# est réutilisé tel quel pour initialize, ping, tools/list et tools/call, si
# bien que les deux transports rendent le même JSON par construction — c'est ce
# que `tests/check_transports.py` vérifie, et il n'aurait rien à vérifier si ce
# fichier avait sa propre table.
import infomaniak_mcp
from infomaniak_mcp import TOOLS, BY_NAME, ErreurInfomaniak  # noqa: F401

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

PORT = int(os.environ.get("INFOMANIAK_LISTEN_PORT", "8080"))
PUBLIC_BASE = os.environ.get("INFOMANIAK_PUBLIC_BASE", "").rstrip("/") \
    or "http://127.0.0.1:%d" % PORT
MCP_URL = PUBLIC_BASE + "/mcp"
DATA_DIR = os.environ.get("INFOMANIAK_DATA", "/data")
OAUTH_PATH = os.path.join(DATA_DIR, "oauth.json")

# La marque que seul le proxy peut produire. Le nom de l'en-tête est une
# constante du module pour qu'un test l'IMPORTE au lieu de le recopier : deux
# orthographes de « X-Infomaniak-Proxy » — l'une ici, l'autre dans le
# middleware — donneraient un serveur qui refuse tout le monde, et un test
# vert.
ENTETE_MARQUE = "X-Infomaniak-Proxy"
MARQUE_PROXY = os.environ.get("INFOMANIAK_MARQUE_PROXY", "").strip()

CLIENT_ID = "infomaniak-domains-claude"
ALLOWED_REDIRECTS = tuple(
    x.strip() for x in os.environ.get(
        "INFOMANIAK_REDIRECTS", "https://claude.ai/api/mcp/auth_callback").split(",")
    if x.strip())

SCOPE_LIRE = "domaines:lire"
SCOPE_ECRIRE = "domaines:ecrire"
SCOPES = (SCOPE_LIRE, SCOPE_ECRIRE, "offline_access")
SCOPES_DEFAUT = SCOPE_LIRE + " " + SCOPE_ECRIRE

PENDING_TTL = 600          # une demande affichée mais pas encore validée
CODE_TTL = 300             # un code d'autorisation
REJEU_TTL = 300            # pendant lequel recharger la page rend la même réponse
ACCESS_TTL = 3600          # un jeton d'accès
REFRESH_TTL = 90 * 86400   # la chaîne de rafraîchissement, en absolu
REVOKE_TTL = 900           # un jeton anti-CSRF de la page « Connecter Claude »

# Ce que survit une PIERRE TOMBALE — une entrée gardée non pour servir, mais
# pour reconnaître un rejeu. Un jeton de rafraîchissement tourné restait dans
# l'état jusqu'à la fin de sa chaîne, c'est-à-dire quatre-vingt-dix jours :
# chaque rotation laissait une pierre de plus, l'état enflait sans borne, et
# comme le fichier vit sur le PVC, le pod finissait OOMKillé de façon
# PERMANENTE — un redémarrage relit le même fichier, donc remeurt. Mesuré :
# 300 rotations, 301 entrées.
#
# Une heure suffit à ce pour quoi la pierre existe : un client qui rejoue le
# fait dans la seconde, pas le lendemain. Au-delà, l'entrée n'est plus une
# détection de rejeu, c'est de l'encombrement — et un jeton présenté après sa
# disparition est refusé de toute façon, faute d'être dans la table.
TOMBE_TTL = 3600

# Une autorisation vit tant que sa chaîne de rafraîchissement peut vivre. Elle
# ne se périmait NULLE PART : `oauth_menage()` n'itérait que pending, codes,
# access et refresh, et `oauth_revoquer()` marquait `revoked` sans jamais
# retirer. `data["grants"]` n'était donc jamais purgée — le même défaut que la
# table refresh, sur la seule table qui ne se vide pas d'elle-même.
GRANT_TTL = REFRESH_TTL

# L'horodatage de dernière activité d'une autorisation. Le rafraîchir à chaque
# requête authentifiée réécrivait TOUT l'état à chaque `tools/list` — et même
# sur un `GET /mcp` qui ne rend qu'un 405. C'est ce qui rendait létale la table
# qui enflait : elle était réécrite en entier, sous le verrou global, à chaque
# requête. Une minute de granularité suffit à répondre « quand ce connecteur
# a-t-il servi pour la dernière fois ? ».
ACTIVITE_PAS = 60

# Le budget de durée TOTALE d'une lecture de corps, en secondes, compté depuis
# le début de la requête. Le `timeout` de la classe est un délai PAR recv : un
# octet toutes les vingt-neuf secondes tenait un thread indéfiniment, sans
# jamais présenter d'identifiant, et ThreadingHTTPServer ne plafonne pas ses
# threads. Un budget total, lui, ne se réarme pas. Réglable pour que les bancs
# d'essai n'aient pas à attendre huit secondes pour constater qu'il existe, et
# BORNÉ à [1 s, 60 s] : un réglage distrait — « 0 », « 999999 », « oui » — ne
# doit ni supprimer le budget ni le rendre inutile. Une valeur illisible
# retombe sur le défaut plutôt que d'empêcher le serveur de démarrer.
def _delai_corps():
    try:
        voulu = float(os.environ.get("INFOMANIAK_DELAI_CORPS") or 8)
    except ValueError:
        voulu = 8.0
    return min(60.0, max(1.0, voulu))


DELAI_CORPS = _delai_corps()

# Trois bornes, parce que trois tables grandissent sous la main d'un inconnu.
# Un plafond bas est un choix : au-delà, ce n'est plus un humain qui autorise
# des connecteurs, c'est quelqu'un qui inonde. Le dépassement évince la plus
# ancienne entrée plutôt que de refuser la nouvelle — refuser donnerait à
# l'inondeur exactement ce qu'il cherche, c'est-à-dire empêcher Vincent
# d'autoriser Claude.
PENDING_MAX = 64
GRACE_MAX = 32
REVOKE_MAX = 32
# La quatrième : les autorisations abouties. Elle est haute parce que /consent
# vit derrière la frontière humaine — la cadence y est celle d'un humain, pas
# celle d'un inondeur. Elle existe quand même : une péremption borne l'état
# dans le temps, un plafond le borne dans l'espace, et c'est le second qui
# tient le jour où l'horloge du pod recule.
GRANTS_MAX = 256

_oauth_lock = threading.Lock()

# Deux réserves qui ne touchent JAMAIS le disque, et c'est toute leur raison
# d'être. `empreinte()` promet qu'un fichier d'état volé ne donne aucun jeton
# utilisable ; l'URL de réponse de la fenêtre de grâce, elle, porte le code en
# clair, et un jeton anti-CSRF persisté serait un secret de plus sur le PVC
# pour rien. Les perdre au redémarrage ne coûte qu'un rechargement de page —
# un instantané du volume, lui, ne se rattrape pas.
#
# Le prix, à connaître : un second réplica ne les partagerait pas. Le
# Deployment est à `replicas: 1` en `Recreate` ; le jour où ça change, la
# fenêtre de grâce et le jeton de /revoke devront changer aussi.
_grace = {}            # empreinte(csrf) -> {"reponse": url, "exp": …}
_csrf_revoke = {}      # empreinte(jeton) -> {"exp": …}

# Les chemins qui sortent de l'authentification humaine, énumérés ici pour que
# le dépôt et l'Ingress se lisent l'un contre l'autre. Le serveur ne s'en sert
# pas pour décider : c'est Traefik qui tient la frontière, en `pathType:
# Exact`. `Prefix` s'y traduit par un préfixe de **chaîne**, donc exempter
# « /mcp » exempterait aussi « /mcpXXX ».
#
# Les sept premiers sont ceux que Claude appelle depuis le cloud. `/_whoami`
# est le huitième et n'a rien à voir avec OAuth : il sert l'empreinte du code
# chargé, et il ne vaut que s'il répond à qui n'a PAS le mot de passe — voir
# `_whoami()` pour ce qu'il montre et ce qu'il tait.
CHEMINS_MACHINE = (
    "/mcp", "/token", "/register",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/_whoami",
)

# --------------------------------------------------------------------------
# l'empreinte du code chargé
# --------------------------------------------------------------------------

# Calculée UNE FOIS, à l'import — pas à chaque requête, et pas par confort.
# `/app` est un ConfigMap : son contenu se rafraîchit tout seul, sans rollout,
# environ une minute après un `kubectl apply`. Relire les fichiers à chaque
# requête annoncerait donc l'empreinte de ce qui est SUR LE DISQUE, quand la
# question posée est « quel code ce processus exécute-t-il ? ». Lue à l'import,
# elle date du moment où Python a chargé ces octets : c'est la seule lecture
# qui réponde à la question.
FICHIERS_CODE = ("serveur.py", "infomaniak_mcp.py")


def _empreintes_du_code():
    """L'empreinte de chaque fichier, plus une empreinte d'ensemble.

    Par fichier et en SHA-256 brut, pour que la comparaison se fasse sans
    outil : `git show HEAD:serveur.py | shasum -a 256` doit rendre la même
    chaîne. Un condensé unique, lui, ne se compare qu'à un autre condensé du
    même programme — et ne dit pas LEQUEL des deux fichiers a divergé.
    """
    dossier = os.path.dirname(os.path.abspath(__file__))
    par_fichier = {}
    for nom in FICHIERS_CODE:
        try:
            with open(os.path.join(dossier, nom), "rb") as fh:
                par_fichier[nom] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            # Un fichier illisible n'est pas « inchangé » : on le dit, plutôt
            # que de servir une empreinte d'ensemble qui aurait l'air normale.
            par_fichier[nom] = "illisible"
    ensemble = hashlib.sha256(
        "".join("%s:%s\n" % (nom, par_fichier[nom])
                for nom in FICHIERS_CODE).encode("utf-8")).hexdigest()
    return par_fichier, ensemble


EMPREINTES_FICHIERS, EMPREINTE_CODE = _empreintes_du_code()


# --------------------------------------------------------------------------
# l'état OAuth — un JSON sur le volume, sous verrou
# --------------------------------------------------------------------------

def empreinte(valeur):
    """Ce qu'on persiste d'un jeton. Le fichier d'état volé ne donne alors
    aucun jeton utilisable."""
    return hashlib.sha256(str(valeur).encode("utf-8")).hexdigest()


def jeton():
    return secrets.token_urlsafe(32)


def horodate():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def oauth_load():
    try:
        with open(OAUTH_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    for cle in ("pending", "codes", "access", "refresh", "grants"):
        if not isinstance(data.get(cle), dict):
            data[cle] = {}
    return data


def oauth_save(data):
    """Rend False si rien n'a pu être écrit, et l'appelant DOIT le regarder.

    Écriture atomique par fichier temporaire puis `os.replace` : une coupure au
    milieu laisserait sinon un état tronqué, donc des jetons valides que le
    serveur ne reconnaît plus — et un utilisateur qui ne comprend pas pourquoi
    son connecteur est mort.
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = OAUTH_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, OAUTH_PATH)
        return True
    except OSError:
        return False


def peremption(entree, defaut=0.0):
    """La péremption d'une entrée, en secondes epoch, et jamais une exception.

    L'état vient d'un fichier : une version d'avant a pu l'écrire, un
    instantané a pu le tronquer, une main a pu l'éditer. Un `exp` absent,
    nul, textuel ou négatif ne doit pas faire lever le ménage — sinon un seul
    caractère de travers rend le serveur inutilisable, ce qui est pire que ce
    qu'on cherchait à empêcher.
    """
    try:
        return float(entree.get("exp") or defaut)
    except (TypeError, ValueError):
        return defaut


def oauth_menage(data, maintenant=None):
    """Écarte ce qui a expiré, et rend le NOMBRE de changements apportés.

    Un code consommé est GARDÉ jusqu'à sa péremption : c'est ce qui permet de
    DÉTECTER un rejeu au lieu de le confondre avec un code inconnu — et un
    rejeu confondu avec une erreur banale ne révoquerait rien.

    Le compte rendu n'est pas décoratif. `/token` est l'un des chemins sortis
    de l'authentification : n'importe qui l'atteint, et six chemins de refus
    persistaient l'état sans que rien n'ait changé — une réécriture complète du
    PVC par requête anonyme, sous le verrou global que `/mcp` doit prendre pour
    valider le moindre Bearer. L'appelant écrit maintenant si, et seulement si,
    ce compte est non nul.

    **Les cinq tables, pas quatre.** `grants` en était absente, et rien
    d'autre ne la vidait : `oauth_revoquer()` marque `revoked` sans retirer.
    Une table jamais purgée sur un volume est un OOMKill à échéance, et un
    OOMKill dont le redémarrage relit le même fichier est PERMANENT. Elle
    porte donc sa péremption comme les autres — posée à la volée sur un état
    écrit par une version d'avant, plutôt que de jeter des autorisations qui
    marchent.
    """
    now = maintenant if maintenant is not None else time.time()
    retire = 0
    for cle in ("pending", "codes", "access", "refresh"):
        garde = {k: v for k, v in data[cle].items()
                 if isinstance(v, dict) and peremption(v) > now}
        retire += len(data[cle]) - len(garde)
        data[cle] = garde

    grants = {}
    for gid, grant in data["grants"].items():
        if not isinstance(grant, dict):
            retire += 1
            continue
        fin = peremption(grant)
        if not fin:
            # Un état écrit avant que les autorisations ne se périment. On ne
            # le jette pas — ce serait déconnecter Claude sans prévenir — on
            # lui pose la péremption qui lui manque. C'est un CHANGEMENT, donc
            # il compte : sans ça, la réparation ne serait jamais persistée et
            # se referait à chaque requête.
            fin = now + GRANT_TTL
            grant["exp"] = fin
            retire += 1
        if fin > now:
            grants[gid] = grant
        else:
            retire += 1
    data["grants"] = grants
    return retire


def oauth_frais():
    """L'état débarrassé de ce qui a expiré, et le témoin qui dit si ce ménage
    a réellement retiré quelque chose. Les deux vont ensemble : sans le témoin,
    l'appelant ne peut que persister à l'aveugle."""
    data = oauth_load()
    return data, oauth_menage(data)


# --------------------------------------------------------------------------
# les réserves de mémoire — bornées, périssables, jamais persistées
# --------------------------------------------------------------------------

def memoire_poser(table, cle, valeur, plafond, maintenant=None):
    """Range une entrée périssable, en gardant la table sous son plafond.

    Le ménage passe d'abord sur ce qui a expiré ; s'il ne suffit pas, c'est la
    plus proche de sa péremption qui saute. Toujours appelée sous
    `_oauth_lock` : ces tables se lisent depuis plusieurs fils.
    """
    now = maintenant if maintenant is not None else time.time()
    for morte in [k for k, v in table.items() if float(v.get("exp", 0)) <= now]:
        del table[morte]
    while len(table) >= plafond:
        del table[min(table, key=lambda k: float(table[k].get("exp", 0)))]
    table[cle] = valeur


def memoire_lire(table, cle, maintenant=None):
    """L'entrée si elle est encore vivante, None sinon. Ne la consomme pas."""
    entree = table.get(cle)
    if not isinstance(entree, dict):
        return None
    now = maintenant if maintenant is not None else time.time()
    if float(entree.get("exp", 0)) <= now:
        del table[cle]
        return None
    return entree


def memoire_consommer(table, cle, maintenant=None):
    """L'entrée, retirée dans le même geste. Un jeton à usage unique ne se
    relit pas : il se prend, et il se prend même s'il était périmé — sinon un
    rejeu laisserait l'entrée en place pour l'essai suivant."""
    entree = table.pop(cle, None)
    if not isinstance(entree, dict):
        return None
    now = maintenant if maintenant is not None else time.time()
    return None if float(entree.get("exp", 0)) <= now else entree


def oauth_revoquer(data, grant_id):
    """Révoque tout ce qui découle d'une même autorisation. Couper le seul jeton
    présenté laisserait vivre le reste de la famille, donc l'accès volé.

    L'autorisation révoquée devient une PIERRE TOMBALE, et une pierre tombale
    se périme : plus rien ne la référence — les trois tables qui la nommaient
    viennent d'être vidées d'elle — et la page d'accueil ne l'affiche plus.
    Sans péremption, révoquer FAISAIT GROSSIR l'état pour toujours ; le geste
    de ménage était devenu le geste qui encombre.
    """
    for cle in ("access", "refresh", "codes"):
        data[cle] = {k: v for k, v in data[cle].items() if v.get("grant_id") != grant_id}
    grant = data["grants"].get(grant_id)
    if isinstance(grant, dict):
        grant["revoked"] = horodate()
        fin = time.time() + TOMBE_TTL
        grant["exp"] = min(peremption(grant, fin), fin)


def scopes_valides(demande):
    """Le sous-ensemble demandé, ou None s'il sort de ce qu'on sait accorder."""
    if not demande:
        return SCOPES_DEFAUT
    demandes = [x for x in str(demande).split() if x]
    if not demandes or any(x not in SCOPES for x in demandes):
        return None
    return " ".join(demandes)


def analyse_url(valeur):
    """L'URL découpée, ou None si elle est illisible.

    Deux LEVÉES vivent dans `urlparse`, et toutes deux se déclenchent sur une
    valeur venue de dehors — chaîne de requête, formulaire, ou ligne de requête
    elle-même :

      - `urlparse("http://[::1/x")` lève « Invalid IPv6 URL » AVANT même qu'on
        puisse lire un champ, sur un crochet non fermé ;
      - `urlparse("https://x:99999/").port` lève « Port out of range », de même
        que « :abc ».

    Toutes deux coupaient la socket sans réponse et crachaient une trace de
    pile dans le journal du pod. Ne pas savoir lire une URL doit être un refus
    ordinaire, jamais un accident : on rend None, et l'appelant refuse.
    """
    try:
        return urlparse(str(valeur))
    except ValueError:
        return None


def chemin_demande(cible):
    """Le chemin d'une cible de requête, ou "" si elle est illisible.

    La ligne de requête accepte une cible en forme absolue — `GET
    http://hôte/x` —, donc `self.path` peut porter n'importe quelle URL. Une
    cible illisible tombe sur le chemin vide, qui n'est routé nulle part : elle
    récolte un 404, ce qu'un inconnu doit recevoir pour tout ce qu'on ne
    comprend pas.
    """
    morceau = analyse_url(cible or "")
    return morceau.path if morceau is not None else ""


def canoniser_ressource(valeur):
    """La forme canonique d'une URL de ressource, ou None si elle n'en a pas.

    Compare deux URL sans se faire piéger par la casse, un port par défaut, un
    fragment ou un slash final. La valeur vient d'un formulaire posté sur
    `/token`, chemin public et non authentifié : le contrôle d'audience était
    devenu la porte de déni de service qu'il était censé fermer. Une URL qu'on
    n'arrive pas à lire n'est pas la nôtre — `ressource_connue()` refuse.
    """
    morceau = analyse_url(valeur)
    if morceau is None:
        return None
    hote = (morceau.hostname or "").lower()
    schema = (morceau.scheme or "").lower()
    try:
        port = morceau.port
    except ValueError:
        return None
    if port and not ((schema == "https" and port == 443) or (schema == "http" and port == 80)):
        hote = "%s:%d" % (hote, port)
    chemin = (morceau.path or "").rstrip("/")
    return "%s://%s%s" % (schema, hote, chemin)


def ressource_connue(valeur):
    """La ressource nommée est-elle la nôtre ? Le `is not None` n'est pas une
    précaution de style : sans lui, deux URL illisibles se compareraient égales
    et l'audience s'ouvrirait justement sur ce qu'on n'a pas su lire."""
    canon = canoniser_ressource(valeur)
    return canon is not None and canon == canoniser_ressource(MCP_URL)


# --------------------------------------------------------------------------
# la portée d'un outil — déduite, jamais redite
# --------------------------------------------------------------------------

# `_o()` ne garde de l'armement qu'une marque en tête de description ; c'est
# donc le seul signal qui arrive jusqu'ici. Le déduire d'une chaîne est laid,
# mais recopier la liste des outils qui écrivent créerait la seconde liste
# qu'on refuse : elle serait juste le jour où on l'écrit, et fausse au premier
# outil ajouté. Un test exige qu'au moins un outil tombe de chaque côté — sans
# quoi une marque renommée dans infomaniak_mcp ferait passer tout le monde en
# lecture, en silence.
MARQUES_ECRITURE = ("[écrit] ", "[DÉPENSE] ")


def portee_outil(outil):
    if str(outil.get("description") or "").startswith(MARQUES_ECRITURE):
        return SCOPE_ECRIRE
    return SCOPE_LIRE


def outils_par_portee():
    """Rend {portée: [noms]} — sert à la page de consentement, qui doit dire ce
    qu'elle autorise vraiment et non une catégorie abstraite."""
    tri = {SCOPE_LIRE: [], SCOPE_ECRIRE: []}
    for outil in TOOLS:
        tri[portee_outil(outil)].append(outil["name"])
    return tri


# --------------------------------------------------------------------------
# les documents de découverte
# --------------------------------------------------------------------------

def metadonnees_ressource():
    """RFC 9728. `resource` doit valoir EXACTEMENT ce qu'on colle dans Claude,
    chemin compris. `offline_access` n'y figure pas alors qu'il figure dans les
    métadonnées du serveur d'autorisation : les deux listes diffèrent, et c'est
    la spec qui le veut."""
    return {"resource": MCP_URL,
            "authorization_servers": [PUBLIC_BASE],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE_LIRE, SCOPE_ECRIRE],
            "resource_name": infomaniak_mcp.NAME}


def metadonnees_autorisation():
    """RFC 8414. `issuer` doit être identique caractère pour caractère à
    l'entrée d'`authorization_servers` ci-dessus, sinon un client conforme
    rejette le document. `code_challenge_methods_supported` est OBLIGATOIRE :
    s'il manque, un client conforme refuse de démarrer sans même tenter
    /authorize — et on croit à une panne réseau."""
    return {"issuer": PUBLIC_BASE,
            "authorization_endpoint": PUBLIC_BASE + "/authorize",
            "token_endpoint": PUBLIC_BASE + "/token",
            "registration_endpoint": PUBLIC_BASE + "/register",
            "scopes_supported": list(SCOPES),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True}


# --------------------------------------------------------------------------
# les pages humaines
# --------------------------------------------------------------------------

# Passé en ARGUMENT du %-formatting, jamais dans la chaîne de format : les
# pourcents d'une feuille de style cassent le rendu (déjà arrivé dans le dépôt
# voisin).
CSS = """
:root{color-scheme:light dark}
body{margin:0;background:#f7f7f5;color:#1e1e1c;
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media (prefers-color-scheme:dark){body{background:#151614;color:#e8e6e1}}
.boite{max-width:36rem;margin:9vh auto;padding:0 1.25rem}
h1{font-size:1.45rem;margin:0 0 1.1rem}
h2{font-size:1rem;margin:2rem 0 .6rem;color:#6d6a63}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em}
.cible{background:#e8eef0;color:#2b5566;border-radius:8px;padding:.7rem .9rem;
margin:0 0 1.2rem;font-size:.95rem}
@media (prefers-color-scheme:dark){.cible{background:#1d262a;color:#8fb8c8}}
.alerte{background:#f6e3d8;color:#8a3f16;border-radius:8px;padding:.7rem .9rem;
margin:0 0 1.2rem;font-size:.95rem}
@media (prefers-color-scheme:dark){.alerte{background:#2e2019;color:#e0a077}}
ul{margin:0 0 1.5rem;padding-left:1.2rem}
li{margin:0 0 .4rem}
.rangee{display:flex;gap:.7rem;align-items:center}
button{font:inherit;border:0;border-radius:8px;padding:.6rem 1.2rem;cursor:pointer}
button.oui{background:#2b5566;color:#f7f7f5}
button.non{background:none;color:#78756e;border:1px solid #dedad2}
button.petit{padding:.3rem .7rem;font-size:.85rem;background:none;color:#78756e;
border:1px solid #dedad2}
table{border-collapse:collapse;width:100%;font-size:.9rem}
td,th{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #dedad2}
p.pied{color:#78756e;font-size:.82rem;margin:1.6rem 0 0}
"""

LIBELLES = {
    SCOPE_LIRE: "lire vos domaines, vos zones DNS, leurs enregistrements, vos "
                "contacts et le solde du compte prépayé",
    SCOPE_ECRIRE: "créer, modifier et supprimer des enregistrements DNS, "
                  "changer les serveurs de noms, et — si l'achat est armé — "
                  "enregistrer un domaine, ce qui dépense de l'argent",
    "offline_access": "garder l'accès sans vous le redemander à chaque fois",
}


def etat_armement():
    """Ce que ce déploiement autorise réellement, en une phrase.

    La portée dit ce que le jeton a le droit de DEMANDER ; l'armement dit ce
    que le serveur accepte de FAIRE. Afficher la portée seule promettrait sur
    la page de consentement un pouvoir que `INFOMANIAK_WRITE` refuse ensuite —
    ou pire, tairait qu'une dépense est possible.
    """
    if not infomaniak_mcp.ecriture_armee():
        etat = ("Ce serveur est en LECTURE SEULE : les outils d'écriture "
                "refuseront d'agir, quelle que soit la portée accordée.")
    else:
        etat = "Les outils d'écriture DNS sont armés sur ce serveur."
    if infomaniak_mcp.achat_arme():
        etat += (" L'enregistrement de domaine est ARMÉ : autoriser ici permet "
                 "une dépense réelle, plafonnée par INFOMANIAK_ACHAT_MAX.")
    else:
        etat += " L'enregistrement de domaine n'est pas armé."
    return etat


def page_consentement(csrf, redirect_uri, scope):
    hote = urlparse(redirect_uri).hostname or redirect_uri
    lignes = "".join("<li>%s</li>" % html.escape(LIBELLES.get(x, x)) for x in scope.split())
    classe = "alerte" if infomaniak_mcp.achat_arme() else "cible"
    return ("""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Autoriser Claude — domaines Infomaniak</title><style>%s</style></head><body>
<div class="boite">
<h1>Claude demande à piloter vos domaines Infomaniak</h1>
<p class="cible">Le jeton sera remis à <b class="mono">%s</b>.</p>
<p>Ce que cela permettra :</p>
<ul>%s</ul>
<p class="%s">%s</p>
<form method="post" action="/consent" class="rangee">
<input type="hidden" name="csrf" value="%s">
<button class="oui" type="submit" name="action" value="autoriser">Autoriser</button>
<button class="non" type="submit" name="action" value="refuser">Refuser</button>
</form>
<p class="pied">Cet écran s'affiche à chaque autorisation : un client public ne
peut pas prouver son identité, donc on ne se souvient d'aucun accord. Le jeton
d'API Infomaniak, lui, ne quitte jamais ce serveur.</p>
</div></body></html>""" % (CSS, html.escape(hote), lignes, classe,
                           html.escape(etat_armement()),
                           html.escape(csrf, quote=True)))


def page_refus(titre, detail):
    return ("""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>%s</style></head><body><div class="boite">
<h1>%s</h1><p>%s</p>
<p class="pied">Rien n'a été autorisé, et aucune adresse n'a été contactée.</p>
</div></body></html>""" % (html.escape(titre), CSS, html.escape(titre),
                           html.escape(detail)))


def page_accueil(grants, csrf):
    """La page « Connecter Claude ». Derrière l'authentification humaine.

    Elle montre l'état réel du déploiement plutôt que ce qu'on croit avoir
    déployé : un jeton d'API absent ne se voit sinon qu'au premier appel
    d'outil, sous la forme d'une erreur qui semble venir de Claude.

    Le `csrf` est le même pour tous les boutons de la page, et il ne sert
    qu'une fois : révoquer consomme le jeton, la redirection vers `/` en rend
    un frais. Le mot de passe du proxy est un credential ambiant que le
    navigateur rejoue seul sur une soumission inter-site — sans ce jeton, une
    page hostile coupait d'un POST toutes les autorisations du connecteur.
    """
    tri = outils_par_portee()
    epingle = infomaniak_mcp.compte_epingle()
    # On regarde si un jeton est configuré, et RIEN de plus : ni sa valeur, ni
    # sa longueur, qui en dirait déjà sur sa forme.
    porteur = "oui" if infomaniak_mcp.jeton() else "NON — aucun outil ne pourra répondre"

    marque = "<input type=\"hidden\" name=\"csrf\" value=\"%s\">" % html.escape(
        csrf, quote=True)

    if grants:
        rangees = "".join(
            "<tr><td>%s</td><td>%s</td><td class=\"mono\">%s</td><td>"
            "<form method=\"post\" action=\"/revoke\">%s"
            "<input type=\"hidden\" name=\"grant\" value=\"%s\">"
            "<button class=\"petit\" type=\"submit\">Révoquer</button>"
            "</form></td></tr>"
            % (html.escape(g.get("created", "")), html.escape(g.get("last", "")),
               html.escape(g.get("scope", "")), marque, html.escape(gid, quote=True))
            for gid, g in grants)
        table = ("<table><tr><th>accordée</th><th>vue</th><th>portée</th><th></th></tr>"
                 "%s</table>"
                 "<form method=\"post\" action=\"/revoke\" style=\"margin-top:1rem\">%s"
                 "<input type=\"hidden\" name=\"grant\" value=\"tout\">"
                 "<button class=\"non\" type=\"submit\">Tout révoquer</button></form>"
                 % (rangees, marque))
    else:
        table = "<p>Aucune autorisation en cours.</p>"

    return ("""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connecter Claude — domaines Infomaniak</title><style>%s</style></head><body>
<div class="boite">
<h1>Connecter Claude à vos domaines Infomaniak</h1>
<p>Dans Claude, ajouter un connecteur et coller cette adresse :</p>
<p class="cible"><b class="mono">%s</b></p>
<h2>État de ce serveur</h2>
<ul>
<li>%s</li>
<li>Jeton d'API Infomaniak configuré : <b>%s</b></li>
<li>Compte épinglé : <b class="mono">%s</b></li>
<li>%d outil(s) en lecture, %d en écriture.</li>
</ul>
<h2>Autorisations en cours</h2>
%s
<p class="pied">Révoquer coupe d'un coup tous les jetons issus d'une même
autorisation — Claude redemandera votre accord. Le jeton d'API Infomaniak reste
dans ce conteneur : il n'est jamais remis à Claude, ni journalisé.</p>
</div></body></html>""" % (CSS, html.escape(MCP_URL), html.escape(etat_armement()),
                           html.escape(porteur), html.escape(epingle or "aucun"),
                           len(tri[SCOPE_LIRE]), len(tri[SCOPE_ECRIRE]), table))


def redirection_erreur(redirect_uri, erreur, state, description=""):
    """Une erreur RENVOYÉE au client — légitime seulement après que l'adresse de
    retour a été validée par égalité stricte. Avant ça, rediriger reviendrait à
    répondre à un inconnu qui a choisi la destination."""
    champs = {"error": erreur, "iss": PUBLIC_BASE}
    if description:
        champs["error_description"] = description
    if state:
        champs["state"] = state
    joint = "&" if "?" in redirect_uri else "?"
    return redirect_uri + joint + urlencode(champs)


# --------------------------------------------------------------------------
# le serveur
# --------------------------------------------------------------------------

class RefusCorps:
    """Le témoin d'un corps qu'on a refusé de lire, et pourquoi.

    Un objet, et non une chaîne. Le témoin valait « trop-gros », comparé au
    corps DÉCODÉ : un client dont le corps valait exactement ces neuf
    caractères se voyait répondre 413. Une sentinelle que la donnée qu'elle
    décrit peut imiter n'est pas une sentinelle.
    """

    __slots__ = ("code", "quoi")

    def __init__(self, code, quoi):
        self.code = code
        self.quoi = quoi


TROP_GROS = RefusCorps(413, "le corps annoncé dépasse ce que ce chemin accepte")
TROP_LENT = RefusCorps(408, "le corps n'est pas arrivé dans le temps imparti")


class Poignee(BaseHTTPRequestHandler):
    server_version = "infomaniak-domains/" + infomaniak_mcp.VERSION
    protocol_version = "HTTP/1.1"
    timeout = 30

    # ---- sorties ---------------------------------------------------------

    def log_message(self, format, *args):             # noqa: A002
        """Le chemin sans sa requête, et rien d'autre.

        La ligne de requête par défaut recopie la chaîne de requête, donc le
        `state` et le `code_challenge` — sans parler d'un `code` qui traînerait
        dans un rechargement. Aucun en-tête n'est journalisé : c'est là que
        vivent le Bearer et le mot de passe du proxy.
        """
        chemin = chemin_demande(self.path)
        print("%s %s %s" % (horodate(), self.command or "?", chemin), flush=True)

    def _corps_en_suspens(self):
        """Reste-t-il, dans le tampon, un corps annoncé que personne n'a lu ?

        C'est la question qui décide si la connexion peut resservir. Un corps
        qui traîne se fait lire comme la requête suivante : `GET /mcp` avec un
        corps faisait servir une requête clandestine, choisie par l'appelant,
        sur un chemin protégé.
        """
        try:
            annonce = int(self.headers.get("Content-Length") or 0)
        except (ValueError, AttributeError):
            annonce = -1
        return annonce != 0 and not getattr(self, "_corps_consomme", False)

    def _fin_de_reponse(self):
        """Rend True — pour que `return self._json(...)` interrompe vraiment le
        traitement — et coupe la connexion si un corps annoncé n'a pas été lu.

        Deux failles jumelles, trouvées par audit adverse le 2026-08-31 et
        l'une comme l'autre prouvées, vivaient ici :

        - sans valeur de retour, `if refus is not None: return refus` ne se
          déclenchait jamais : le 401 partait, puis le traitement continuait et
          un anonyme recevait un 200 complet sur /mcp ;
        - un corps annoncé et non consommé devenait une requête pipelinée.

        Ce qu'il RESTE ici n'est plus qu'une ceinture. La décision de couper se
        prend désormais AVANT d'écrire les en-têtes, dans `_prelude()` : la
        poser après `end_headers()` faisait partir une réponse d'allure
        keep-alive sur une socket que le serveur allait fermer, si bien que le
        proxy la remettait dans son pool et voyait sa requête suivante mourir
        sans réponse. Couper sans le dire, c'est faire porter la panne à
        l'intermédiaire.
        """
        if self._corps_en_suspens():
            self.close_connection = True
        return True

    def _prelude(self, code):
        """Ouvre la réponse, en ayant D'ABORD décidé si la connexion survit.

        L'ordre est tout : `send_response()` fige la ligne de statut, et
        `send_header("Connection", …)` n'a plus de sens une fois les en-têtes
        terminés. On tranche donc ici, avant le premier octet, et on ANNONCE ce
        qu'on a tranché — un client, un proxy, un pool de connexions ne peuvent
        se conduire correctement que devant une réponse qui dit la vérité sur
        la connexion qui la porte.
        """
        coupe = self.close_connection or self._corps_en_suspens()
        self.send_response(code)
        if coupe:
            # Pose aussi `close_connection`, par contrat de `send_header`.
            self.send_header("Connection", "close")
        return coupe

    def _send(self, code, corps, ctype="text/html; charset=utf-8", extra=None):
        octets = corps.encode("utf-8") if isinstance(corps, str) else corps
        self._prelude(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(octets)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for nom, valeur in extra or ():
            self.send_header(nom, valeur)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(octets)
        return self._fin_de_reponse()

    def _json(self, code, charge, extra=None, cache=None):
        octets = json.dumps(charge, ensure_ascii=False).encode("utf-8")
        self._prelude(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(octets)))
        self.send_header("Cache-Control", cache or "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for nom, valeur in extra or ():
            self.send_header(nom, valeur)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(octets)
        # Le retour est HORS du `if`, comme dans `_send` : sur un HEAD, `_json`
        # rendait None, donc `if refus is not None` ne se déclenchait pas et le
        # traitement continuait — deux réponses sur une seule requête. C'est
        # exactement la faille que `_fin_de_reponse()` existe pour fermer.
        return self._fin_de_reponse()

    def _redirect(self, location, code=303):
        self._prelude(code)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return self._fin_de_reponse()

    # ---- le cadrage de la requête ----------------------------------------

    def parse_request(self):
        """Le cadrage, tranché AVANT le routage — et le départ du chronomètre.

        Deux choses se règlent ici, et nulle part ailleurs, parce qu'ici est
        le seul endroit que TOUTES les méthodes traversent : celles qu'on
        implémente comme celles qu'on ne connaît pas.

        **Transfer-Encoding est refusé, sans exception.** La couche HTTP de la
        stdlib ne l'implémente pas : elle cadre sur le seul `Content-Length` et
        ignore `Transfer-Encoding`. Une requête portant les deux se fait donc
        découper d'une façon par nous et d'une autre par le proxy en amont —
        la désynchronisation CL.TE, prouvée en socket brute sur ce serveur :
        DEUX réponses partaient, dont une pour une requête clandestine que
        l'appelant avait glissée dans le corps. On ne « corrige » pas ce
        désaccord en implémentant le chunked ; on refuse d'être le deuxième
        avis. 400, et la connexion se ferme : la garder reviendrait à raisonner
        sur un tampon dont on vient d'admettre qu'on ne sait pas le découper.

        **Un Content-Length douteux est refusé de même** : annoncé deux fois
        avec deux valeurs, ou écrit autrement qu'en chiffres ASCII. `int()`
        accepte « +5 », « 1_0 » et les chiffres pleine chasse ; un proxy en
        amont, non. Là où deux couches peuvent lire deux longueurs, il n'y a
        pas de bonne réponse à servir — on n'en sert aucune.

        Deux annonces IDENTIQUES sont acceptées : le RFC 7230 §3.3.2 les
        autorise, et aucune ambiguïté n'en découle. Les espaces autour de la
        valeur ne sont pas notre affaire non plus — le parseur de la stdlib les
        a déjà retirés, comme le prescrit le même RFC.
        """
        if not BaseHTTPRequestHandler.parse_request(self):
            return False
        # Le chronomètre part ici : la ligne de requête et les en-têtes sont
        # lus, le corps ne l'est pas encore. C'est de cet instant que court le
        # budget de `_corps_borne`.
        self._debut_requete = time.monotonic()
        self._corps_consomme = False

        if self.headers.get_all("Transfer-Encoding"):
            return self._refus_cadrage(
                "Transfer-Encoding n'est pas accepté : ce serveur ne cadre que "
                "sur Content-Length.")
        longueurs = {v.strip() for v in (self.headers.get_all("Content-Length") or [])}
        if len(longueurs) > 1:
            return self._refus_cadrage(
                "Content-Length est annoncé plusieurs fois, et pas deux fois "
                "pareil.")
        # Des chiffres ASCII, et rien d'autre : `.isdigit()` dirait oui aux
        # chiffres pleine chasse, qu'`int()` accepte aussi — mais qu'un proxy
        # en amont lira tout autrement, s'il ne les refuse pas.
        if longueurs and not re.fullmatch(r"[0-9]{1,15}", longueurs.pop()):
            return self._refus_cadrage(
                "Content-Length n'est pas un nombre d'octets.")
        return True

    def _refus_cadrage(self, pourquoi):
        """400, la connexion coupée, et False pour que rien ne soit routé."""
        self.close_connection = True
        self._corps_consomme = True     # on ne lira pas ce corps : il est mort avec
        self._send(400, page_refus("Requête mal cadrée", pourquoi))
        return False

    # ---- entrées ---------------------------------------------------------

    def _refus_corps(self, temoin, en_json=False):
        """La réponse que mérite un corps refusé, dans le format du chemin."""
        if en_json:
            return self._json(temoin.code, {"error": "invalid_request",
                                            "error_description": temoin.quoi})
        return self._send(temoin.code, page_refus("Corps refusé", temoin.quoi))

    def _corps_borne(self, limite):
        """Rend le corps, "" s'il n'y en a pas, ou un témoin de refus.

        Deux bornes, et deux dimensions distinctes.

        **La taille** : sans elle, un Content-Length de plusieurs gigaoctets
        tiendrait un thread et la mémoire du conteneur. Témoin `TROP_GROS`.

        **La durée** : `timeout = 30` est un délai PAR recv, pas un plafond de
        durée. Un octet toutes les vingt-neuf secondes tenait donc un thread
        indéfiniment — anonymement, sans authentification, et sans que rien ne
        le compte. C'est le slowloris, et ThreadingHTTPServer ne plafonne pas
        ses threads : quelques centaines de connexions au goutte-à-goutte et le
        pod ne répond plus, y compris à sa sonde de readiness.

        On lit donc par tranches contre une échéance ABSOLUE, calculée depuis
        le début de la requête. Témoin `TROP_LENT`, que l'appelant rend en 408.
        Une connexion qui a dépassé son budget ne peut plus servir : son tampon
        contient un corps à moitié lu, dont personne ne sait où il s'arrête.

        Les deux témoins sont des OBJETS, non des chaînes : un corps valant
        exactement « trop-gros » se faisait refuser comme s'il l'était.
        """
        try:
            taille = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return ""
        if taille <= 0:
            self._corps_consomme = True
            return ""
        if taille > limite:
            # Le corps n'est pas lu : la connexion ne peut plus servir.
            self.close_connection = True
            return TROP_GROS

        echeance = getattr(self, "_debut_requete", time.monotonic()) + DELAI_CORPS
        morceaux, lu = [], 0
        try:
            while lu < taille:
                reste = echeance - time.monotonic()
                if reste <= 0:
                    self.close_connection = True
                    return TROP_LENT
                self.connection.settimeout(reste)
                # `read1` rend ce qui est arrivé, sans attendre le compte rond :
                # c'est ce qui permet de revenir vérifier l'échéance entre deux
                # tranches. `read(n)` bloquerait jusqu'aux n octets, et le
                # budget ne serait consulté qu'une fois trop tard.
                bloc = self.rfile.read1(min(taille - lu, 65536))
                if not bloc:
                    # Fin de flux avant le compte annoncé : le corps est
                    # tronqué, et ce qu'on en a ne se distingue pas d'un corps
                    # complet. On le traite comme un dépassement.
                    self.close_connection = True
                    return TROP_LENT
                morceaux.append(bloc)
                lu += len(bloc)
        except (OSError, ValueError):
            # `socket.timeout` en est un ; une socket coupée en plein corps
            # aussi. Dans les deux cas il n'y a pas de corps à servir.
            self.close_connection = True
            return TROP_LENT
        finally:
            self.connection.settimeout(self.timeout)

        # Le témoin dit que le tampon est vide : sans lui, un corps annoncé et
        # jamais lu se ferait interpréter comme une requête pipelinée.
        self._corps_consomme = True
        return b"".join(morceaux).decode("utf-8", "replace")

    def _stricte(self, brut):
        """Décode une chaîne de paramètres en REFUSANT les clés répétées.

        `parse_qsl` garde la dernière : un `redirect_uri` doublé laisserait
        alors le contrôle porter sur l'une et l'usage sur l'autre, selon le
        composant qui lit. Rend None plutôt que d'arbitrer.
        """
        vus = {}
        try:
            paires = parse_qsl(brut, keep_blank_values=True, max_num_fields=48)
        except ValueError:
            return None
        for cle, valeur in paires:
            if cle in vus:
                return None
            vus[cle] = valeur
        return vus

    def _query_stricte(self):
        morceau = analyse_url(self.path)
        return None if morceau is None else self._stricte(morceau.query)

    def _form_stricte(self):
        """Le formulaire décodé, None s'il est illisible, ou un témoin de refus
        que l'appelant doit rendre tel quel — 413 ou 408, jamais 400 : « je
        n'ai pas su lire » et « tu as dépassé ta borne » ne sont pas la même
        chose, et un client qui les confond réessaie ce qu'il ne devrait pas."""
        brut = self._corps_borne(64 * 1024)
        if isinstance(brut, RefusCorps):
            return brut
        return self._stricte(brut)

    # ---- l'authentification humaine, tenue devant --------------------------

    def _boucle_locale(self):
        """La requête vient-elle de l'intérieur du conteneur ?

        L'adresse du pair est constatée par le noyau, pas écrite par
        l'appelant : c'est la seule chose, dans une requête HTTP, qu'on ne
        puisse pas forger. En production rien n'arrive par la boucle locale —
        Traefik appelle depuis son IP de pod, la sonde de readiness depuis
        celle du nœud, et ce pod n'est pas en `hostNetwork`. Une requête en
        127.0.0.1 est donc déjà dans le conteneur, où il n'y a plus rien à lui
        refuser.
        """
        adresse = (self.client_address or ("",))[0]
        if adresse.startswith("::ffff:"):       # IPv4 vue par une pile IPv6
            adresse = adresse[7:]
        return adresse == "::1" or adresse.startswith("127.")

    def _humain_present(self):
        """La marque que seul le proxy peut produire.

        Ce qu'on croyait avant : `Authorization: Basic n'importe-quoi` ou un
        `X-Forwarded-User` suffisaient. Or ces deux en-têtes, l'appelant les
        écrit lui-même — et le pod écoute sur 8080 : tout voisin du cluster
        atteignait /authorize, la page qui émet les codes d'autorisation, sans
        jamais passer par Traefik ni par son mot de passe.

        On compare donc un secret partagé avec le proxy, en temps constant, et
        sur des empreintes plutôt que sur les valeurs : `compare_digest` lève
        sur une chaîne non-ASCII, et l'en-tête vient de dehors.

        **Une seule occurrence acceptée.** Si le middleware ajoutait la marque
        au lieu de l'écraser, une copie hostile arriverait en tête et serait
        celle que `get()` rend. Le middleware doit écraser ; on refuse le
        doublon pour que sa mauvaise configuration se voie plutôt que
        s'exploite.

        **Le vide alarme.** Sans `INFOMANIAK_MARQUE_PROXY`, il n'existe aucune
        marque à comparer : le serveur ne sert plus les pages humaines qu'à la
        boucle locale. En test — banc jetable sur 127.0.0.1 — tout continue de
        fonctionner ; en production, où rien n'arrive par la boucle locale,
        tout est refusé. Une variable oubliée rend donc le connecteur
        inutilisable et visiblement cassé, jamais ouvert en silence.
        """
        if not MARQUE_PROXY:
            return self._boucle_locale()
        recus = self.headers.get_all(ENTETE_MARQUE) or []
        if len(recus) != 1:
            return False
        return hmac.compare_digest(empreinte(recus[0].strip()),
                                   empreinte(MARQUE_PROXY))

    def _defi_humain(self):
        """401, et il dit LEQUEL des deux cas s'est produit.

        Le défi Basic est conservé parce que la frontière humaine reste celle
        de Traefik : c'est à lui que le navigateur doit présenter le mot de
        passe. Mais un 401 muet enverrait Vincent taper un mot de passe qui ne
        sert à rien quand la vraie cause est une variable absente — et cette
        heure-là, on l'a déjà payée ailleurs.
        """
        if MARQUE_PROXY:
            detail = ("Cette page est réservée au propriétaire du serveur, et "
                      "cette requête n'a pas traversé le proxy qui l'authentifie.")
        else:
            detail = ("Ce serveur n'a pas de marque de proxy (INFOMANIAK_MARQUE_PROXY) : "
                      "il ne sert donc les pages humaines qu'à lui-même. Tant que la "
                      "variable manque, aucun mot de passe n'ouvrira cette page.")
        return self._send(401, page_refus("Authentification requise", detail),
                          extra=[("WWW-Authenticate", 'Basic realm="domaines Infomaniak"')])

    # ---- le porteur ------------------------------------------------------

    def _defi_bearer(self, erreur="", description=""):
        """Le défi qui dit à Claude OÙ demander un jeton. Sans le paramètre
        `resource_metadata`, il ne trouve pas le serveur d'autorisation et
        abandonne sur « Couldn't reach the MCP server » — une panne qui ne
        ressemble en rien à un problème d'authentification."""
        parties = ['Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"'
                   % PUBLIC_BASE,
                   'scope="%s %s"' % (SCOPE_LIRE, SCOPE_ECRIRE)]
        if erreur:
            parties.append('error="%s"' % erreur)
            if description:
                parties.append('error_description="%s"' % description.replace('"', ""))
        return self._json(401, {"error": erreur or "invalid_token"},
                          extra=[("WWW-Authenticate", ", ".join(parties))])

    def _porteur(self):
        """Le jeton présenté, validé. Rend (portées, None) ou (None, réponse).

        **Une lecture n'est pas une écriture.** Cette fonction réécrivait TOUT
        l'état — les cinq tables, sérialisées, sur le PVC, sous le verrou
        global — à chaque requête authentifiée. Prouvé : le mtime de
        `oauth.json` changeait sur un simple `tools/list`, et jusque sur un
        `GET /mcp` qui ne rend qu'un 405. C'est ce qui rendait létale une table
        qui enfle : le coût d'une entrée de plus se payait par requête, pas par
        rotation.

        On ne persiste donc que si quelque chose a réellement changé : un
        ménage qui a retiré une entrée, ou un horodatage d'activité qu'on ne
        rafraîchit qu'une fois par `ACTIVITE_PAS`. La question à laquelle
        `last` répond — « quand ce connecteur a-t-il servi ? » — n'a jamais eu
        besoin de la seconde près.
        """
        brut = self.headers.get("Authorization") or ""
        if not brut:
            return None, self._defi_bearer()
        if brut.startswith("Basic "):
            # Refus EXPLICITE du credential ambiant : le mot de passe du proxy
            # prouve « ce navigateur le détient », jamais « cet humain a voulu
            # CETTE autorisation-ci ».
            return None, self._defi_bearer("invalid_token",
                                           "ce chemin demande un jeton Bearer")
        if not brut.startswith("Bearer "):
            return None, self._defi_bearer("invalid_token")
        with _oauth_lock:
            data, change = oauth_frais()
            entree = data["access"].get(empreinte(brut[7:].strip()))
            if not isinstance(entree, dict):
                if change:
                    oauth_save(data)
                return None, self._defi_bearer("invalid_token")
            if entree.get("aud") != MCP_URL:
                if change:
                    oauth_save(data)
                return None, self._defi_bearer("invalid_token",
                                               "jeton émis pour une autre ressource")
            grant = data["grants"].get(entree.get("grant_id"))
            if isinstance(grant, dict) and grant.get("revoked"):
                if change:
                    oauth_save(data)
                return None, self._defi_bearer("invalid_token", "autorisation révoquée")
            # L'horodatage ne se pose que sur une autorisation qui EXISTE
            # encore. Sur un dictionnaire fabriqué à la volée — le cas d'un
            # jeton d'accès dont l'autorisation vient d'expirer, une heure au
            # plus tous les quatre-vingt-dix jours — l'écrire ne mémoriserait
            # rien et ferait réécrire tout l'état à chaque requête. C'est-à-dire
            # rouvrir, dans un coin, la faille qu'on vient de fermer.
            maintenant = time.time()
            if isinstance(grant, dict):
                try:
                    dernier = float(grant.get("last_ts") or 0)
                except (TypeError, ValueError):
                    dernier = 0.0
                if maintenant - dernier >= ACTIVITE_PAS:
                    grant["last"] = horodate()
                    grant["last_ts"] = maintenant
                    change += 1
            if change:
                oauth_save(data)
        return set((entree.get("scope") or "").split()), None

    # ---- le transport MCP ------------------------------------------------

    def _mcp(self):
        # L'ORDRE compte : le jeton se vérifie AVANT toute lecture du corps.
        # Sinon un corps mal formé rendrait 400, et le client ne verrait jamais
        # d'invite d'authentification — seulement « injoignable ».
        hote = (self.headers.get("Host") or "").split(":")[0]
        attendu = urlparse(PUBLIC_BASE).hostname or ""
        if hote and attendu and hote != attendu and hote not in ("127.0.0.1", "localhost"):
            return self._json(400, {"error": "bad_host"})
        origine = self.headers.get("Origin")
        # Origin ABSENT est accepté : Claude appelle de serveur à serveur. Une
        # validation trop stricte est une cause documentée d'échec d'initialize.
        if origine and origine.rstrip("/") != PUBLIC_BASE:
            return self._json(403, {"error": "bad_origin"})

        portees, refus = self._porteur()
        if refus is not None:
            return refus

        ctype = (self.headers.get("Content-Type") or "").lower()
        if not ctype.startswith("application/json"):
            return self._json(415, {"error": "invalid_request"})
        brut = self._corps_borne(256 * 1024)
        if isinstance(brut, RefusCorps):
            return self._refus_corps(brut, en_json=True)
        try:
            message = json.loads(brut) if brut.strip() else None
        except ValueError:
            message = None
        if not isinstance(message, dict):
            return self._json(200, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "parse error"}})

        methode = message.get("method")
        mid = message.get("id")
        if isinstance(methode, str) and methode.startswith("notifications/"):
            # Une notification n'attend pas de réponse : 202 et zéro octet.
            return self._send(202, "", "text/plain; charset=utf-8")

        # La portée est vérifiée ICI, avant de laisser passer l'appel. Elle ne
        # remplace pas INFOMANIAK_WRITE : la portée dit ce que ce jeton a le
        # droit de demander, l'armement ce que ce déploiement accepte de faire.
        # Les deux doivent céder pour qu'une zone bouge.
        if methode == "tools/call":
            # Deux gardes, deux plantages prouvés : `params` non-objet — une
            # liste, une chaîne — n'a pas de `.get`, et un `name` non-hachable
            # — une liste, un objet — fait lever `BY_NAME.get`. L'exception
            # partait AVANT le contrôle de portée : connexion coupée, trace de
            # pile dans le journal, et le contrôle jamais atteint. Un contrôle
            # qu'un paramètre mal formé fait sauter n'est pas un contrôle.
            #
            # Ce qui est mal formé est REFUSÉ ICI, en -32602, plutôt que laissé
            # descendre. `handle()` s'en garde aussi de son côté — il est appelé
            # sur stdio, où ce transport ne le protège pas — mais il rendrait
            # alors « cet outil n'existe pas », c'est-à-dire un résultat d'outil
            # là où la faute est dans l'enveloppe. Ce n'est pas l'outil qui
            # manque : c'est la requête qui n'en nomme aucun.
            params = message.get("params")
            nom = params.get("name") if isinstance(params, dict) else None
            if not isinstance(params, dict) or not isinstance(nom, str):
                return self._json(200, {
                    "jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602,
                              "message": "params doit être un objet portant un "
                                         "name de type chaîne"}})
            outil = BY_NAME.get(nom)
            if outil is not None:
                exigee = portee_outil(outil)
                if exigee not in portees:
                    return self._json(403, {"error": "insufficient_scope"}, extra=[
                        ("WWW-Authenticate",
                         'Bearer error="insufficient_scope", scope="%s"' % exigee)])

        try:
            charge = infomaniak_mcp.handle(message)
        except ErreurInfomaniak as err:
            return self._json(200, {"jsonrpc": "2.0", "id": mid,
                                    "error": {"code": -32601, "message": str(err)}})
        except Exception as err:                      # noqa: BLE001
            # Un outil qui plante ne doit pas rendre un 500 : le client perdrait
            # la session entière pour l'erreur d'un seul appel.
            return self._json(200, {"jsonrpc": "2.0", "id": mid,
                                    "error": {"code": -32603,
                                              "message": "%s: %s" % (type(err).__name__, err)}})
        if mid is None or charge is None:
            return self._send(202, "", "text/plain; charset=utf-8")
        return self._json(200, {"jsonrpc": "2.0", "id": mid, "result": charge})

    # ---- le serveur d'autorisation ---------------------------------------

    def _exige_navigation(self):
        """Refuse ce qui n'est pas une navigation de premier plan. Rend None
        quand ça en est une, une réponse sinon.

        Le garde des pages GET qui ÉCRIVENT dans une table bornée. Une page
        hostile boucle sur une balise `<img>`, le navigateur rejoue le
        credential ambiant tout seul, et chaque chargement ajoute une entrée.
        Contre une table de 32 places, trente-deux chargements suffisent à
        évincer celle de Vincent.

        Sec-Fetch-Site n'entre PAS dans le contrôle, contrairement à /consent :
        Claude ouvre /authorize depuis claude.ai, donc en `cross-site` — la
        refuser fermerait le connecteur pour de bon. C'est `Dest: document` qui
        distingue une navigation d'un chargement d'image, et c'est là que vit
        la différence entre les deux pages. En-têtes absents, on laisse passer :
        un navigateur qui ne les envoie pas ne peut pas non plus fabriquer
        l'attaque, et une sonde en ligne de commande doit continuer de servir.

        **En un seul exemplaire, et c'est le correctif.** Le contrôle vivait
        recopié dans `_authorize()` seule ; `_accueil()` frappe pourtant, elle
        aussi, un jeton dans une table de 32 places — celle qui autorise la
        RÉVOCATION. Trente-deux chargements hostiles de `/` interdisaient donc
        à Vincent de révoquer quoi que ce soit, au moment précis où il en a
        besoin. Une garde recopiée est une garde qu'on oublie de recopier.
        """
        dest = self.headers.get("Sec-Fetch-Dest")
        mode = self.headers.get("Sec-Fetch-Mode")
        if (dest and dest != "document") or (mode and mode != "navigate"):
            return self._send(403, page_refus(
                "Ce n'est pas une navigation (%s)" % ((dest or mode)[:40]),
                "Cette page ne s'ouvre qu'en navigation de premier plan. Un "
                "chargement en arrière-plan n'exprime aucune intention."))
        return None

    def _authorize(self):
        """Rend un FORMULAIRE. N'émet jamais de code — c'est tout l'intérêt de
        le séparer de /consent."""
        if not self._humain_present():
            return self._defi_humain()

        refus = self._exige_navigation()
        if refus is not None:
            return refus

        q = self._query_stricte()
        if q is None:
            return self._send(400, page_refus(
                "Demande mal formée", "Un paramètre est répété."))

        # (1) et (2) AVANT toute redirection : tant que le client et l'adresse
        # de retour ne sont pas vérifiés, rediriger serait une porte ouverte.
        if q.get("client_id") != CLIENT_ID:
            return self._send(400, page_refus(
                "Client inconnu",
                "Cette demande ne vient pas d'un client connu de ce serveur."))
        redirect_uri = q.get("redirect_uri", "")
        # L'égalité stricte se teste sur la CHAÎNE, avant d'essayer de découper
        # quoi que ce soit : `urlparse` lève sur un crochet IPv6 non fermé, et
        # découper d'abord faisait planter la page sur une valeur qu'on
        # s'apprêtait de toute façon à refuser. Les contrôles qui suivent sont
        # des ceintures : l'adresse est déjà l'une des nôtres.
        morceau = analyse_url(redirect_uri)
        if (redirect_uri not in ALLOWED_REDIRECTS or morceau is None
                or morceau.fragment
                or morceau.username or morceau.password or ".." in redirect_uri):
            return self._send(400, page_refus(
                "Adresse de retour refusée",
                "Ce serveur ne remet de jeton qu'à une adresse connue."))

        state = str(q.get("state", ""))[:512]

        def refuser(erreur, description=""):
            return self._redirect(
                redirection_erreur(redirect_uri, erreur, state, description), code=302)

        if q.get("response_type") != "code":
            return refuser("unsupported_response_type")
        if q.get("code_challenge_method") != "S256":
            return refuser("invalid_request", "code_challenge_method doit valoir S256")
        challenge = q.get("code_challenge", "")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", challenge or ""):
            return refuser("invalid_request", "code_challenge absent ou mal formé")
        ressource = q.get("resource")
        if ressource and not ressource_connue(ressource):
            return refuser("invalid_target")
        scope = scopes_valides(q.get("scope"))
        if scope is None:
            return refuser("invalid_scope")

        csrf = jeton()
        with _oauth_lock:
            data, _ = oauth_frais()
            attente = data["pending"]
            # La borne, seconde moitié de la garde. Un humain n'a jamais
            # soixante-quatre consentements en cours ; au-delà, on évince la
            # plus proche de sa péremption — et sa fenêtre de grâce avec elle,
            # sinon la mémoire garderait une réponse dont la demande n'existe
            # plus.
            while len(attente) >= PENDING_MAX:
                vieille = min(attente, key=lambda k: float(attente[k].get("exp", 0)))
                del attente[vieille]
                _grace.pop(vieille, None)
            attente[empreinte(csrf)] = {
                "client_id": CLIENT_ID, "redirect_uri": redirect_uri,
                "code_challenge": challenge, "scope": scope,
                "resource": MCP_URL, "state": state,
                "exp": time.time() + PENDING_TTL}
            durable = oauth_save(data)
        if not durable:
            return self._send(500, page_refus(
                "Impossible d'enregistrer la demande",
                "Le volume n'est pas accessible en écriture."))
        return self._send(200, page_consentement(csrf, redirect_uri, scope), extra=[
            ("Content-Security-Policy",
             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
             "frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY")])

    def _consent(self):
        """Le SEUL endroit du programme qui émet un code d'autorisation."""
        if not self._humain_present():
            return self._defi_humain()
        # Une origine OPAQUE (« null ») n'est pas une origine étrangère : des
        # navigateurs l'envoient sur des navigations légitimes, et la refuser
        # bloque le consentement pour de bon — constaté sur le connecteur
        # voisin. La vraie défense contre le CSRF est le jeton à usage unique,
        # lié côté serveur à une demande précise ; ces en-têtes ne sont qu'une
        # ceinture de plus.
        origine = self.headers.get("Origin")
        if origine and origine != "null" and origine.rstrip("/") != PUBLIC_BASE:
            return self._send(403, page_refus(
                "Origine refusée",
                "Cette soumission annonce venir de %s, et non de ce serveur."
                % origine[:120]))
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return self._send(403, page_refus(
                "Soumission inter-site refusée (%s)" % site[:40],
                "Le mot de passe est rejoué automatiquement par le navigateur : "
                "une soumission venue d'ailleurs ne prouve rien."))
        form = self._form_stricte()
        if isinstance(form, RefusCorps):
            return self._refus_corps(form)
        if form is None:
            return self._send(400, page_refus("Demande mal formée", "Corps illisible."))

        # On ne lit QUE csrf et action. Tout le reste — adresse de retour,
        # challenge, portée — est relu depuis l'enregistrement serveur : c'est
        # ce qui rend inopérante l'auto-soumission d'un formulaire fabriqué,
        # qui changerait l'adresse de retour entre l'affichage et l'envoi.
        csrf = form.get("csrf", "")
        action = form.get("action", "")
        marque_csrf = empreinte(csrf)
        code = jeton()
        with _oauth_lock:
            data, retire = oauth_frais()
            demande = data["pending"].get(marque_csrf)
            if not isinstance(demande, dict):
                if retire:
                    oauth_save(data)
                return self._send(400, page_refus(
                    "Demande introuvable ou expirée",
                    "Relancez la connexion depuis Claude."))
            # Recharger la page REJOUE le POST. Répondre par une erreur laissait
            # l'utilisateur dans un cul-de-sac alors que son autorisation avait
            # abouti. On lui rend donc la MÊME réponse pendant une courte
            # fenêtre — le code reste à usage unique là où ça compte, à
            # l'échange.
            #
            # Deux choses ont changé ici, et chacune ferme une faille prouvée :
            #
            # - la réponse ne vit plus dans le fichier. Elle porte le code en
            #   CLAIR, quand `empreinte()` promet noir sur blanc qu'un état volé
            #   ne donne aucun jeton utilisable — instantané du PVC, kubectl
            #   exec, kubectl cp. Le fichier ne garde que l'empreinte du code
            #   émis ; l'URL vit en mémoire, avec la même péremption.
            # - on ne re-livre qu'un code encore VIERGE. Le geste même pour
            #   lequel la grâce existe — recharger la page — rendait un code
            #   déjà échangé ; l'échanger une seconde fois révoque toute la
            #   famille et tue l'autorisation qui marchait.
            #
            # Le prix, assumé : après un redémarrage, la mémoire est vide et la
            # grâce ne joue plus. Recharger rend alors ce refus-ci plutôt que
            # l'ancienne réponse — l'autorisation déjà partie chez Claude,
            # elle, n'est pas touchée.
            if demande.get("code") or demande.get("reponse"):
                emis = data["codes"].get(demande.get("code") or "")
                grace = memoire_lire(_grace, marque_csrf)
                if (grace is None or not isinstance(emis, dict)
                        or emis.get("used")):
                    return self._send(400, page_refus(
                        "Autorisation déjà aboutie",
                        "Ce consentement a déjà rendu son code, et il ne se "
                        "rend qu'une fois. Relancez la connexion depuis Claude."))
                return self._redirect(grace["reponse"], code=302)
            if action != "autoriser":
                del data["pending"][marque_csrf]
                oauth_save(data)
                return self._redirect(redirection_erreur(
                    demande["redirect_uri"], "access_denied", demande.get("state", "")),
                    code=302)
            grant_id = jeton()
            marque_code = empreinte(code)
            data["codes"][marque_code] = {
                "client_id": demande["client_id"], "redirect_uri": demande["redirect_uri"],
                "code_challenge": demande["code_challenge"], "scope": demande["scope"],
                "resource": demande["resource"], "grant_id": grant_id,
                "exp": time.time() + CODE_TTL, "used": False}
            # Une autorisation PÉRIT, et elle est PLAFONNÉE. Elle ne faisait
            # ni l'un ni l'autre : `oauth_menage()` ne l'a jamais vue et
            # `oauth_revoquer()` la marquait sans la retirer, si bien que la
            # seule table qu'aucun mécanisme ne vidait était aussi la seule à
            # ne pas se périmer. Sa péremption est celle de la chaîne qu'elle
            # peut engendrer : au-delà, plus aucun jeton n'en descend, donc
            # elle ne répond plus à personne.
            attentes = data["grants"]
            while len(attentes) >= GRANTS_MAX:
                del attentes[min(attentes, key=lambda k: peremption(
                    attentes[k] if isinstance(attentes[k], dict) else {}))]
            attentes[grant_id] = {
                "created": horodate(), "last": horodate(), "last_ts": time.time(),
                "scope": demande["scope"], "exp": time.time() + GRANT_TTL,
                "redirect_uri": demande["redirect_uri"], "revoked": ""}
            champs = {"code": code, "iss": PUBLIC_BASE}
            if demande.get("state"):
                champs["state"] = demande["state"]
            joint = "&" if "?" in demande["redirect_uri"] else "?"
            reponse = demande["redirect_uri"] + joint + urlencode(champs)
            # La demande n'est pas supprimée : elle retient l'EMPREINTE du code
            # qu'elle a servi — de quoi reconnaître un rechargement et savoir si
            # ce code est encore vierge — puis expire comme le reste.
            demande.pop("reponse", None)      # un état écrit par la version d'avant
            demande["code"] = marque_code
            demande["exp"] = time.time() + REJEU_TTL
            durable = oauth_save(data)
            if durable:
                # Après l'écriture, jamais avant : la mémoire ne doit pas
                # promettre une réponse dont le code n'est pas persisté.
                memoire_poser(_grace, marque_csrf,
                              {"reponse": reponse, "exp": time.time() + REJEU_TTL},
                              GRACE_MAX)
        if not durable:
            # Un code non persisté est un code rejouable indéfiniment : on
            # préfère échouer bruyamment que d'en émettre un.
            return self._send(500, page_refus(
                "Impossible d'enregistrer l'autorisation",
                "Aucun code n'a été émis."))
        return self._redirect(reponse, code=302)

    def _token(self):
        ctype = (self.headers.get("Content-Type") or "").lower()
        if not ctype.startswith("application/x-www-form-urlencoded"):
            return self._json(415, {"error": "invalid_request",
                                    "error_description": "form-urlencoded attendu"})
        form = self._form_stricte()
        if isinstance(form, RefusCorps):
            return self._refus_corps(form, en_json=True)
        if form is None:
            return self._json(400, {"error": "invalid_request"})
        # RFC 8707 : si le client nomme la ressource, elle doit être la nôtre.
        # Le contrôle vaut aux deux bouts — ici, et au moment de présenter le
        # jeton (`_porteur`), qui refuse une autre audience.
        ressource = form.get("resource")
        if ressource and not ressource_connue(ressource):
            return self._json(400, {"error": "invalid_target"})
        genre = form.get("grant_type")
        if genre == "authorization_code":
            return self._token_code(form)
        if genre == "refresh_token":
            return self._token_refresh(form)
        return self._json(400, {"error": "unsupported_grant_type"})

    def _emettre(self, data, grant_id, scope, aud, chain_exp=None):
        """Émet une paire de jetons. Appelé SOUS le verrou, jamais hors de lui.

        **L'audience est un ARGUMENT, et c'est tout l'objet du correctif.**
        Elle valait `MCP_URL`, c'est-à-dire la configuration du processus au
        moment d'émettre — la même que celle que `_porteur()` compare au moment
        de présenter. Deux lectures de la même variable ne peuvent pas
        diverger : le contrôle d'audience était une TAUTOLOGIE, verte quoi
        qu'il arrive, et le champ `resource` que `/authorize` prend soin
        d'enregistrer n'était lu par personne.

        Elle vient donc désormais de l'AUTORISATION — le code, puis le jeton de
        rafraîchissement qui en descend. Ce que le jeton porte est ce pour quoi
        il a été demandé ; ce que `_porteur()` exige est ce que ce serveur-ci
        sert. Les deux peuvent différer, donc le contrôle existe.
        """
        acces, rafraichir = jeton(), jeton()
        maintenant = time.time()
        data["access"][empreinte(acces)] = {
            "grant_id": grant_id, "scope": scope, "aud": aud,
            "exp": maintenant + ACCESS_TTL}
        fin_chaine = chain_exp or (maintenant + REFRESH_TTL)
        data["refresh"][empreinte(rafraichir)] = {
            "grant_id": grant_id, "scope": scope, "used": False, "aud": aud,
            "chain_exp": fin_chaine, "exp": fin_chaine}
        return acces, rafraichir

    def _token_code(self, form):
        """Tout se joue dans UNE SEULE prise de verrou. La découper laisserait
        passer deux requêtes concurrentes porteuses du même code : sous
        ThreadingHTTPServer, toutes deux vérifieraient avant qu'aucune n'ait
        écrit, et chacune repartirait avec des jetons."""
        code = form.get("code", "")
        verifier = form.get("code_verifier", "")
        # Un code_verifier absent est refusé INCONDITIONNELLEMENT. « On ne
        # vérifie que si un challenge était enregistré » est le contournement le
        # plus fréquent des serveurs d'autorisation écrits à la main.
        if not verifier or not code:
            return self._json(400, {"error": "invalid_grant",
                                    "error_description": "code et code_verifier requis"})
        # La FORME du verifier, exigée avant de le hacher, et hors du verrou.
        #
        # `encode("ascii", "ignore")` laissait tomber en silence tout caractère
        # hors ASCII : « abc…def » et « abcdef » se hachaient pareil, donc un
        # verifier DIFFÉRENT de celui qui avait demandé le code passait le
        # contrôle. PKCE n'existe que pour prouver ce point-là. La grammaire du
        # RFC 7636 §4.1 — 43 à 128 caractères non réservés — n'était par
        # ailleurs vérifiée nulle part : ce qui la respecte est forcément
        # ASCII, et l'encodage se fait ensuite sans échappatoire.
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            return self._json(400, {"error": "invalid_grant",
                                    "error_description": "code_verifier mal formé"})
        with _oauth_lock:
            data, retire = oauth_frais()
            entree = data["codes"].get(empreinte(code))
            if not isinstance(entree, dict):
                # `if retire`, ici et à chaque refus : ce chemin est public et
                # anonyme, et persister sans que rien n'ait changé donnait une
                # réécriture complète du PVC par requête — sous le verrou que
                # /mcp doit prendre pour valider le moindre Bearer.
                if retire:
                    oauth_save(data)
                return self._json(400, {"error": "invalid_grant"})
            if entree.get("used"):
                # Rejeu détecté : on révoque TOUT ce qui découle de ce code.
                oauth_revoquer(data, entree.get("grant_id"))
                oauth_save(data)
                return self._json(400, {"error": "invalid_grant",
                                        "error_description": "code déjà utilisé"})
            if (form.get("client_id") != entree.get("client_id")
                    or form.get("redirect_uri") != entree.get("redirect_uri")):
                if retire:
                    oauth_save(data)
                return self._json(400, {"error": "invalid_grant"})
            attendu = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            ).rstrip(b"=").decode()
            if not hmac.compare_digest(attendu, entree.get("code_challenge", "")):
                if retire:
                    oauth_save(data)
                return self._json(400, {"error": "invalid_grant",
                                        "error_description": "code_verifier invalide"})
            # Gardé, marqué : c'est l'entrée conservée qui permettra de
            # RECONNAÎTRE un rejeu, au lieu de le prendre pour un code inconnu.
            entree["used"] = True
            acces, rafraichir = self._emettre(
                data, entree["grant_id"], entree["scope"],
                # `or MCP_URL` : un code écrit par la version d'avant n'a pas
                # d'audience à porter, et déconnecter Claude pour ça serait un
                # correctif qui coûte plus cher que la faille.
                entree.get("resource") or MCP_URL)
            durable = oauth_save(data)
        if not durable:
            return self._json(500, {"error": "server_error"})
        return self._json(200, {"access_token": acces, "token_type": "Bearer",
                                "expires_in": ACCESS_TTL, "refresh_token": rafraichir,
                                "scope": entree["scope"]},
                          extra=[("Pragma", "no-cache")])

    def _token_refresh(self, form):
        presente = form.get("refresh_token", "")
        if not presente:
            return self._json(400, {"error": "invalid_grant"})
        with _oauth_lock:
            data, retire = oauth_frais()
            entree = data["refresh"].get(empreinte(presente))
            if not isinstance(entree, dict):
                if retire:
                    oauth_save(data)
                return self._json(400, {"error": "invalid_grant"})
            if entree.get("used"):
                # Un jeton de rafraîchissement déjà tourné qui revient : soit il
                # a été volé, soit le vrai client rejoue. Dans le doute on coupe
                # toute la famille — c'est la conduite prescrite, et la seule
                # qui ne laisse pas le voleur et le propriétaire coexister.
                oauth_revoquer(data, entree.get("grant_id"))
                oauth_save(data)
                return self._json(400, {"error": "invalid_grant",
                                        "error_description": "jeton déjà utilisé"})
            grant = data["grants"].get(entree.get("grant_id")) or {}
            if grant.get("revoked"):
                if retire:
                    oauth_save(data)
                return self._json(400, {"error": "invalid_grant"})
            # La portée se valide AVANT de consommer le jeton. Sinon un refus
            # brûle un jeton parfaitement valide : l'usage légitime suivant est
            # alors lu comme un rejeu, et révoque toute la famille. Un refus ne
            # doit consommer aucun jeton — trouvé par audit adverse le
            # 2026-08-31.
            scope = entree["scope"]
            demande = form.get("scope")
            if demande:
                # Jamais élargie. Demander plus large est une erreur du client,
                # pas une négociation : on refuse plutôt que de rogner en
                # silence, pour qu'il sache que sa demande n'a pas été honorée.
                accorde = set(scope.split())
                voulu = set(demande.split())
                if not voulu <= accorde:
                    return self._json(400, {
                        "error": "invalid_scope",
                        "error_description": "portée non accordée : %s"
                                             % " ".join(sorted(voulu - accorde))})
                if not voulu:
                    return self._json(400, {"error": "invalid_scope"})
                scope = " ".join(sorted(voulu))
            # La PIERRE TOMBALE, et sa péremption. L'entrée reste — c'est elle
            # qui permettra de reconnaître un rejeu au lieu de le prendre pour
            # un jeton inconnu — mais elle ne reste plus quatre-vingt-dix
            # jours : chaque rotation en laissait une, et rien ne les retirait
            # jamais. Une heure suffit à ce pour quoi elle existe.
            entree["used"] = True
            tombe = time.time() + TOMBE_TTL
            entree["exp"] = min(peremption(entree, tombe), tombe)
            acces, neuf = self._emettre(data, entree["grant_id"], scope,
                                        entree.get("aud") or MCP_URL,
                                        chain_exp=entree.get("chain_exp"))
            grant["last"] = horodate()
            grant["last_ts"] = time.time()
            durable = oauth_save(data)
        if not durable:
            return self._json(500, {"error": "server_error"})
        return self._json(200, {"access_token": acces, "token_type": "Bearer",
                                "expires_in": ACCESS_TTL, "refresh_token": neuf,
                                "scope": scope}, extra=[("Pragma", "no-cache")])

    def _register(self):
        """Sans état et idempotent — c'est le pivot de sécurité de tout le reste.
        On n'écrit rien, donc rien à inonder ; on n'accepte qu'une adresse de
        retour connue, donc rien d'hostile à enregistrer ; et on ne renvoie
        aucune donnée fournie par le client, donc rien à afficher plus tard.
        Quatre failles meurent par construction plutôt que par correctif."""
        brut = self._corps_borne(16384)
        if isinstance(brut, RefusCorps):
            return self._refus_corps(brut, en_json=True)
        try:
            demande = json.loads(brut) if brut.strip() else None
        except ValueError:
            demande = None
        if not isinstance(demande, dict):
            return self._json(400, {"error": "invalid_client_metadata",
                                    "error_description": "corps JSON attendu"})
        voulues = demande.get("redirect_uris")
        voulues = [x for x in voulues if isinstance(x, str)] if isinstance(voulues, list) else []
        # Journalisé volontairement : c'est le seul moyen fiable de savoir
        # quelles adresses de retour Claude déclare réellement. Aucun secret
        # là-dedans — et c'est précisément ce qui manquait pour diagnostiquer le
        # connecteur voisin.
        print("register: redirect_uris=%r" % (voulues,), flush=True)
        gardees = [x for x in voulues if x in ALLOWED_REDIRECTS]
        if not gardees:
            return self._json(400, {
                "error": "invalid_redirect_uri",
                "error_description": "ce serveur ne remet de jeton qu'à : "
                                     + ", ".join(ALLOWED_REDIRECTS)})
        return self._json(201, {
            "client_id": CLIENT_ID,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": gardees,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"})

    def _revoke(self):
        """Couper une autorisation, ou toutes.

        N'est pas dans la liste de la spec, et n'est PAS exempté de
        l'authentification humaine. Sans lui, révoquer un rafraîchissement qui
        vit quatre-vingt-dix jours demanderait d'aller éditer un JSON dans le
        conteneur — un geste qu'on ne fait pas dans l'urgence, donc un accès
        qu'on ne coupe pas.
        """
        if not self._humain_present():
            return self._defi_humain()
        # Les trois mêmes contrôles que /consent, et pour la même raison : le
        # credential ambiant que le navigateur rejoue seul sur une soumission
        # inter-site. /consent les avait, /revoke non — l'écart n'était pas
        # voulu, et une page hostile coupait d'un POST toutes les autorisations
        # du connecteur. Une origine OPAQUE reste acceptée, comme là-bas : des
        # navigateurs l'envoient sur des navigations légitimes.
        origine = self.headers.get("Origin")
        if origine and origine != "null" and origine.rstrip("/") != PUBLIC_BASE:
            return self._send(403, page_refus(
                "Origine refusée",
                "Cette soumission annonce venir de %s, et non de ce serveur."
                % origine[:120]))
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return self._send(403, page_refus(
                "Soumission inter-site refusée (%s)" % site[:40],
                "Le mot de passe est rejoué automatiquement par le navigateur : "
                "une soumission venue d'ailleurs ne prouve rien."))
        form = self._form_stricte()
        if isinstance(form, RefusCorps):
            return self._refus_corps(form)
        if form is None:
            return self._send(400, page_refus("Demande mal formée", "Corps illisible."))
        vise = form.get("grant", "")
        with _oauth_lock:
            # La vraie défense : un jeton à usage unique, émis par la page
            # elle-même. Il est consommé AVANT de regarder ce qu'on révoque, et
            # même s'il est périmé — sinon un rejeu le laisserait en place pour
            # l'essai suivant.
            if memoire_consommer(_csrf_revoke, empreinte(form.get("csrf", ""))) is None:
                return self._send(400, page_refus(
                    "Demande périmée",
                    "Ce bouton vient d'une page trop ancienne, ou d'ailleurs. "
                    "Rechargez la page et recommencez ; rien n'a été révoqué."))
            data, retire = oauth_frais()
            if vise == "tout":
                for gid in list(data["grants"]):
                    oauth_revoquer(data, gid)
                coupe = bool(data["grants"])
            else:
                coupe = vise in data["grants"]
                if coupe:
                    oauth_revoquer(data, vise)
            if coupe or retire:
                oauth_save(data)
        return self._redirect("/")

    def _accueil(self):
        if not self._humain_present():
            return self._defi_humain()
        # Le MÊME contrôle que /authorize, et pour la même raison : cette page
        # frappe un jeton anti-CSRF dans `_csrf_revoke`, bornée à REVOKE_MAX.
        # Sans lui, trente-deux chargements hostiles évinçaient le jeton de
        # Vincent et lui interdisaient de révoquer — le correctif de D5 avait
        # créé la table sans lui donner sa garde.
        refus = self._exige_navigation()
        if refus is not None:
            return refus
        csrf = jeton()
        with _oauth_lock:
            data, _ = oauth_frais()
            vivants = sorted(
                ((gid, g) for gid, g in data["grants"].items()
                 if isinstance(g, dict) and not g.get("revoked")),
                key=lambda paire: paire[1].get("created", ""), reverse=True)
            memoire_poser(_csrf_revoke, empreinte(csrf),
                          {"exp": time.time() + REVOKE_TTL}, REVOKE_MAX)
        return self._send(200, page_accueil(vivants, csrf), extra=[
            ("Content-Security-Policy",
             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
             "frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY")])

    def _whoami(self):
        """Quel artefact tourne ici — et rien d'autre.

        SANS authentification humaine, délibérément. La question « la
        production correspond-elle au dépôt ? » se pose depuis l'extérieur,
        souvent quand quelque chose cloche, et une réponse qu'il faut
        déverrouiller n'est pas consultée : on suppose à la place, et une
        supposition coûte plus cher qu'une question. Chez le dépôt voisin, un
        `ETAT.md` a affirmé pendant des semaines que la prod correspondait au
        dépôt alors que le ConfigMap servait une variante divergente.
        Comparer :

            curl -s https://domains.mcp.ephais.eu/_whoami
            git show HEAD:serveur.py | shasum -a 256

        Ce qui est servi n'apprend rien à qui n'a pas le mot de passe : le
        code est public, sa version aussi, et l'armement se lit déjà sur la
        page de consentement de quiconque autorise le connecteur. Ce qui n'y
        est PAS, et n'y sera pas : le jeton Infomaniak et jusqu'à son existence,
        le compte épinglé — un numéro de client, qui n'a rien à faire dehors —
        et toute donnée d'autorisation, codes, jetons, familles ou même leur
        nombre, qui dirait à un inconnu quand quelqu'un vient de se connecter.

        `marque_proxy` dit seulement si le garde-fou de D1 est armé. Le taire
        ne protégerait rien — un serveur sans marque REFUSE tout ce qui ne
        vient pas de lui-même — et l'annoncer donne le seul moyen de constater
        de dehors qu'un déploiement est bien fermé.
        """
        return self._json(200, {
            "service": infomaniak_mcp.NAME,
            "version": infomaniak_mcp.VERSION,
            "code": EMPREINTE_CODE,
            "fichiers": EMPREINTES_FICHIERS,
            "public_base": PUBLIC_BASE,
            "ecriture_armee": infomaniak_mcp.ecriture_armee(),
            "achat_arme": infomaniak_mcp.achat_arme(),
            "marque_proxy": bool(MARQUE_PROXY),
        })

    # ---- routage ---------------------------------------------------------

    def do_GET(self):
        chemin = chemin_demande(self.path)

        if chemin == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")

        if chemin == "/_whoami":
            return self._whoami()

        if chemin in ("/.well-known/oauth-protected-resource",
                      "/.well-known/oauth-protected-resource/mcp"):
            return self._json(200, metadonnees_ressource(), cache="public, max-age=300")

        if chemin in ("/.well-known/oauth-authorization-server",
                      "/.well-known/openid-configuration"):
            return self._json(200, metadonnees_autorisation(), cache="public, max-age=300")

        if chemin == "/authorize":
            return self._authorize()

        if chemin == "/mcp":
            # Ce transport ne fait que du POST. On valide quand même le jeton
            # d'abord : un anonyme doit récolter 401 ici comme ailleurs, sans
            # quoi la sonde de frontière lirait un 405 et croirait le chemin
            # protégé alors qu'il répond à tout le monde.
            _, refus = self._porteur()
            if refus is not None:
                return refus
            return self._json(405, {"error": "method_not_allowed",
                                    "error_description": "POST attendu"},
                              extra=[("Allow", "POST")])

        if chemin == "/":
            return self._accueil()

        return self._send(404, page_refus("Introuvable", "Ce chemin n'existe pas."))

    def do_POST(self):
        chemin = chemin_demande(self.path)

        if chemin == "/mcp":
            return self._mcp()
        if chemin == "/token":
            return self._token()
        if chemin == "/register":
            return self._register()
        if chemin == "/consent":
            return self._consent()
        if chemin == "/revoke":
            return self._revoke()

        # /authorize en POST n'existe pas : c'est /consent, et lui seul, qui
        # émet un code. Confondre les deux est exactement la faille qu'on évite.
        return self._send(404, page_refus("Introuvable", "Ce chemin n'existe pas."))

    def do_HEAD(self):
        return self.do_GET()

    def do_DELETE(self):
        chemin = chemin_demande(self.path)
        if chemin == "/mcp":
            # Claude ferme parfois une session par DELETE. Ce transport est sans
            # session : rien à fermer, mais répondre proprement évite qu'un
            # client conclue à une panne.
            _, refus = self._porteur()
            if refus is not None:
                return refus
            return self._send(204, "", "text/plain; charset=utf-8")
        return self._send(404, page_refus("Introuvable", "Ce chemin n'existe pas."))


# --------------------------------------------------------------------------
# démarrage
# --------------------------------------------------------------------------

def main():
    if not os.environ.get("INFOMANIAK_PUBLIC_BASE", "").strip():
        # Pas fatal — on veut pouvoir lancer un serveur jetable pour les tests —
        # mais il faut le dire : des documents de découverte qui annoncent
        # 127.0.0.1 envoient Claude s'adresser à lui-même.
        print("ATTENTION : INFOMANIAK_PUBLIC_BASE n'est pas posé ; toutes les "
              "URL publiques vaudront %s, ce qui ne convient qu'en local."
              % PUBLIC_BASE, flush=True)

    if not MARQUE_PROXY:
        # Le vide alarme, et il alarme fort : sans marque, /, /authorize,
        # /consent et /revoke ne répondent qu'à la boucle locale. En bac à
        # sable c'est ce qu'on veut ; en production, personne ne pourra
        # autoriser Claude, et il faut que la cause tienne dans la première
        # ligne du journal plutôt que dans une demi-journée de diagnostic.
        print("ALARME : INFOMANIAK_MARQUE_PROXY n'est pas posé. Les pages "
              "humaines (/, /authorize, /consent, /revoke) ne s'ouvriront QUE "
              "depuis la boucle locale — c'est-à-dire à personne, derrière un "
              "proxy. Poser la même valeur ici et dans le middleware Traefik "
              "qui écrase l'en-tête %s." % ENTETE_MARQUE, flush=True)

    serveur = ThreadingHTTPServer(("", PORT), Poignee)
    serveur.daemon_threads = True
    tri = outils_par_portee()
    print("infomaniak-domains %s — %s (écoute :%d) ; %d outils en lecture, "
          "%d en écriture ; état OAuth dans %s"
          % (infomaniak_mcp.VERSION, PUBLIC_BASE, PORT,
             len(tri[SCOPE_LIRE]), len(tri[SCOPE_ECRIRE]), OAUTH_PATH), flush=True)
    print(etat_armement(), flush=True)
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        serveur.server_close()


if __name__ == "__main__":
    main()
