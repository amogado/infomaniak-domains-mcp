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

_oauth_lock = threading.Lock()

# Les sept chemins qui sortent de l'authentification humaine, énumérés ici pour
# que le dépôt et l'Ingress se lisent l'un contre l'autre. Le serveur ne s'en
# sert pas pour décider : c'est Traefik qui tient la frontière, en `pathType:
# Exact`. `Prefix` s'y traduit par un préfixe de **chaîne**, donc exempter
# « /mcp » exempterait aussi « /mcpXXX ».
CHEMINS_MACHINE = (
    "/mcp", "/token", "/register",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
)


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


def oauth_menage(data, maintenant=None):
    """Écarte ce qui a expiré. Un code consommé est GARDÉ jusqu'à sa péremption :
    c'est ce qui permet de DÉTECTER un rejeu au lieu de le confondre avec un
    code inconnu — et un rejeu confondu avec une erreur banale ne révoquerait
    rien."""
    now = maintenant if maintenant is not None else time.time()
    for cle in ("pending", "codes", "access", "refresh"):
        data[cle] = {k: v for k, v in data[cle].items()
                     if isinstance(v, dict) and float(v.get("exp", 0)) > now}
    return data


def oauth_revoquer(data, grant_id):
    """Révoque tout ce qui découle d'une même autorisation. Couper le seul jeton
    présenté laisserait vivre le reste de la famille, donc l'accès volé."""
    for cle in ("access", "refresh", "codes"):
        data[cle] = {k: v for k, v in data[cle].items() if v.get("grant_id") != grant_id}
    grant = data["grants"].get(grant_id)
    if isinstance(grant, dict):
        grant["revoked"] = horodate()


def scopes_valides(demande):
    """Le sous-ensemble demandé, ou None s'il sort de ce qu'on sait accorder."""
    if not demande:
        return SCOPES_DEFAUT
    demandes = [x for x in str(demande).split() if x]
    if not demandes or any(x not in SCOPES for x in demandes):
        return None
    return " ".join(demandes)


def canoniser_ressource(valeur):
    """Compare deux URL de ressource sans se faire piéger par la casse, un port
    par défaut, un fragment ou un slash final."""
    morceau = urlparse(str(valeur))
    hote = (morceau.hostname or "").lower()
    schema = (morceau.scheme or "").lower()
    port = morceau.port
    if port and not ((schema == "https" and port == 443) or (schema == "http" and port == 80)):
        hote = "%s:%d" % (hote, port)
    chemin = (morceau.path or "").rstrip("/")
    return "%s://%s%s" % (schema, hote, chemin)


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


def page_accueil(grants):
    """La page « Connecter Claude ». Derrière l'authentification humaine.

    Elle montre l'état réel du déploiement plutôt que ce qu'on croit avoir
    déployé : un jeton d'API absent ne se voit sinon qu'au premier appel
    d'outil, sous la forme d'une erreur qui semble venir de Claude.
    """
    tri = outils_par_portee()
    epingle = infomaniak_mcp.compte_epingle()
    # On regarde si un jeton est configuré, et RIEN de plus : ni sa valeur, ni
    # sa longueur, qui en dirait déjà sur sa forme.
    porteur = "oui" if infomaniak_mcp.jeton() else "NON — aucun outil ne pourra répondre"

    if grants:
        rangees = "".join(
            "<tr><td>%s</td><td>%s</td><td class=\"mono\">%s</td><td>"
            "<form method=\"post\" action=\"/revoke\">"
            "<input type=\"hidden\" name=\"grant\" value=\"%s\">"
            "<button class=\"petit\" type=\"submit\">Révoquer</button>"
            "</form></td></tr>"
            % (html.escape(g.get("created", "")), html.escape(g.get("last", "")),
               html.escape(g.get("scope", "")), html.escape(gid, quote=True))
            for gid, g in grants)
        table = ("<table><tr><th>accordée</th><th>vue</th><th>portée</th><th></th></tr>"
                 "%s</table>"
                 "<form method=\"post\" action=\"/revoke\" style=\"margin-top:1rem\">"
                 "<input type=\"hidden\" name=\"grant\" value=\"tout\">"
                 "<button class=\"non\" type=\"submit\">Tout révoquer</button></form>"
                 % rangees)
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
        chemin = urlparse(self.path or "").path
        print("%s %s %s" % (horodate(), self.command or "?", chemin), flush=True)

    def _fin_de_reponse(self):
        """Rend True — pour que `return self._json(...)` interrompe vraiment le
        traitement — et coupe la connexion si un corps annoncé n'a pas été lu.

        Les deux moitiés répondent à deux failles jumelles, trouvées par audit
        adverse le 2026-08-31 et l'une comme l'autre prouvées :

        - sans valeur de retour, `if refus is not None: return refus` ne se
          déclenchait jamais : le 401 partait, puis le traitement continuait et
          un anonyme recevait un 200 complet sur /mcp ;
        - un corps annoncé et non consommé reste dans le tampon et se fait lire
          comme une requête pipelinée : `GET /mcp` avec un corps faisait servir
          une requête clandestine sur un chemin protégé.
        """
        try:
            annonce = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            annonce = -1
        if annonce != 0 and not getattr(self, "_corps_consomme", False):
            self.close_connection = True
        return True

    def _send(self, code, corps, ctype="text/html; charset=utf-8", extra=None):
        octets = corps.encode("utf-8") if isinstance(corps, str) else corps
        self.send_response(code)
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
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(octets)))
        self.send_header("Cache-Control", cache or "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for nom, valeur in extra or ():
            self.send_header(nom, valeur)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(octets)
            return self._fin_de_reponse()

    def _redirect(self, location, code=303):
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return self._fin_de_reponse()

    # ---- entrées ---------------------------------------------------------

    def _corps_borne(self, limite):
        """Rend le corps, "" s'il n'y en a pas, ou le témoin "trop-gros".

        Une borne explicite, parce que rien d'autre n'en pose : sans elle, un
        Content-Length de plusieurs gigaoctets tiendrait un thread et la
        mémoire du conteneur.
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
            return "trop-gros"
        brut = self.rfile.read(taille).decode("utf-8", "replace")
        # Le témoin dit que le tampon est vide : sans lui, un corps annoncé et
        # jamais lu se ferait interpréter comme une requête pipelinée.
        self._corps_consomme = True
        return brut

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
        return self._stricte(urlparse(self.path).query)

    def _form_stricte(self):
        brut = self._corps_borne(64 * 1024)
        if brut == "trop-gros":
            return None
        return self._stricte(brut)

    # ---- l'authentification humaine, tenue devant --------------------------

    def _humain_present(self):
        """Une trace d'authentification humaine posée par le proxy.

        Le mot de passe est vérifié par Traefik, pas ici : ce contrôle ne prouve
        donc rien à lui seul, et n'est pas la barrière. Il existe pour qu'une
        exemption de frontière posée par erreur sur /authorize ou /consent se
        solde par un 401 visible plutôt que par un code d'autorisation émis à
        un inconnu — c'est-à-dire pour que l'erreur se voie.
        """
        brut = self.headers.get("Authorization") or ""
        if brut.startswith("Basic "):
            return True
        # oauth2-proxy, si l'authentification humaine bascule un jour, ne
        # repasse pas de Basic : il pose l'identité en en-tête.
        return bool(self.headers.get("X-Forwarded-User")
                    or self.headers.get("X-Auth-Request-User"))

    def _defi_humain(self):
        return self._send(401, page_refus(
            "Authentification requise",
            "Cette page est réservée au propriétaire du serveur."),
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
        """Le jeton présenté, validé. Rend (portées, None) ou (None, réponse)."""
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
            data = oauth_menage(oauth_load())
            entree = data["access"].get(empreinte(brut[7:].strip()))
            if not isinstance(entree, dict):
                return None, self._defi_bearer("invalid_token")
            if entree.get("aud") != MCP_URL:
                return None, self._defi_bearer("invalid_token",
                                               "jeton émis pour une autre ressource")
            grant = data["grants"].get(entree.get("grant_id")) or {}
            if grant.get("revoked"):
                return None, self._defi_bearer("invalid_token", "autorisation révoquée")
            grant["last"] = horodate()
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
        if brut == "trop-gros":
            return self._json(413, {"error": "invalid_request"})
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
            nom = (message.get("params") or {}).get("name")
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

    def _authorize(self):
        """Rend un FORMULAIRE. N'émet jamais de code — c'est tout l'intérêt de
        le séparer de /consent."""
        if not self._humain_present():
            return self._defi_humain()
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
        morceau = urlparse(redirect_uri)
        if (redirect_uri not in ALLOWED_REDIRECTS or morceau.fragment
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
        if ressource and canoniser_ressource(ressource) != canoniser_ressource(MCP_URL):
            return refuser("invalid_target")
        scope = scopes_valides(q.get("scope"))
        if scope is None:
            return refuser("invalid_scope")

        csrf = jeton()
        with _oauth_lock:
            data = oauth_menage(oauth_load())
            data["pending"][empreinte(csrf)] = {
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
        if form is None:
            return self._send(400, page_refus("Demande mal formée", "Corps illisible."))

        # On ne lit QUE csrf et action. Tout le reste — adresse de retour,
        # challenge, portée — est relu depuis l'enregistrement serveur : c'est
        # ce qui rend inopérante l'auto-soumission d'un formulaire fabriqué,
        # qui changerait l'adresse de retour entre l'affichage et l'envoi.
        csrf = form.get("csrf", "")
        action = form.get("action", "")
        code = jeton()
        with _oauth_lock:
            data = oauth_menage(oauth_load())
            demande = data["pending"].get(empreinte(csrf))
            if not isinstance(demande, dict):
                return self._send(400, page_refus(
                    "Demande introuvable ou expirée",
                    "Relancez la connexion depuis Claude."))
            # Recharger la page REJOUE le POST. Répondre par une erreur laissait
            # l'utilisateur dans un cul-de-sac alors que son autorisation avait
            # abouti. On lui rend donc la MÊME réponse pendant une courte
            # fenêtre — le code reste à usage unique là où ça compte, à
            # l'échange.
            if demande.get("reponse"):
                return self._redirect(demande["reponse"], code=302)
            if action != "autoriser":
                del data["pending"][empreinte(csrf)]
                oauth_save(data)
                return self._redirect(redirection_erreur(
                    demande["redirect_uri"], "access_denied", demande.get("state", "")),
                    code=302)
            grant_id = jeton()
            data["codes"][empreinte(code)] = {
                "client_id": demande["client_id"], "redirect_uri": demande["redirect_uri"],
                "code_challenge": demande["code_challenge"], "scope": demande["scope"],
                "resource": demande["resource"], "grant_id": grant_id,
                "exp": time.time() + CODE_TTL, "used": False}
            data["grants"][grant_id] = {
                "created": horodate(), "last": horodate(), "scope": demande["scope"],
                "redirect_uri": demande["redirect_uri"], "revoked": ""}
            champs = {"code": code, "iss": PUBLIC_BASE}
            if demande.get("state"):
                champs["state"] = demande["state"]
            joint = "&" if "?" in demande["redirect_uri"] else "?"
            reponse = demande["redirect_uri"] + joint + urlencode(champs)
            # La demande n'est pas supprimée : elle garde sa réponse le temps de
            # la fenêtre de grâce, puis expire comme le reste.
            demande["reponse"] = reponse
            demande["exp"] = time.time() + REJEU_TTL
            durable = oauth_save(data)
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
        if form is None:
            return self._json(400, {"error": "invalid_request"})
        # RFC 8707 : si le client nomme la ressource, elle doit être la nôtre.
        # Le contrôle vaut aux deux bouts — ici, et au moment de présenter le
        # jeton (`_porteur`), qui refuse une autre audience.
        ressource = form.get("resource")
        if ressource and canoniser_ressource(ressource) != canoniser_ressource(MCP_URL):
            return self._json(400, {"error": "invalid_target"})
        genre = form.get("grant_type")
        if genre == "authorization_code":
            return self._token_code(form)
        if genre == "refresh_token":
            return self._token_refresh(form)
        return self._json(400, {"error": "unsupported_grant_type"})

    def _emettre(self, data, grant_id, scope, chain_exp=None):
        """Émet une paire de jetons. Appelé SOUS le verrou, jamais hors de lui."""
        acces, rafraichir = jeton(), jeton()
        maintenant = time.time()
        data["access"][empreinte(acces)] = {
            "grant_id": grant_id, "scope": scope, "aud": MCP_URL,
            "exp": maintenant + ACCESS_TTL}
        fin_chaine = chain_exp or (maintenant + REFRESH_TTL)
        data["refresh"][empreinte(rafraichir)] = {
            "grant_id": grant_id, "scope": scope, "used": False,
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
        with _oauth_lock:
            data = oauth_menage(oauth_load())
            entree = data["codes"].get(empreinte(code))
            if not isinstance(entree, dict):
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
                oauth_save(data)
                return self._json(400, {"error": "invalid_grant"})
            attendu = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii", "ignore")).digest()
            ).rstrip(b"=").decode()
            if not hmac.compare_digest(attendu, entree.get("code_challenge", "")):
                oauth_save(data)
                return self._json(400, {"error": "invalid_grant",
                                        "error_description": "code_verifier invalide"})
            # Gardé, marqué : c'est l'entrée conservée qui permettra de
            # RECONNAÎTRE un rejeu, au lieu de le prendre pour un code inconnu.
            entree["used"] = True
            acces, rafraichir = self._emettre(data, entree["grant_id"], entree["scope"])
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
            data = oauth_menage(oauth_load())
            entree = data["refresh"].get(empreinte(presente))
            if not isinstance(entree, dict):
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
            entree["used"] = True
            acces, neuf = self._emettre(data, entree["grant_id"], scope,
                                        chain_exp=entree.get("chain_exp"))
            grant["last"] = horodate()
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
        if brut == "trop-gros":
            return self._json(413, {"error": "invalid_client_metadata"})
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
        form = self._form_stricte()
        if form is None:
            return self._send(400, page_refus("Demande mal formée", "Corps illisible."))
        vise = form.get("grant", "")
        with _oauth_lock:
            data = oauth_menage(oauth_load())
            if vise == "tout":
                for gid in list(data["grants"]):
                    oauth_revoquer(data, gid)
            elif vise in data["grants"]:
                oauth_revoquer(data, vise)
            oauth_save(data)
        return self._redirect("/")

    def _accueil(self):
        if not self._humain_present():
            return self._defi_humain()
        with _oauth_lock:
            data = oauth_menage(oauth_load())
            vivants = sorted(
                ((gid, g) for gid, g in data["grants"].items()
                 if isinstance(g, dict) and not g.get("revoked")),
                key=lambda paire: paire[1].get("created", ""), reverse=True)
        return self._send(200, page_accueil(vivants), extra=[
            ("Content-Security-Policy",
             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
             "frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY")])

    # ---- routage ---------------------------------------------------------

    def do_GET(self):
        chemin = urlparse(self.path).path

        if chemin == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")

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
        chemin = urlparse(self.path).path

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
        chemin = urlparse(self.path).path
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
