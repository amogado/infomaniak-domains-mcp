"""La page de configuration : ce qu'elle règle, et ce qu'elle ne montre jamais.

Écrit contre la **spec** (`docs/specs/2026-08-31-page-de-configuration.md`), pas
contre l'implémentation — les deux ont été rédigées en parallèle, exprès. Un
test calqué sur le code qu'il juge ne dit rien de plus que « ce code fait ce
qu'il fait » ; celui-ci dit « ce code fait ce qui a été décidé ».

D'où une règle de conduite tenue partout ici : **on est dur sur ce que la spec
fixe, et on sonde ce qu'elle laisse ouvert.** La spec nomme `/config`,
`/data/config.json`, `0600`, `/data/journal.json`, `X-Auth-Request-Email`, et
« le champ est vide, un envoi vide ne change rien » : tout cela est en assertion
dure. Elle ne nomme PAS les champs du formulaire — les deviner en dur ferait
virer au rouge une page parfaitement juste. Le banc lit donc la page rendue,
en extrait les formulaires, et **se comporte comme un navigateur** : il renvoie
le formulaire tel qu'il a été servi, avec la seule modification qu'il veut
éprouver. C'est la même conduite que `tests/marque_proxy.py`, pour la même
raison : ce qui protège une page n'est pas le NOM d'un champ.

Quatre pièges, dont trois ont déjà coûté du temps dans ce dépôt et le voisin :

1. **La marque de proxy est POSÉE, jamais omise.** Sans
   `INFOMANIAK_MARQUE_PROXY`, `_humain_present()` retombe sur la boucle locale
   — et un banc qui parle depuis 127.0.0.1 obtiendrait tout, sans jamais rien
   présenter. « /config refuse un anonyme » serait alors vert par construction,
   c'est-à-dire faux. Le banc arme donc la marque, et vérifie d'abord qu'un
   anonyme se fait bien refuser AILLEURS que sur /config.
2. **Une assertion d'absence est verte quand la page ne rend rien.** « le jeton
   n'apparaît pas » est vrai d'une page vide, d'un 404, d'un 500. Chaque
   absence est donc appariée à une présence : le témoin qui DOIT être là (les
   quatre derniers caractères, le formulaire, le champ) est exigé dans la même
   respiration.
3. **Un refus se constate dans le FICHIER, pas dans le code de retour.** Un 403
   qui a quand même écrit est un 403 qui ment. On relit `config.json` et on
   compare les états.
4. **L'API Infomaniak est pointée sur un port fermé.** La page alimente sa
   liste de comptes depuis l'API ; en banc d'essai il n'y a ni jeton ni réseau.
   Un port fermé donne un refus immédiat — un hôte réel donnerait une attente,
   et une suite lente est une suite qu'on cesse de lancer.

Aucun sommeil n'est utilisé pour mesurer quoi que ce soit : la seule attente est
celle du démarrage du serveur, et elle se termine dès que le port répond.
"""

import base64
import hashlib
import html.parser
import http.client
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import marque_proxy                                              # noqa: E402

RACINE = pathlib.Path(__file__).resolve().parent.parent

VERIFS = 0
ECHECS = []


def ok(condition, quoi):
    global VERIFS
    VERIFS += 1
    if not condition:
        ECHECS.append(quoi)
    return bool(condition)


def egal(obtenu, attendu, quoi):
    return ok(obtenu == attendu, "%s : attendu %r, obtenu %r" % (quoi, attendu, obtenu))


def dans(obtenu, ensemble, quoi):
    return ok(obtenu in ensemble,
              "%s : attendu l'un de %r, obtenu %r" % (quoi, sorted(ensemble), obtenu))


def rendre(code=None):
    """Le verdict, dans le format que `run.sh` sait compter."""
    print("%d vérifications, %d échec(s)" % (VERIFS, len(ECHECS)))
    for e in ECHECS:
        print("  ✗", e)
    for proc in list(PROCESSUS):
        arreter(proc)
    sys.exit(code if code is not None else (1 if ECHECS else 0))


def abandon(pourquoi):
    """Un manque qui rend la suite du banc sans objet.

    On ne lève pas : une trace de pile ne se compte pas, et `run.sh` ne verrait
    ni le nombre de vérifications ni la raison. On dit, et on sort rouge.
    """
    ECHECS.append(pourquoi)
    rendre(1)


# --------------------------------------------------------------------------
# le banc : un serveur jetable, un répertoire d'état temporaire
# --------------------------------------------------------------------------

def port_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# Un port qu'on ferme aussitôt et que personne ne réouvre : l'API Infomaniak y
# répond « connexion refusée », immédiatement. C'est ce qui permet à la page de
# se rendre sans réseau et sans attente.
PORT_API_MORT = port_libre()
API_MORTE = "http://127.0.0.1:%d" % PORT_API_MORT

PROCESSUS = []
JOURNAUX = {}          # pid -> chemin du fichier qui reçoit stderr


def lancer(dossier, port, extra=None):
    """Un serveur, sur ce répertoire d'état, avec la marque de proxy armée.

    `stderr` va dans un FICHIER, pas dans un tube : ce banc envoie plus d'un
    millier de requêtes, chacune journalisée, et un tube de 64 Kio que personne
    ne vide bloquerait le serveur au milieu du test — un blocage qui
    ressemblerait à une lenteur du serveur, alors qu'il viendrait du banc.
    Le fichier sert ensuite à une assertion à part entière : le secret n
e doit
    pas s'y trouver non plus.
    """
    env = dict(os.environ)
    env.update(marque_proxy.env())
    env.update({
        "INFOMANIAK_DATA": str(dossier),
        "INFOMANIAK_LISTEN_PORT": str(port),
        "INFOMANIAK_PUBLIC_BASE": "http://127.0.0.1:%d" % port,
        "INFOMANIAK_BASE": API_MORTE,
        "INFOMANIAK_RATE": "1000000",
        "PYTHONUNBUFFERED": "1",
    })
    # L'amorçage se déclare explicitement, jamais par héritage : un
    # `INFOMANIAK_WRITE` traînant dans l'environnement de celui qui lance la
    # suite armerait l'écriture, et « le fichier fait autorité » deviendrait
    # invérifiable.
    for nom in ("INFOMANIAK_TOKEN", "INFOMANIAK_TOKEN_CMD", "INFOMANIAK_WRITE",
                "INFOMANIAK_ACHAT", "INFOMANIAK_ACHAT_MAX", "INFOMANIAK_ACCOUNT"):
        env.pop(nom, None)
    env.update(extra or {})

    trace = tempfile.NamedTemporaryFile(prefix="config-stderr-", suffix=".log",
                                        delete=False)
    proc = subprocess.Popen([sys.executable, str(RACINE / "serveur.py")],
                            stdout=subprocess.DEVNULL, stderr=trace, env=env)
    trace.close()
    JOURNAUX[proc.pid] = trace.name
    PROCESSUS.append(proc)

    # Le serveur doit être VIVANT : un port qui répond ne prouve pas que c'est
    # le nôtre, et un serveur mort au démarrage donnerait des refus qu'on
    # prendrait pour des gardes.
    for _ in range(80):
        if proc.poll() is not None:
            abandon("le serveur est mort au démarrage : %s"
                    % lire_trace(proc)[-800:])
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            return proc
        except OSError:
            time.sleep(0.05)
    abandon("le serveur n'écoute toujours pas sur %d" % port)


def lire_trace(proc):
    chemin = JOURNAUX.get(proc.pid)
    if not chemin or not os.path.exists(chemin):
        return ""
    with open(chemin, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def arreter(proc):
    if proc in PROCESSUS:
        PROCESSUS.remove(proc)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def demande(port, methode, chemin, entetes=None, corps=None, attente=10.0):
    """Une requête, une réponse, une connexion neuve. Rend (code, en-têtes, texte)."""
    tetes = dict(entetes or {})
    if corps is not None and "Content-Type" not in tetes:
        tetes["Content-Type"] = "application/x-www-form-urlencoded"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=attente)
    try:
        conn.request(methode, chemin, body=corps, headers=tetes)
        rep = conn.getresponse()
        texte = rep.read().decode("utf-8", "replace")
        return rep.status, {k.lower(): v for k, v in rep.getheaders()}, texte
    finally:
        conn.close()


# --------------------------------------------------------------------------
# lire un formulaire comme un navigateur le lit
# --------------------------------------------------------------------------

class Formulaire:
    def __init__(self, action, methode):
        self.action = action
        self.methode = (methode or "get").lower()
        self.champs = []        # dicts : balise, nom, type, valeur, coche, options

    def par_nom(self, nom):
        for c in self.champs:
            if c["nom"] == nom:
                return c
        return None

    def cherche(self, mots, types=None, exclure=()):
        """Le premier champ dont le nom évoque l'un de ces mots.

        La spec ne nomme pas les champs ; les deviner en dur ferait virer au
        rouge une page juste. On les reconnaît donc à ce qu'ils sont.
        """
        for c in self.champs:
            nom = (c["nom"] or "").lower()
            if not nom or any(x in nom for x in exclure):
                continue
            if types and c["type"] not in types:
                continue
            if any(mot in nom for mot in mots):
                return c
        return None


class LecteurFormulaires(html.parser.HTMLParser):
    """Assez de HTML pour rejouer un formulaire, et pas une ligne de plus."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.formulaires = []
        self._courant = None
        self._select = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "form":
            self._courant = Formulaire(a.get("action", ""), a.get("method", "get"))
            self.formulaires.append(self._courant)
        elif tag == "input" and self._courant is not None:
            self._courant.champs.append({
                "balise": "input",
                "nom": a.get("name", ""),
                "type": (a.get("type") or "text").lower(),
                "valeur": a.get("value", ""),
                "a_valeur": "value" in a,
                "coche": "checked" in a,
                "options": [],
            })
        elif tag == "textarea" and self._courant is not None:
            self._courant.champs.append({
                "balise": "textarea", "nom": a.get("name", ""), "type": "textarea",
                "valeur": "", "a_valeur": False, "coche": False, "options": [],
            })
        elif tag == "select" and self._courant is not None:
            self._select = {
                "balise": "select", "nom": a.get("name", ""), "type": "select",
                "valeur": "", "a_valeur": False, "coche": False, "options": [],
            }
            self._courant.champs.append(self._select)
        elif tag == "option" and self._select is not None:
            valeur = a.get("value", "")
            self._select["options"].append(valeur)
            if "selected" in a:
                self._select["valeur"] = valeur

    def handle_endtag(self, tag):
        if tag == "form":
            self._courant = None
        elif tag == "select":
            if self._select is not None and not self._select["valeur"] \
                    and self._select["options"]:
                self._select["valeur"] = self._select["options"][0]
            self._select = None


def formulaires(page):
    lecteur = LecteurFormulaires()
    lecteur.feed(page)
    return lecteur.formulaires


NON_ENVOYES = ("submit", "button", "image", "reset", "file")


def corps_de(form, modifs=None):
    """Ce qu'un navigateur enverrait de ce formulaire, avec nos modifications.

    `modifs` : nom -> valeur, ou None pour omettre le champ (ce qui est la
    seule façon de dire « la case est décochée » et « le jeton anti-CSRF est
    absent »).

    **Un nom, une valeur.** `_stricte()` refuse les clés répétées — et le motif
    `<input type=hidden name=x><input type=checkbox name=x>` en produit deux.
    Le banc garde la dernière, comme le fait un cadre serveur ordinaire : son
    objet est d'éprouver le jeton anti-CSRF et le refus d'écriture, pas de
    faire virer au rouge sur un doublon qui n'est pas ce qu'on mesure.
    """
    modifs = dict(modifs or {})
    paires = {}
    ordre = []
    for c in form.champs:
        nom = c["nom"]
        if not nom or (c["balise"] == "input" and c["type"] in NON_ENVOYES
                       and nom not in modifs):
            continue
        if nom in modifs:
            continue
        if c["type"] in ("checkbox", "radio") and not c["coche"]:
            continue
        if nom not in paires:
            ordre.append(nom)
        paires[nom] = c["valeur"] if c["type"] not in ("checkbox", "radio") \
            else (c["valeur"] or "on")
    for nom, valeur in modifs.items():
        if valeur is None:
            paires.pop(nom, None)
            if nom in ordre:
                ordre.remove(nom)
            continue
        if nom not in paires:
            ordre.append(nom)
        paires[nom] = valeur
    return urllib.parse.urlencode([(n, paires[n]) for n in ordre])


def cible_de(form, defaut="/config"):
    """Où ce formulaire s'envoie. Un `action` vide vaut la page courante.

    La spec ne dit pas si tous les réglages tiennent dans un formulaire ou
    dans plusieurs, ni où chacun s'envoie. On suit ce que la page déclare,
    comme un navigateur — pas ce qu'on aurait écrit à sa place.
    """
    action = (form.action or "").strip()
    if not action:
        return defaut
    morceau = urllib.parse.urlsplit(action)
    chemin = morceau.path or defaut
    return chemin + (("?" + morceau.query) if morceau.query else "")


def valeur_pour(champ, arme):
    """Ce qu'on met dans un champ pour dire « armé » ou « non armé »."""
    if champ["type"] == "checkbox":
        return (champ["valeur"] or "on") if arme else None
    if champ["type"] == "select" or champ["options"]:
        oui = [o for o in champ["options"] if o.lower() in ("1", "oui", "on", "true", "yes")]
        non = [o for o in champ["options"] if o.lower() in ("0", "non", "off", "false", "no", "")]
        if arme:
            return oui[0] if oui else "1"
        return non[0] if non else "0"
    return "1" if arme else "0"


# --------------------------------------------------------------------------
# ce qu'on pose, et ce qu'on cherchera ensuite dans les fichiers
# --------------------------------------------------------------------------

EMAIL = "vi.doyon@gmail.com"            # la liste nominative de la spec
ENTETE_EMAIL = "X-Auth-Request-Email"   # ce qu'oauth2-proxy transmet

# Deux jetons distincts, de même longueur, aux quatre derniers caractères
# distincts : c'est ce qui permet de vérifier à la fois qu'un secret ne
# s'affiche jamais et que la page en distingue quand même deux.
JETON_A = "jeton-de-config-AAAAAAAAAAAAAAAA-Zq7X"
JETON_B = "jeton-de-config-BBBBBBBBBBBBBBBB-Wm4P"
# Celui de l'amorçage, qui ne doit JAMAIS gagner contre le fichier.
JETON_AMORCE = "jeton-d-amorcage-CCCCCCCCCCCC-Rt9K"
COMPTE_AMORCE = "424242424"

MOTS_JETON = ("jeton", "token", "secret", "cle", "clef", "api")
MOTS_PLAFOND = ("plafond", "achat_max", "achatmax", "max", "montant", "depense",
                "dépense", "budget", "euros")
MOTS_ECRITURE = ("ecriture", "écriture", "write", "dns", "armement_dns")
MOTS_ACHAT = ("achat", "enregistrement", "acheter", "purchase", "domaine_achat")
MOTS_COMPTE = ("compte", "account")
MOTS_CSRF = ("csrf", "xsrf", "anti", "nonce", "jeton_page")


def chemin_etat(dossier, nom):
    return os.path.join(str(dossier), nom)


def charger_json(chemin):
    try:
        with open(chemin, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def trouver_valeur(objet, cible, prefixe=()):
    """Le chemin où `cible` se trouve dans un JSON, ou None.

    Le jeton est écrit en clair — la spec interdit le chiffrement maison — donc
    il se retrouve. On tolère quand même le base64 : ce n'est pas du
    chiffrement, seulement un encodage, et un banc qui ne le lirait pas
    accuserait à tort une implémentation honnête.
    """
    variantes = {cible, base64.b64encode(cible.encode("utf-8")).decode("ascii")}
    if isinstance(objet, dict):
        for cle, valeur in objet.items():
            trouve = trouver_valeur(valeur, cible, prefixe + (cle,))
            if trouve:
                return trouve
    elif isinstance(objet, list):
        for i, valeur in enumerate(objet):
            trouve = trouver_valeur(valeur, cible, prefixe + (i,))
            if trouve:
                return trouve
    elif isinstance(objet, str) and objet in variantes:
        return prefixe
    return None


def au_chemin(objet, chemin):
    for pas in chemin:
        try:
            objet = objet[pas]
        except (KeyError, IndexError, TypeError):
            return None
    return objet


def entrees_journal(chemin):
    """Les entrées du journal, quelle que soit la forme du fichier.

    Une liste au premier niveau, ou la première liste que porte un objet : la
    spec fixe le CHEMIN du fichier et son contenu, pas la forme de son
    enveloppe.
    """
    contenu = charger_json(chemin)
    if isinstance(contenu, list):
        return contenu
    if isinstance(contenu, dict):
        for valeur in contenu.values():
            if isinstance(valeur, list):
                return valeur
    return []


def texte_brut(chemin):
    try:
        with open(chemin, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# --------------------------------------------------------------------------
# 1. la frontière humaine : le canari, élargi
# --------------------------------------------------------------------------

ETAT = tempfile.mkdtemp(prefix="config-etat-")
PORT = port_libre()
CONFIG = chemin_etat(ETAT, "config.json")
JOURNAL = chemin_etat(ETAT, "journal.json")

serveur = lancer(ETAT, PORT)
ok(serveur.poll() is None, "le serveur de test est vivant")

NAV = marque_proxy.navigation()

# La marque : on ne devine pas son nom d'en-tête, on le sonde. Ce qui protège
# la page n'est pas le nom de l'en-tête — un inconnu peut en écrire n'importe
# lequel — mais sa valeur, qu'il ne peut pas produire.
MARQUE = marque_proxy.trouver(
    lambda entetes: demande(PORT, "GET", "/", dict(NAV, **entetes))[0] == 200)
if MARQUE is None:
    abandon("aucune façon d'annoncer « je viens du proxy » n'ouvre la page "
            "humaine « / » : le banc ne peut plus rien éprouver de /config. "
            "Voir tests/marque_proxy.py pour les noms qu'il essaie.")
ok(marque_proxy.VALEUR in MARQUE.values() or "Authorization" in MARQUE,
   "la marque trouvée est bien celle que le banc a posée")

# Le contrôle qui rend tout le reste falsifiable : SANS marque et SANS identité,
# une page humaine se refuse. Si celle-ci passait, « /config refuse un
# anonyme » serait vrai par accident et ne prouverait rien.
code, _, page = demande(PORT, "GET", "/", NAV)
ok(code != 200, "sans marque ni identité, la page humaine « / » ne s'ouvre pas "
                "(obtenu %d) — sans quoi tout ce banc serait vert par accident" % code)

IDENTITE = dict(NAV, **MARQUE)
IDENTITE[ENTETE_EMAIL] = EMAIL

# ---- le canari élargi : la marque OU l'identité, jamais le vide -------------
# La spec : « Le canari doit être élargi avant la bascule — il n'accepte
# aujourd'hui que la marque de proxy ; il devra accepter aussi l'identité
# transmise par oauth2-proxy. Ne pas le faire rend la page inatteignable au
# moment même où l'on en a besoin. »

code_marque, _, _ = demande(PORT, "GET", "/config", dict(NAV, **MARQUE))
ok(code_marque == 200,
   "le canari accepte la marque de proxy seule (obtenu %d)" % code_marque)

# La spec disait d'abord « le canari doit accepter aussi l'identité » — et elle
# avait tort. `X-Auth-Request-Email` est un en-tête que l'appelant écrit
# lui-même s'il n'existe rien pour l'écraser, et le pod est joignable sur 8080
# depuis le cluster sans traverser le proxy. L'accepter seul donnerait /config,
# donc le jeton d'API et l'armement de la dépense, à tout voisin.
# La marque, elle, est infalsifiable. On exige donc les deux — ce qui ne ferme
# aucune porte légitime, puisqu'en production ils arrivent ensemble.
code_email, _, _ = demande(PORT, "GET", "/config",
                           dict(NAV, **{ENTETE_EMAIL: EMAIL}))
ok(code_email != 200,
   "l'identité SEULE n'ouvre pas /config (obtenu %d) — un en-tête ne prouve "
   "rien par lui-même" % code_email)

code_deux, _, _ = demande(PORT, "GET", "/config",
                          dict(NAV, **dict(MARQUE, **{ENTETE_EMAIL: EMAIL})))
egal(code_deux, 200,
     "marque ET identité ouvrent — c'est ce qui arrive en production")

code_vide, _, page_vide = demande(PORT, "GET", "/config",
                                  dict(NAV, **{ENTETE_EMAIL: ""}))
ok(code_vide != 200,
   "un %s VIDE ne vaut pas une identité (obtenu %d) : un en-tête présent et "
   "vide est exactement ce que pose un proxy mal branché, et le vide doit "
   "tomber du côté qui refuse" % (ENTETE_EMAIL, code_vide))

code_rien, _, _ = demande(PORT, "GET", "/config", NAV)
dans(code_rien, {401, 403, 302, 303, 307}, "GET /config sans identité humaine")
ok(code_rien != 200, "GET /config sans identité humaine n'est JAMAIS un 200")

# ---- avec l'identité, la page est rendue -----------------------------------
code, _, page = demande(PORT, "GET", "/config", IDENTITE)
egal(code, 200, "GET /config avec l'identité humaine")
if code != 200:
    abandon("la page de configuration ne se rend pas (%d) : rien de ce qui suit "
            "n'aurait de sens. Corps : %r" % (code, page[:400]))

forms = [f for f in formulaires(page)
         if f.methode == "post" and (not f.action or "config" in f.action)]
if not forms:
    abandon("la page rendue ne porte aucun formulaire POST vers /config : "
            "le banc n'a rien à soumettre. Début de page : %r" % page[:400])
ok(True, "la page de configuration porte au moins un formulaire de réglage")

# Le contraire de l'assertion précédente, sans quoi « la page ne contient pas le
# jeton » serait vraie d'une page vide : la page contient bien des champs.
champs_totaux = sum(len(f.champs) for f in forms)
ok(champs_totaux >= 2,
   "et ce formulaire porte des champs (%d) — une page vide ne prouve rien"
   % champs_totaux)


def form_avec(page, mots, types=None, exclure=()):
    """Le formulaire qui porte ce champ, et le champ."""
    for f in formulaires(page):
        if f.methode != "post":
            continue
        c = f.cherche(mots, types=types, exclure=exclure)
        if c is not None:
            return f, c
    return None, None


def csrf_de(form):
    c = form.cherche(MOTS_CSRF, types=("hidden",))
    if c is None:
        # Un formulaire ne portant qu'un seul champ caché : c'est lui.
        caches = [x for x in form.champs if x["type"] == "hidden" and x["nom"]]
        if len(caches) == 1:
            return caches[0]
    return c


f_jeton, champ_jeton = form_avec(page, MOTS_JETON,
                                 types=("password", "text"), exclure=("csrf", "xsrf"))
f_plafond, champ_plafond = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
f_ecriture, champ_ecriture = form_avec(page, MOTS_ECRITURE,
                                       types=("checkbox", "select", "radio"))
f_achat, champ_achat = form_avec(page, MOTS_ACHAT,
                                 types=("checkbox", "select", "radio"))

for quoi, champ in (("le jeton d'API", champ_jeton),
                    ("le plafond de dépense", champ_plafond),
                    ("l'armement de l'écriture DNS", champ_ecriture),
                    ("l'armement de l'enregistrement de domaine", champ_achat)):
    ok(champ is not None,
       "la page offre un réglage pour %s (tableau « Ce qui se règle » de la spec)"
       % quoi)

if champ_jeton is None or champ_plafond is None:
    abandon("sans champ de jeton ni champ de plafond, le banc ne peut éprouver "
            "ni le secret ni le refus d'un plafond illisible. Champs vus : %r"
            % [(c["nom"], c["type"]) for f in forms for c in f.champs])

# ---- le compte est une LISTE, pas un champ libre ---------------------------
# « Taper un identifiant à la main, c'est exactement l'erreur qui a fait lister
# les domaines d'un tiers pendant cette session. »
libre = None
for f in formulaires(page):
    c = f.cherche(MOTS_COMPTE, types=("text", "search", "number"),
                  exclure=("csrf", "xsrf"))
    if c is not None:
        libre = c
ok(libre is None,
   "le compte épinglé ne se saisit pas au clavier : aucun champ libre ne le "
   "porte (trouvé %r)" % (libre and libre["nom"]))

# ---- le contexte de navigation ---------------------------------------------
image = dict(IDENTITE)
image["Sec-Fetch-Dest"] = "image"
image["Sec-Fetch-Mode"] = "no-cors"
code_img, _, page_img = demande(PORT, "GET", "/config", image)
ok(code_img != 200,
   "GET /config en Sec-Fetch-Dest: image est refusé (obtenu %d) : un "
   "chargement en arrière-plan n'exprime aucune intention" % code_img)
# Le refus ne doit pas non plus DISTRIBUER un jeton au passage : c'est la
# frappe dans une table bornée qui fait l'attaque, pas l'affichage de la page.
ok(all(csrf_de(f) is None for f in formulaires(page_img)),
   "et le refus ne distribue pas de jeton anti-CSRF au passage")


# --------------------------------------------------------------------------
# 2. poser un secret, et ne jamais le revoir
# --------------------------------------------------------------------------

def envoyer(port, form, modifs, entetes=None):
    """Soumet ce formulaire, tel qu'il a été rendu, avec ces modifications."""
    entetes = entetes or IDENTITE
    return demande(port, "POST", cible_de(form), entetes, corps_de(form, modifs))


def page_de(port, entetes=None):
    entetes = entetes or IDENTITE
    code, _, courante = demande(port, "GET", "/config", entetes)
    if code != 200:
        abandon("la page de configuration ne se rend plus (%d) : rien de ce "
                "qui suit n'aurait de sens" % code)
    return courante


def poser(port, modifs, entetes=None, attendu=None, mots=None):
    """Recharge la page, prend un jeton anti-CSRF frais, soumet le formulaire.

    C'est la seule façon honnête de soumettre : le jeton est à usage unique,
    donc chaque envoi part d'une page fraîchement rendue, comme chez un humain.
    """
    entetes = entetes or IDENTITE
    courante = page_de(port, entetes)
    cible = None
    if mots:
        cible, _ = form_avec(courante, mots)
    if cible is None:
        for f in formulaires(courante):
            if f.methode == "post" and all(f.par_nom(n) is not None
                                           for n in modifs if n):
                cible = f
                break
    if cible is None:
        postables = [f for f in formulaires(courante) if f.methode == "post"]
        if not postables:
            abandon("la page ne porte plus aucun formulaire à soumettre")
        cible = postables[0]
    code, _, reponse = envoyer(port, cible, modifs, entetes)
    if attendu is not None:
        dans(code, attendu, "POST %s (%s)"
             % (cible_de(cible), ", ".join(sorted(modifs))))
    return code, reponse


SUCCES = {200, 201, 202, 204, 302, 303}

poser(PORT, {champ_jeton["nom"]: JETON_A}, attendu=SUCCES)

# Le fichier existe, et il n'est lisible que par le service.
ok(os.path.exists(CONFIG),
   "le fichier de configuration est écrit en %s" % CONFIG)
if os.path.exists(CONFIG):
    mode = os.stat(CONFIG).st_mode & 0o777
    egal(oct(mode), oct(0o600),
         "le mode RÉEL de config.json — un instantané de volume est la seule "
         "exposition que la spec assume ; un fichier lisible par tous en "
         "ajouterait une seconde")

config = charger_json(CONFIG)
ok(isinstance(config, dict), "config.json contient un objet JSON lisible")
chemin_jeton = trouver_valeur(config, JETON_A)
ok(chemin_jeton is not None,
   "le jeton posé est bien persisté dans config.json (sinon il ne survivrait "
   "pas au redémarrage) — clés vues : %r"
   % (sorted(config) if isinstance(config, dict) else config))

# ---- il n'apparaît JAMAIS dans la page ------------------------------------
code, _, page = demande(PORT, "GET", "/config", IDENTITE)
egal(code, 200, "la page se rend encore, jeton posé")
ok(JETON_A not in page,
   "le jeton posé n'apparaît NULLE PART dans le HTML rendu — recherche de la "
   "valeur exacte, pas d'un champ vide")
ok(JETON_A[-8:] not in page,
   "ni même ses huit derniers caractères : la spec en accorde quatre")

# L'appariement qui empêche l'assertion précédente d'être vraie par vacuité :
# ce qui DOIT être montré l'est.
ok(JETON_A[-4:] in page,
   "les quatre derniers caractères, eux, sont montrés (%r) : « assez pour "
   "distinguer deux jetons et vérifier qu'on a posé le bon »" % JETON_A[-4:])
ok(str(len(JETON_A)) in page,
   "la longueur du jeton est montrée (%d)" % len(JETON_A))
condense = hashlib.sha256(JETON_A.encode("utf-8")).hexdigest()
ok(any(condense[:n] in page for n in (6, 8, 10, 12, 16)),
   "une empreinte courte du jeton est montrée (SHA-256 tronqué)")

# ---- le champ est VIDE ------------------------------------------------------
f_jeton, champ_jeton = form_avec(page, MOTS_JETON, types=("password", "text"),
                                 exclure=("csrf", "xsrf"))
ok(champ_jeton is not None, "le champ du jeton est toujours offert")
if champ_jeton is not None:
    egal(champ_jeton["valeur"], "",
         "le champ du secret est VIDE : un formulaire qui réaffiche le secret "
         "le met dans le cache du navigateur et dans le gestionnaire de mots "
         "de passe")
    dans(champ_jeton["type"], {"password", "text"}, "le type du champ du jeton")

# ---- un envoi vide ne change rien -------------------------------------------
avant = charger_json(CONFIG)
poser(PORT, {champ_jeton["nom"]: ""}, attendu=SUCCES)
apres = charger_json(CONFIG)
ok(au_chemin(apres, chemin_jeton or ()) == au_chemin(avant, chemin_jeton or ()),
   "un envoi vide ne change PAS le jeton — constaté dans le fichier, pas au "
   "code de retour")
code, _, page = demande(PORT, "GET", "/config", IDENTITE)
ok(JETON_A[-4:] in page,
   "et la page montre toujours le même jeton après cet envoi vide")

# ---- deux jetons différents donnent deux pages différentes ------------------
poser(PORT, {champ_jeton["nom"]: JETON_B}, attendu=SUCCES)
code, _, page_b = demande(PORT, "GET", "/config", IDENTITE)
ok(JETON_B not in page_b, "le second jeton non plus n'apparaît pas dans la page")
ok(JETON_B[-4:] in page_b, "mais la page montre ses quatre derniers caractères")
ok(JETON_A[-4:] not in page_b,
   "et ne montre plus ceux de l'ancien : la page distingue bien deux jetons")

# On repose le premier : tout ce qui suit le cherche.
poser(PORT, {champ_jeton["nom"]: JETON_A}, attendu=SUCCES)


# --------------------------------------------------------------------------
# 3. le jeton anti-CSRF : exigé, et à usage unique
# --------------------------------------------------------------------------

code, _, page = demande(PORT, "GET", "/config", IDENTITE)
f_plafond, champ_plafond = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
champ_csrf = csrf_de(f_plafond) if f_plafond else None
ok(champ_csrf is not None,
   "le formulaire porte un jeton anti-CSRF (champ caché) — « les mêmes gardes "
   "que /consent, pour les mêmes raisons »")
if champ_csrf is None:
    abandon("sans jeton anti-CSRF identifiable, le banc ne peut pas éprouver "
            "son absence ni son usage unique. Champs cachés vus : %r"
            % [c["nom"] for c in f_plafond.champs if c["type"] == "hidden"])

# Un plafond connu, pour que « rien n'a changé » se constate sur une valeur.
poser(PORT, {champ_plafond["nom"]: "7"}, attendu=SUCCES)
avant = charger_json(CONFIG)
entrees_avant = len(entrees_journal(JOURNAL))

# ---- sans jeton : refus, ET rien n'a changé --------------------------------
page = page_de(PORT)
f_plafond, champ_plafond = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
code, _, _ = envoyer(PORT, f_plafond,
                     {champ_plafond["nom"]: "13", champ_csrf["nom"]: None})
dans(code, {400, 401, 403, 409}, "POST /config sans jeton anti-CSRF est refusé")
apres = charger_json(CONFIG)
egal(apres, avant,
     "et RIEN n'a changé dans config.json — constaté dans le fichier, parce "
     "qu'un 403 qui a quand même écrit est un 403 qui ment")
egal(len(entrees_journal(JOURNAL)), entrees_avant,
     "le journal n'a pas gagné d'entrée non plus")

# Un jeton fabriqué de toutes pièces ne vaut pas mieux qu'aucun.
code, _, _ = envoyer(PORT, f_plafond,
                     {champ_plafond["nom"]: "17",
                      champ_csrf["nom"]: "jeton-fabrique-par-l-attaquant"})
dans(code, {400, 401, 403, 409}, "POST /config avec un jeton inventé est refusé")
egal(charger_json(CONFIG), avant, "et le fichier n'a toujours pas bougé")

# ---- à usage unique ---------------------------------------------------------
page = page_de(PORT)
f_plafond, champ_plafond = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
csrf_unique = csrf_de(f_plafond)["valeur"]
code, _, _ = envoyer(PORT, f_plafond, {champ_plafond["nom"]: "23",
                                       champ_csrf["nom"]: csrf_unique})
dans(code, SUCCES, "le premier envoi, jeton frais, passe")
config = charger_json(CONFIG)
ok(config != avant, "et il a bien écrit quelque chose")

code, _, _ = envoyer(PORT, f_plafond, {champ_plafond["nom"]: "29",
                                       champ_csrf["nom"]: csrf_unique})
dans(code, {400, 401, 403, 409},
     "le MÊME jeton anti-CSRF rejoué est refusé : à usage unique")
egal(charger_json(CONFIG), config,
     "et le rejeu n'a rien écrit — la valeur 29 n'est nulle part dans le fichier")
ok("29" not in json.dumps(charger_json(CONFIG)),
   "la valeur du rejeu est absente du fichier, cherchée dans son texte entier")


# --------------------------------------------------------------------------
# 4. le plafond de dépense : illisible ⇒ refus, jamais le défaut
# --------------------------------------------------------------------------
# « un contrôle qui autorise une dépense doit se fermer quand il ne se comprend
# pas lui-même » — infomaniak_mcp.plafond_achat(). La page ne doit pas ouvrir
# une porte que le module tient fermée.

poser(PORT, {champ_plafond["nom"]: "7"}, attendu=SUCCES)
avant = charger_json(CONFIG)

# « 1e400 » et « nan » sont les deux pièges de `float()` : le premier rend
# `inf`, le second `nan`. Ni l'un ni l'autre n'est un nombre d'euros, et le
# premier est pire qu'un plafond absent — il PASSE toutes les comparaisons de
# prix, donc il autorise n'importe quelle dépense. Écrits tels quels dans
# `config.json`, ils y produisent en outre `Infinity` et `NaN`, que le JSON
# standard ne connaît pas : le fichier suivant ne se relit plus.
for illisible in ("beaucoup", "-3", "0", "1e400", "nan"):
    f, c = form_avec(page_de(PORT), MOTS_PLAFOND, types=("number", "text"))
    code, _, _ = envoyer(PORT, f, {c["nom"]: illisible})
    dans(code, {400, 403, 409, 422},
         "un plafond %r est refusé" % illisible)
    egal(charger_json(CONFIG), avant,
         "et le plafond %r n'a pas été écrit : le refus se constate dans le "
         "fichier" % illisible)

code, _, page = demande(PORT, "GET", "/config", IDENTITE)
f, c = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
ok(c is not None and c["valeur"].strip() in ("7", "7.0", "7,0"),
   "le plafond montré est toujours celui qui a été accepté (7), et non le "
   "défaut de 50 : un plafond illisible ne retombe pas sur le défaut — "
   "obtenu %r" % (c and c["valeur"]))


# --------------------------------------------------------------------------
# 5. le journal : le nom du réglage et l'identité, jamais la valeur
# --------------------------------------------------------------------------

ok(os.path.exists(JOURNAL),
   "le journal des changements est écrit en %s" % JOURNAL)
entrees = entrees_journal(JOURNAL)
ok(len(entrees) > 0,
   "et il porte des entrées (%d) — un journal vide rendrait vraie par vacuité "
   "toute assertion d'absence qui suit" % len(entrees))

brut_journal = texte_brut(JOURNAL)
ok(JETON_A not in brut_journal and JETON_B not in brut_journal,
   "AUCUNE valeur de jeton dans le journal — recherche des valeurs exactes")
ok(EMAIL in brut_journal,
   "l'identité qui a fait le changement y est, elle : « un armement de dépense "
   "qui apparaît sans qu'on sache qui l'a posé est une question sans réponse »")

nom_jeton = champ_jeton["nom"].lower()
nom_plafond = champ_plafond["nom"].lower()
ok(any(mot in brut_journal.lower()
       for mot in (nom_jeton,) + MOTS_JETON),
   "le NOM du réglage « jeton » est journalisé")
ok(any(mot in brut_journal.lower()
       for mot in (nom_plafond,) + MOTS_PLAFOND),
   "le NOM du réglage « plafond » est journalisé")

# Une date, sous une forme ou une autre : « quand » est l'une des trois choses
# que la spec exige. On ne fixe pas le format, on exige qu'il y ait un instant.
def a_une_date(entree):
    if not isinstance(entree, dict):
        return False
    for valeur in entree.values():
        if isinstance(valeur, (int, float)) and valeur > 1_600_000_000:
            return True
        if isinstance(valeur, str) and len(valeur) >= 10 and valeur[:4].isdigit() \
                and "-" in valeur:
            return True
    return False


ok(all(a_une_date(e) for e in entrees),
   "chaque entrée du journal est datée")

# ---- le journal est BORNÉ ---------------------------------------------------
# On ne connaît pas la borne : on la cherche. Le repère est un changement de
# NATURE DIFFÉRENTE posé en tête — le jeton — puis une inondation de
# changements de plafond. Quand la borne mord, l'entrée « jeton » doit avoir
# disparu et les entrées « plafond » rester : c'est ce qui distingue « les plus
# anciennes partent » de « on jette au hasard ».
poser(PORT, {champ_jeton["nom"]: JETON_A}, attendu=SUCCES)
repere = len(entrees_journal(JOURNAL))

# On ne s'arrête PAS au premier signe d'éviction : à cet instant, le journal
# garde encore quelques entrées d'avant l'inondation, et « les plus anciennes
# partent » ne se constaterait pas. On continue jusqu'à ce que l'inondation
# seule puisse remplir le journal — c'est-à-dire jusqu'à en avoir posé autant
# que la borne observée. C'est le même piège que l'assertion d'absence : un
# repère encore présent rendrait l'assertion suivante fausse pour une raison
# qui n'est pas celle qu'on mesure.
PLAFOND_ESSAIS = 600
poses = 0
evince = False
garde = 0
while poses < PLAFOND_ESSAIS and not (evince and poses >= garde):
    poses += 1
    f, c = form_avec(page_de(PORT), MOTS_PLAFOND, types=("number", "text"))
    envoyer(PORT, f, {c["nom"]: str(3 + (poses % 40))})
    if poses % 8 == 0 or poses == PLAFOND_ESSAIS:
        garde = len(entrees_journal(JOURNAL))
        evince = garde < repere + poses

final = len(entrees_journal(JOURNAL))
ok(final < repere + poses,
   "le journal est BORNÉ : %d changements posés, %d entrées gardées — au-delà "
   "de la borne, les plus anciennes partent. Un journal qui grandit sans fin "
   "sur un PVC finit par tuer le pod de façon permanente (déjà vu ici, table "
   "refresh)" % (poses, final))
brut_journal = texte_brut(JOURNAL)
ok(not any(mot in brut_journal.lower() for mot in (nom_jeton,) + MOTS_JETON),
   "ce sont bien les PLUS ANCIENNES qui sont parties : après l'inondation, "
   "plus aucune entrée ne nomme le réglage « jeton » posé en tête")
ok(any(mot in brut_journal.lower() for mot in (nom_plafond,) + MOTS_PLAFOND),
   "et les récentes sont restées : le journal nomme encore le plafond")
ok(serveur.poll() is None, "le serveur a survécu à l'inondation du journal")


# --------------------------------------------------------------------------
# 6. /_whoami : les réglages effectifs, et rien d'autre
# --------------------------------------------------------------------------

def whoami(port):
    code, _, corps = demande(port, "GET", "/_whoami")
    try:
        return code, json.loads(corps), corps
    except ValueError:
        return code, {}, corps


# On arme l'écriture DNS depuis la page, puis on regarde ce que le serveur dit
# de lui-même. C'est le seul moyen de prouver que le réglage est EFFECTIF et
# pas seulement écrit dans un fichier.
code, _, page = demande(PORT, "GET", "/config", IDENTITE)
f_ecriture, champ_ecriture = form_avec(page, MOTS_ECRITURE,
                                       types=("checkbox", "select", "radio"))
if champ_ecriture is not None:
    code, corps_w, _ = whoami(PORT)
    avant_w = corps_w.get("ecriture_armee")
    poser(PORT, {champ_ecriture["nom"]: valeur_pour(champ_ecriture, True)},
          attendu=SUCCES, mots=MOTS_ECRITURE)
    code, corps_w, _ = whoami(PORT)
    egal(corps_w.get("ecriture_armee"), True,
         "armer l'écriture DNS depuis la page se voit dans /_whoami : le "
         "réglage est EFFECTIF, pas seulement écrit")
    poser(PORT, {champ_ecriture["nom"]: valeur_pour(champ_ecriture, False)},
          attendu=SUCCES, mots=MOTS_ECRITURE)
    code, corps_w, _ = whoami(PORT)
    egal(corps_w.get("ecriture_armee"), False,
         "et le désarmer aussi — sans quoi « toujours vrai » passerait pour un "
         "correctif")

if champ_achat is not None:
    f_achat, champ_achat = form_avec(page_de(PORT), MOTS_ACHAT,
                                     types=("checkbox", "select", "radio"))
    poser(PORT, {champ_achat["nom"]: valeur_pour(champ_achat, True)},
          attendu=SUCCES, mots=MOTS_ACHAT)
    code, corps_w, _ = whoami(PORT)
    egal(corps_w.get("achat_arme"), True,
         "armer l'enregistrement de domaine depuis la page se voit aussi")

code, corps_w, brut_w = whoami(PORT)
egal(code, 200, "/_whoami répond")
ok(JETON_A not in brut_w and JETON_B not in brut_w,
   "/_whoami ne contient AUCUN jeton — recherche des valeurs exactes dans le "
   "corps rendu")
interdites = {"token", "jeton", "compte", "account", "secret", "cle", "clef"}
communes = interdites & {str(k).lower() for k in corps_w}
egal(communes, set(),
     "et aucune clé de /_whoami ne nomme un jeton ni un compte : « un numéro "
     "de client n'a rien à faire dehors »")


# --------------------------------------------------------------------------
# 7. le redémarrage : le fichier fait autorité sur l'environnement
# --------------------------------------------------------------------------

# On fige un état reconnaissable, puis on relance le MÊME répertoire avec un
# amorçage qui dit le CONTRAIRE. Si l'environnement gagnait, il n'y aurait
# aucune façon de s'en apercevoir depuis la page — c'est exactement le genre
# d'écart qu'un `ETAT.md` a affirmé pendant des semaines chez le voisin.
poser(PORT, {champ_plafond["nom"]: "11"}, attendu=SUCCES, mots=MOTS_PLAFOND)
poser(PORT, {champ_jeton["nom"]: JETON_A}, attendu=SUCCES, mots=MOTS_JETON)
code, _, page = demande(PORT, "GET", "/config", IDENTITE)
f_ecriture, champ_ecriture = form_avec(page, MOTS_ECRITURE,
                                       types=("checkbox", "select", "radio"))
if champ_ecriture is not None:
    poser(PORT, {champ_ecriture["nom"]: valeur_pour(champ_ecriture, True)},
          attendu=SUCCES, mots=MOTS_ECRITURE)

etat_fige = charger_json(CONFIG)
arreter(serveur)

PORT2 = port_libre()
serveur = lancer(ETAT, PORT2, extra={
    "INFOMANIAK_TOKEN": JETON_AMORCE,
    "INFOMANIAK_ACHAT_MAX": "9999",
    "INFOMANIAK_ACCOUNT": COMPTE_AMORCE,
    # L'écriture n'est PAS armée dans l'environnement : si elle reste armée
    # après redémarrage, c'est que le fichier a parlé.
})
ok(serveur.poll() is None, "le serveur redémarre sur le même répertoire d'état")

code, _, page = demande(PORT2, "GET", "/config", IDENTITE)
egal(code, 200, "la page se rend après redémarrage")
f, c = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
ok(c is not None and c["valeur"].strip() in ("11", "11.0", "11,0"),
   "le plafond réglé (11) a survécu au redémarrage et l'emporte sur "
   "INFOMANIAK_ACHAT_MAX=9999 — obtenu %r" % (c and c["valeur"]))
ok(JETON_A[-4:] in page,
   "le jeton réglé a survécu, lui aussi (ses quatre derniers caractères)")
ok(JETON_AMORCE[-4:] not in page,
   "et le jeton d'amorçage n'a PAS repris la main : « les variables "
   "d'environnement deviennent des valeurs d'amorçage »")
ok(JETON_AMORCE not in page, "le jeton d'amorçage n'est pas rendu non plus")

if champ_ecriture is not None:
    code, corps_w, _ = whoami(PORT2)
    egal(corps_w.get("ecriture_armee"), True,
         "l'armement de l'écriture a survécu au redémarrage, sans "
         "INFOMANIAK_WRITE dans l'environnement")

code, corps_w, brut_w = whoami(PORT2)
ok(COMPTE_AMORCE not in brut_w,
   "/_whoami ne dit pas le compte épinglé, même quand il vient de "
   "l'environnement")
ok(JETON_AMORCE not in brut_w, "ni le jeton d'amorçage")

# ---- le mode du fichier tient au redémarrage --------------------------------
mode = os.stat(CONFIG).st_mode & 0o777
egal(oct(mode), oct(0o600), "config.json est TOUJOURS en 0600 après redémarrage")

# ---- un plafond illisible dans le fichier ne devient pas le défaut ----------
# Le fichier peut être abîmé autrement que par la page : à la main, par une
# restauration, par une version antérieure. Le vide doit alors tomber du côté
# qui alarme.
arreter(serveur)
abime = charger_json(CONFIG)
chemin_p = None
for cle in list(abime or {}):
    if any(mot in str(cle).lower() for mot in MOTS_PLAFOND):
        chemin_p = cle
if chemin_p is not None:
    abime[chemin_p] = "beaucoup"
    with open(CONFIG, "w", encoding="utf-8") as fh:
        json.dump(abime, fh)
    PORT3 = port_libre()
    serveur = lancer(ETAT, PORT3)
    code, _, page = demande(PORT3, "GET", "/config", IDENTITE)
    f, c = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
    montre = (c["valeur"].strip() if c is not None else "")
    ok(code != 200 or montre not in ("50", "50.0", "50,0"),
       "un plafond illisible dans le fichier ne devient PAS le défaut de 50 : "
       "il refuse (obtenu HTTP %d, plafond montré %r)" % (code, montre))
    ok(serveur.poll() is None,
       "et le serveur ne meurt pas pour autant : un réglage abîmé se répare "
       "depuis la page, ce qui suppose que la page se serve encore")
    arreter(serveur)
else:
    ok(False, "aucune clé de config.json ne porte le plafond : le banc ne peut "
              "pas l'abîmer à la main. Clés vues : %r" % sorted(abime or {}))


# --------------------------------------------------------------------------
# 8. l'amorçage : une variable seule sert encore de départ
# --------------------------------------------------------------------------
# Le pendant du test précédent, et il est indispensable : « le fichier fait
# autorité » se satisferait d'un serveur qui IGNORE l'environnement, ce qui
# rendrait impossible le tout premier démarrage.

NEUF = tempfile.mkdtemp(prefix="config-neuf-")
PORT4 = port_libre()
serveur = lancer(NEUF, PORT4, extra={
    "INFOMANIAK_TOKEN": JETON_AMORCE,
    "INFOMANIAK_WRITE": "1",
    "INFOMANIAK_ACHAT": "1",
    "INFOMANIAK_ACHAT_MAX": "33",
    "INFOMANIAK_ACCOUNT": COMPTE_AMORCE,
})
ok(not os.path.exists(chemin_etat(NEUF, "config.json"))
   or charger_json(chemin_etat(NEUF, "config.json")) is not None,
   "sur un répertoire neuf, le serveur démarre sans fichier de configuration "
   "valide à lire")

code, corps_w, brut_w = whoami(PORT4)
egal(code, 200, "/_whoami répond sur un état neuf")
egal(corps_w.get("ecriture_armee"), True,
     "INFOMANIAK_WRITE=1 seul arme encore l'écriture : l'environnement reste "
     "une valeur d'AMORÇAGE")
egal(corps_w.get("achat_arme"), True, "INFOMANIAK_ACHAT=1 seul arme encore l'achat")
ok(JETON_AMORCE not in brut_w and COMPTE_AMORCE not in brut_w,
   "et /_whoami ne dit toujours ni le jeton ni le compte")

code, _, page = demande(PORT4, "GET", "/config", IDENTITE)
egal(code, 200, "la page se rend sur un état neuf, amorcé par l'environnement")
ok(JETON_AMORCE not in page,
   "le jeton d'amorçage n'est pas rendu non plus : sa provenance ne change "
   "rien à ce qu'on en montre")
ok(JETON_AMORCE[-4:] in page,
   "mais la page dit qu'un jeton est présent (ses quatre derniers caractères)")
f, c = form_avec(page, MOTS_PLAFOND, types=("number", "text"))
ok(c is not None and c["valeur"].strip() in ("33", "33.0", "33,0"),
   "le plafond d'amorçage est celui que la page montre — obtenu %r"
   % (c and c["valeur"]))

# Le secret ne doit pas non plus tomber dans la sortie d'erreur du serveur :
# une ligne de journalisation distraite est un secret exposé aussi sûrement
# qu'un champ pré-rempli.
traces = "".join(texte_brut(c) for c in JOURNAUX.values())
ok(JETON_A not in traces and JETON_B not in traces and JETON_AMORCE not in traces,
   "aucun jeton n'apparaît dans la sortie d'erreur du serveur")

ok(serveur.poll() is None, "le serveur d'amorçage est encore vivant à la fin")

for p in list(PROCESSUS):
    arreter(p)
for dossier in (ETAT, NEUF):
    shutil.rmtree(dossier, ignore_errors=True)
for chemin in JOURNAUX.values():
    try:
        os.unlink(chemin)
    except OSError:
        pass


rendre()
