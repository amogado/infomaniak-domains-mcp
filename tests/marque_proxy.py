"""La marque du proxy : le contrat entre le banc d'essai et le serveur.

D1 remplace « une trace d'authentification, quelle qu'elle soit » par « une
marque que seul Traefik peut produire ». Une marque partagée est un secret que
deux fichiers doivent nommer pareil sans jamais s'importer : le serveur la lit
dans son environnement, le banc d'essai la pose. Ce module est le seul endroit
du dépôt où ce contrat est écrit — un renommage se corrige ici, une fois.

Le banc ne devine pas le nom : il **sonde**. Il pose la même valeur sous chaque
nom d'environnement plausible, essaie chaque en-tête plausible, et garde celui
qui ouvre la porte. Ce n'est pas de la complaisance : ce qui protège la page
d'autorisation n'est pas le NOM de l'en-tête — un inconnu peut écrire n'importe
quel en-tête — mais sa VALEUR, qu'il ne peut pas produire. Une sonde qui
cherche le nom n'affaiblit donc rien, tandis qu'un nom deviné en dur ferait
virer au rouge un correctif parfaitement juste.

`ANCIEN_REGIME` est la façon d'entrer d'avant D1 : le Basic rejoué par le
navigateur. Elle reste dans la liste des candidats pour que le banc traverse
les deux mondes — mais `check_durcissement.py` exige, lui, qu'elle ne suffise
plus.
"""

import base64

# Ce que le banc pose comme marque. Sa valeur n'a d'importance que par le fait
# qu'un attaquant ne l'a pas : elle est fixe pour que deux exécutions se
# comparent, et assez longue pour n'être pas devinable par accident.
VALEUR = "marque-de-banc-d-essai-3f8a1c9d4b7e2065"

# L'identité humaine d'avant D1, telle que Traefik la vérifiait.
ANCIEN_REGIME = {"Authorization": "Basic " + base64.b64encode(b"vincent:secret").decode()}

# Les noms sous lesquels le serveur peut lire la marque attendue.
NOMS_ENV = (
    "INFOMANIAK_MARQUE",
    "INFOMANIAK_MARQUE_PROXY",
    "INFOMANIAK_PROXY_MARQUE",
    "INFOMANIAK_MARQUE_HUMAIN",
    "INFOMANIAK_HUMAIN_MARQUE",
    "INFOMANIAK_PROXY_SECRET",
)

# Les en-têtes sous lesquels le proxy peut la poser.
NOMS_ENTETE = (
    "X-Infomaniak-Marque",
    "X-Marque-Proxy",
    "X-Proxy-Marque",
    "X-Marque",
    "X-Infomaniak-Proxy",
    "X-Humain-Marque",
)


def env():
    """L'environnement à donner au serveur pour qu'il connaisse la marque."""
    return {nom: VALEUR for nom in NOMS_ENV}


def navigation():
    """Ce qu'un navigateur pose sur une VRAIE navigation.

    D9 refuse à /authorize tout ce qui n'en est pas une. Un banc d'essai qui
    n'envoie aucun `Sec-Fetch-*` ressemble alors à une balise `<img>` — et le
    correctif ferait virer au rouge des tests qui n'ont rien à voir avec lui.
    """
    return {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin"}


def candidats(valeur=VALEUR):
    """Toutes les façons plausibles d'annoncer « je viens du proxy »."""
    liste = [{nom: valeur} for nom in NOMS_ENTETE]
    liste.append(dict(ANCIEN_REGIME))
    return liste


def trouver(sonde):
    """La première façon d'entrer que le serveur accepte, ou None.

    `sonde(entetes)` doit rendre vrai quand la page humaine est servie."""
    for entetes in candidats():
        if sonde(entetes):
            return entetes
    return None
