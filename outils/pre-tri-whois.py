#!/usr/bin/env python3
"""Un premier tri par whois — utile avant même d'avoir un jeton d'API.

whois dit « libre ou pris » ; il ne dit ni le prix, ni si le nom est réservable.
L'outil `disponibilite` du serveur MCP, lui, répond les deux — mais il demande
un jeton. Ce script sert donc à dégrossir une liste de candidats en amont.

    python3 outils/pre-tri-whois.py exemple.ch exemple.fr …

Piège corrigé ici, et qui vaut d'être connu : quand le client whois ne suit pas
la délégation vers le registre, il rend la fiche du **TLD** au lieu de celle du
domaine. Cette fiche contient « domain: CH » et « organisation: … », de sorte
qu'une détection naïve du motif « ce domaine a un titulaire » y mord et déclare
occupé un nom parfaitement libre. Le repère est que la valeur de « domain: »
est le TLD lui-même ; on retombe alors sur les serveurs de noms, qui tranchent.

Et un « libre » reste un indice, pas une preuve : un domaine en période de
rédemption n'a pas non plus de serveurs de noms.
"""
import concurrent.futures as futures
import re
import subprocess
import sys


LIBRE = re.compile(
    r"no match|not found|no data found|no entries found|aucun objet|"
    r"statut:\s*(libre|available)|domain not found|not registered|"
    r"^no object found|is free|available for (registration|purchase)",
    re.I | re.M)
PRIS = re.compile(
    r"^\s*(domain name|domaine|nom de domaine|registrar|registrant|"
    r"creation date|created|created on|statut|status)\s*:", re.I | re.M)


def regarde(nom):
    try:
        out = subprocess.run(["whois", nom], capture_output=True, text=True,
                             timeout=25)
        texte = (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        return nom, "incertain", "whois n'a pas répondu en 25 s"
    except Exception as err:
        return nom, "incertain", str(err)[:60]
    if not texte.strip():
        return nom, "incertain", "réponse vide"

    # Piège : quand le client whois ne suit pas la délégation, il rend la fiche
    # du TLD au lieu de celle du domaine. Cette fiche contient « domain: CH » et
    # « organisation: … », donc le motif « pris » y mord et déclare occupé un
    # nom parfaitement libre. On le repère au fait que la valeur de « domain: »
    # est le TLD lui-même, et on retombe alors sur les serveurs de noms.
    tld = nom.rsplit(".", 1)[1]
    fiche_du_tld = re.search(r"^domain:\s*%s\s*$" % re.escape(tld), texte,
                             re.I | re.M)
    if fiche_du_tld:
        ns = subprocess.run(["dig", "+short", "NS", nom], capture_output=True,
                            text=True, timeout=20).stdout.strip()
        if ns:
            return nom, "pris", "délégué : " + ns.splitlines()[0]
        return nom, "LIBRE", "whois muet, aucun serveur de noms"

    if LIBRE.search(texte):
        return nom, "LIBRE", ""
    if "status: active" in texte.lower() or PRIS.search(texte):
        titulaire = ""
        m = re.search(r"^\s*(registrar|registrar name)\s*:\s*(.+)$", texte, re.I | re.M)
        if m:
            titulaire = m.group(2).strip()[:40]
        return nom, "pris", titulaire
    return nom, "incertain", texte.strip().splitlines()[0][:60]


candidats = sys.argv[1:]
if not candidats:
    sys.exit("usage : pre-tri-whois.py <domaine> [<domaine>…]")

with futures.ThreadPoolExecutor(max_workers=8) as pool:
    resultats = list(pool.map(regarde, candidats))

for etat in ("LIBRE", "incertain", "pris"):
    lot = [r for r in resultats if r[1] == etat]
    if not lot:
        continue
    print("\n=== %s (%d) ===" % (etat, len(lot)))
    for nom, _, note in lot:
        print("  %-22s %s" % (nom, note))
