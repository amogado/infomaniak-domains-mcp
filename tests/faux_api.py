"""Une fausse API Infomaniak, servie en local.

Elle imite ce qui compte : l'enveloppe `{"result": ..., "data": ...}`, l'entête
`Authorization: Bearer`, les codes d'erreur, et la forme exacte des chemins
relevés dans la spec OpenAPI publiée sur developer.infomaniak.com.

Elle *enregistre chaque requête reçue*. C'est le point : un test qui vérifie
qu'un garde-fou a bloqué une écriture doit constater qu'aucune requête n'est
partie, pas seulement qu'un message d'erreur est revenu. Les deux ne disent pas
la même chose — le second passe encore si l'écriture est faite puis regrettée.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JETON = "jeton-de-test"

RECU = []          # toutes les requêtes vues, dans l'ordre
VERROU = threading.Lock()

# état mutable, remis à neuf par `remise_a_zero`
ETAT = {}


def remise_a_zero():
    with VERROU:
        RECU.clear()
        ETAT.clear()
        ETAT.update({
            "comptes": [{"id": 4242, "name": "Compte de test"}],
            "domaines": [
                {"id": 1, "customer_name": "exemple.ch", "expired_at": 1800000000},
                {"id": 2, "customer_name": "exemple.fr", "expired_at": 1800000000},
            ],
            "zones": {"exemple.ch": [{"id": 9, "fqdn": "exemple.ch"}]},
            "enregistrements": {
                "exemple.ch": [
                    {"id": 101, "source": "", "type": "A", "target": "95.217.21.250",
                     "ttl": 3600, "updated_at": 1700000000},
                    {"id": 102, "source": "www", "type": "CNAME", "target": "exemple.ch.",
                     "ttl": 3600, "updated_at": 1700000000},
                    {"id": 103, "source": "", "type": "MX", "target": "10 mail.exemple.ch.",
                     "ttl": 3600, "updated_at": 1700000000},
                ]
            },
            "prochain_id": 200,
            "libres": {"kiosquier.ch": True, "exemple.ch": False},
            # forçages, pour éprouver les chemins d'erreur
            "force_code": None,
            "force_corps": None,
        })


remise_a_zero()


def requetes(methode=None, chemin_contient=None):
    """Les requêtes reçues, filtrables. C'est l'instrument de mesure des tests."""
    with VERROU:
        vues = list(RECU)
    if methode:
        vues = [r for r in vues if r["methode"] == methode]
    if chemin_contient:
        vues = [r for r in vues if chemin_contient in r["chemin"]]
    return vues


class Poignee(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):          # silence
        pass

    # ---- plomberie ----------------------------------------------------
    def _rend(self, code, charge):
        corps = json.dumps(charge).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def _succes(self, data):
        self._rend(200, {"result": "success", "data": data})

    def _echec(self, code, code_erreur, description):
        self._rend(code, {"result": "error",
                          "error": {"code": code_erreur, "description": description}})

    def _corps(self):
        taille = int(self.headers.get("Content-Length") or 0)
        if not taille:
            return None
        try:
            return json.loads(self.rfile.read(taille).decode("utf-8"))
        except ValueError:
            return None

    def _route(self, methode):
        from urllib.parse import urlparse, parse_qs, unquote
        decoupe = urlparse(self.path)
        chemin = decoupe.path
        params = parse_qs(decoupe.query)
        corps = self._corps()

        with VERROU:
            RECU.append({"methode": methode, "chemin": chemin, "params": params,
                         "corps": corps,
                         "autorisation": self.headers.get("Authorization") or "",
                         "content_type": self.headers.get("Content-Type") or ""})

        # forçage d'erreur, pour éprouver les chemins d'échec
        if ETAT["force_code"]:
            code = ETAT["force_code"]
            ETAT["force_code"] = None
            if ETAT["force_corps"] is not None:
                brut = ETAT["force_corps"].encode("utf-8")
                ETAT["force_corps"] = None
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(brut)))
                self.end_headers()
                self.wfile.write(brut)
                return
            return self._echec(code, "force", "erreur forcée par le test")

        if self.headers.get("Authorization") != "Bearer " + JETON:
            return self._echec(401, "not_authorized", "jeton invalide")

        seg = [unquote(s) for s in chemin.strip("/").split("/")]

        # /1/accounts
        if seg == ["1", "accounts"] and methode == "GET":
            return self._succes(ETAT["comptes"])

        # /2/domains/domains
        if seg == ["2", "domains", "domains"] and methode == "GET":
            liste = ETAT["domaines"]
            cherche = (params.get("search") or [""])[0]
            if cherche:
                liste = [d for d in liste if cherche in d["customer_name"]]
            tld = (params.get("tld") or [""])[0]
            if tld:
                liste = [d for d in liste if d["customer_name"].endswith("." + tld)]
            return self._succes(liste)

        # /2/domains/domains/{domain}
        if len(seg) == 4 and seg[:3] == ["2", "domains", "domains"] and methode == "GET":
            for d in ETAT["domaines"]:
                if d["customer_name"] == seg[3]:
                    return self._succes(d)
            return self._echec(404, "not_found", "domaine inconnu")

        # /2/domains/domains/{domain}/zones
        if len(seg) == 5 and seg[:3] == ["2", "domains", "domains"] and seg[4] == "zones":
            return self._succes(ETAT["zones"].get(seg[3], []))

        # /2/domains/domains/{domain}/dnssec/check
        if len(seg) == 6 and seg[4] == "dnssec" and seg[5] == "check":
            return self._succes({"domain": seg[3], "enabled": False})

        # /2/domains/domains/{domain}/nameservers
        if len(seg) == 5 and seg[4] == "nameservers" and methode == "PUT":
            noms = (corps or {}).get("nameservers") or []
            return self._succes({"domain": seg[3], "nameservers": noms})

        # /2/domains/accounts/{account}/check
        if len(seg) == 5 and seg[:3] == ["2", "domains", "accounts"] and seg[4] == "check":
            nom = (corps or {}).get("domain") or ""
            if "." not in nom:
                return self._echec(400, "subdomain_availability_check_fail",
                                   "ce n'est pas un domaine")
            # Forme relevée sur la VRAIE API le 2026-08-30. La première version
            # de cette réponse était inventée — `available`, `price` — parce
            # que l'OpenAPI ne décrit ici que l'enveloppe générique. Le vrai dit
            # `is_available`, range les prix sous `action.pricing`, et surtout
            # distingue le prix de première période du prix de renouvellement,
            # qui est le coût récurrent et vaut souvent le double.
            libre = ETAT["libres"].get(nom, True)
            data = {"domain": nom, "is_available": libre, "need_transfer": False,
                    "status": "registration" if libre else "hosting",
                    "is_premium": bool(ETAT.get("premium", {}).get(nom))}
            if libre:
                premiere = ETAT.get("prix_premiere", 6.0)
                renouv = ETAT.get("prix_renouvellement", 9.9)
                data["action"] = {
                    "name": "registration",
                    "pricing": {
                        "currency": "EUR",
                        "registration_periods": list(range(1, 11)),
                        "prices": {
                            "registration": {"amount_excl_tax": premiere,
                                             "amount_base_excl_tax": renouv},
                            "renew": {"amount_excl_tax": renouv,
                                      "amount_base_excl_tax": renouv},
                            "transfer": {"amount_excl_tax": 0, "amount_base_excl_tax": 0},
                        },
                        "registration_period_prices": [
                            {"period": p,
                             "amount_excl_tax": round(premiere + (p - 1) * renouv, 2),
                             "amount_base_excl_tax": round(p * renouv, 2)}
                            for p in range(1, 11)],
                    },
                }
                if (corps or {}).get("with_option_prices"):
                    data["action"]["pricing"]["options"] = {"domain_privacy": 5.0}
            return self._succes(data)

        # /2/zones/{zone}/records  et /2/zones/{zone}/records/{id}
        if len(seg) >= 4 and seg[:2] == ["2", "zones"] and seg[3] == "records":
            zone = seg[2]
            recs = ETAT["enregistrements"].setdefault(zone, [])
            if len(seg) == 4 and methode == "GET":
                return self._succes(recs)
            if len(seg) == 4 and methode == "POST":
                nouveau = dict(corps or {})
                nouveau["id"] = ETAT["prochain_id"]
                ETAT["prochain_id"] += 1
                nouveau.setdefault("source", "")
                nouveau["updated_at"] = 1700000001
                recs.append(nouveau)
                return self._succes(nouveau)
            if len(seg) >= 5:
                try:
                    ident = int(seg[4])
                except ValueError:
                    return self._echec(404, "not_found", "identifiant illisible")
                trouve = next((r for r in recs if r["id"] == ident), None)
                if len(seg) == 6 and seg[5] == "check" and methode == "GET":
                    if not trouve:
                        return self._echec(404, "not_found", "enregistrement inconnu")
                    return self._succes({"id": ident, "resolved": True})
                if not trouve:
                    return self._echec(404, "not_found", "enregistrement inconnu")
                if methode == "PUT":
                    trouve.update({k: v for k, v in (corps or {}).items()})
                    return self._succes(trouve)
                if methode == "DELETE":
                    recs.remove(trouve)
                    return self._succes(True)

        return self._echec(404, "not_found", "chemin inconnu : " + chemin)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")


def demarre():
    """Lance la fausse API sur un port libre. Rend (serveur, base_url)."""
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Poignee)
    fil = threading.Thread(target=serveur.serve_forever, daemon=True)
    fil.start()
    return serveur, "http://127.0.0.1:%d" % serveur.server_address[1]
