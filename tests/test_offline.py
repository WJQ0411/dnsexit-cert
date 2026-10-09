"""Offline unit tests for acme-dnsexit.

None of these tests touch the network: the ACME client and the DNSExit API
are replaced by fakes.  Run with::

    python3 -m unittest discover -s tests -v
    # or simply
    python3 tests/test_offline.py
"""

from __future__ import annotations

import datetime
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme import challenges, messages  # noqa: E402
import dns.message  # noqa: E402
import dns.rrset  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
import josepy as jose  # noqa: E402

import acme_dnsexit as m  # noqa: E402
from dnsexit import DNSExitClient, DNSExitError  # noqa: E402

DOMAIN = "example.com"
FQDN = "_acme-challenge.example.com"


def _leaf_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class DNSExitClientTests(unittest.TestCase):
    def test_zone_candidates(self):
        cands = DNSExitClient._candidates("_acme-challenge.www.example.com")
        self.assertEqual(cands[0], ("_acme-challenge.www.example.com", ""))
        self.assertIn(("example.com", "_acme-challenge.www"), cands)

    def test_zone_discovery_and_cache(self):
        client = DNSExitClient("KEY")
        calls = []

        def fake_post(payload):
            calls.append(payload)
            if payload["domain"] == "example.com":
                return {"code": 0, "message": "Success"}
            return {"code": 5, "message": "unknown zone"}

        client._post = fake_post
        self.assertEqual(client.add_txt("_acme-challenge.www.example.com", "V1"),
                         ("example.com", "_acme-challenge.www"))
        # second add reuses the cached zone (1 additional call, no probing)
        client.add_txt("_acme-challenge.www.example.com", "V2")
        self.assertEqual(len(calls), 4)

    def test_add_uses_overwrite_false(self):
        client = DNSExitClient("KEY")
        sent = {}

        def fake_post(payload):
            if payload["domain"] != "example.com":
                return {"code": 5, "message": "unknown zone"}
            sent.update(payload)
            return {"code": 0, "message": "ok"}

        client._post = fake_post
        client.add_txt(FQDN, "V", ttl=2)
        self.assertFalse(sent["add"]["overwrite"])
        self.assertEqual(sent["add"]["ttl"], 2)
        self.assertEqual(sent["domain"], "example.com")
        self.assertEqual(sent["add"]["name"], "_acme-challenge")

    def test_delete_carries_content(self):
        client = DNSExitClient("KEY")
        sent = {}

        def fake_post(payload):
            if payload["domain"] != "example.com":
                return {"code": 5, "message": "unknown zone"}
            sent.clear()
            sent.update(payload)
            return {"code": 0}

        client._post = fake_post
        client.add_txt(FQDN, "V")
        client.delete_txt(FQDN, "V", zone="example.com")
        self.assertEqual(sent["delete"]["content"], "V")
        self.assertEqual(sent["delete"]["name"], "_acme-challenge")

    def test_invalid_zone_override(self):
        client = DNSExitClient("KEY")
        with self.assertRaises(DNSExitError):
            client.add_txt(FQDN, "V", zone_override="other.com")

    def test_fresh_run_failure_is_clear(self):
        client = DNSExitClient("KEY")
        # code 5 = record type / zone not supported for every candidate
        client._post = lambda p: {"code": 5, "message": "bad"}
        with self.assertRaises(DNSExitError):
            client.add_txt(FQDN, "V")

    def test_existing_record_is_tolerated(self):
        # Unknown zones -> code 5; the real zone reports code 1 because the
        # record already exists.  We should assume success and let the
        # propagation check decide.
        client = DNSExitClient("KEY")

        def fake_post(payload):
            if payload["domain"] == "example.com":
                return {"code": 1, "message": "already exists"}
            return {"code": 5, "message": "unknown zone"}

        client._post = fake_post
        self.assertEqual(client.add_txt(FQDN, "V"),
                         ("example.com", "_acme-challenge"))


class ConfigTests(unittest.TestCase):
    def test_merge_cli_over_file(self):
        with tempfile.TemporaryDirectory() as d:
            cfgfile = os.path.join(d, "c.json")
            with open(cfgfile, "w") as fh:
                import json
                json.dump({"api_key": "FILE", "email": "file@x.com",
                           "domains": ["file.example.com"],
                           "output_dir": os.path.join(d, "out"),
                           "key_type": "rsa", "rsa_key_size": 3072}, fh)
            args = m.build_parser().parse_args(
                ["--config", cfgfile, "--email", "cli@x.com",
                 "--domain", "a.example.com", "--staging"])
            cfg = m.build_config(args)
            self.assertEqual(cfg.api_key, "FILE")
            self.assertEqual(cfg.email, "cli@x.com")
            self.assertEqual(cfg.domains, ["a.example.com"])
            self.assertEqual(cfg.key_type, "rsa")
            self.assertEqual(cfg.rsa_key_size, 3072)
            self.assertEqual(cfg.directory_url, m.LETSENCRYPT_STAGING)
            self.assertEqual(cfg.account_key, os.path.join(d, "out", "account.key"))
            m.validate_config(cfg)

    def test_empty_config_fails_validation(self):
        with self.assertRaises(SystemExit):
            m.validate_config(m.Config())

    def _cfg(self, argv):
        args = m.build_parser().parse_args(argv)
        if args.dns_resolvers:
            args.dns_resolvers = [x for i in args.dns_resolvers
                                  for x in i.split(",") if x.strip()]
        if args.doh_url:
            args.doh_url = [x for i in args.doh_url
                            for x in i.split(",") if x.strip()]
        return m.build_config(args)

    def test_doh_default_endpoints(self):
        cfg = self._cfg(["--domain", "a.com", "--doh"])
        self.assertEqual(cfg.dns_resolvers, m.DEFAULT_DOH_RESOLVERS)

    def test_doh_custom_urls_imply_doh(self):
        cfg = self._cfg(["--domain", "a.com", "--doh-url",
                         "https://dns.quad9.net/dns-query,https://doh.example/x"])
        self.assertEqual(cfg.dns_resolvers,
                         ["https://dns.quad9.net/dns-query", "https://doh.example/x"])

    def test_doh_mixes_with_explicit_classic(self):
        cfg = self._cfg(["--domain", "a.com", "--dns-resolvers", "9.9.9.9",
                         "--doh"])
        self.assertEqual(cfg.dns_resolvers[0], "9.9.9.9")
        for url in m.DEFAULT_DOH_RESOLVERS:
            self.assertIn(url, cfg.dns_resolvers)

    def test_doh_url_inline_in_resolvers(self):
        cfg = self._cfg(["--domain", "a.com", "--dns-resolvers",
                         "1.1.1.1,https://dns.google/dns-query"])
        self.assertEqual(cfg.dns_resolvers,
                         ["1.1.1.1", "https://dns.google/dns-query"])

    def test_doh_config_file(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            with open(path, "w") as fh:
                json.dump({"api_key": "K", "email": "a@b.com",
                           "domains": ["a.com"], "doh": True,
                           "doh_resolvers": ["https://doh.mine/q"]}, fh)
            cfg = self._cfg(["--config", path])
            self.assertEqual(cfg.dns_resolvers, ["https://doh.mine/q"])

    def test_doh_disabled_keeps_classic(self):
        cfg = self._cfg(["--domain", "a.com"])
        self.assertEqual(cfg.dns_resolvers, m.DEFAULT_RESOLVERS)


class PropagationTests(unittest.TestCase):
    def test_retries_until_visible(self):
        cfg = m.Config(propagation_timeout=30, propagation_interval=1)
        state = {"n": 0}

        def fake_query(name, resolvers):
            state["n"] += 1
            return {"GOOD"} if state["n"] >= 2 else set()

        with mock.patch.object(m, "query_txt", fake_query):
            m.wait_for_propagation([(FQDN, "GOOD")], cfg)
        self.assertGreaterEqual(state["n"], 2)

    def test_timeout(self):
        cfg = m.Config(propagation_timeout=1, propagation_interval=1)
        with mock.patch.object(m, "query_txt", lambda n, r: set()):
            with self.assertRaises(SystemExit):
                m.wait_for_propagation([(FQDN, "NOPE")], cfg)

    def test_skip(self):
        cfg = m.Config(skip_propagation_check=True, propagation_timeout=1)
        m.wait_for_propagation([(FQDN, "NOPE")], cfg)  # must not raise


class CertificateFormatTests(unittest.TestCase):
    def test_save_certificate(self):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = _leaf_pem()
        with tempfile.TemporaryDirectory() as d:
            m.save_certificate(d, pem + "\n" + pem, m.key_to_pem(key))
            for name in ("fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"):
                self.assertTrue(os.path.exists(os.path.join(d, name)), name)
            mode = os.stat(os.path.join(d, "privkey.pem")).st_mode & 0o777
            self.assertEqual(mode, 0o600)


# --------------------------------------------------------------------------- #
# Full offline integration
# --------------------------------------------------------------------------- #
def _make_authz(uri, wildcard, token):
    return messages.AuthorizationResource.from_json({
        "uri": uri,
        "body": {
            "identifier": {"type": "dns", "value": DOMAIN},
            "status": "pending",
            "wildcard": wildcard,
            "challenges": [{"type": "dns-01", "url": uri + "/c",
                            "status": "pending", "token": token}],
        },
        "new_cert_uri": None,
    })


class _FakeDNS:
    instances = []

    def __init__(self, api_key, timeout=30):
        self.added = []
        self.deleted = []
        _FakeDNS.instances.append(self)

    def add_txt(self, fqdn, value, ttl=1, zone_override=None):
        self.added.append((fqdn, value))
        return "example.com", fqdn[: -len("." + DOMAIN)]

    def delete_txt(self, fqdn, value, zone=None):
        self.deleted.append((fqdn, value))

    def close(self):
        pass


class _FakeNet:
    def __init__(self, key, **kwargs):
        self.key = key

    def get(self, url):
        class _Resp:
            def json(self):
                return {"newAccount": "x", "newOrder": "y"}
        return _Resp()


class _FakeACME:
    def __init__(self, directory, net):
        self.answered = []

    def new_order(self, csr_pem):
        a1 = _make_authz("https://acme/authz/1", True, "a" * 24)
        a2 = _make_authz("https://acme/authz/2", False, "b" * 24)
        body = messages.Order(status="pending",
                              authorizations=[a1.uri, a2.uri],
                              identifiers=[], finalize="https://acme/finalize")
        return messages.OrderResource(body=body, uri="https://acme/order/1",
                                      authorizations=(a1, a2), csr_pem=csr_pem,
                                      fullchain_pem=None)

    def answer_challenge(self, challb, response):
        self.answered.append(challb.uri)

    def poll_and_finalize(self, orderr, deadline):
        return orderr.update(fullchain_pem=_leaf_pem())


class FullFlowTests(unittest.TestCase):
    def test_wildcard_and_apex(self):
        _FakeDNS.instances.clear()
        with mock.patch.object(m, "DNSExitClient", _FakeDNS), \
             mock.patch.object(m, "ClientNetwork", _FakeNet), \
             mock.patch.object(m.acme_client, "ClientV2", _FakeACME), \
             mock.patch.object(m, "register_account", lambda a, e: object()), \
             mock.patch.object(m, "wait_for_propagation", lambda r, c: None):
            with tempfile.TemporaryDirectory() as d:
                cfg = m.Config(api_key="K", email="a@b.com",
                               domains=[DOMAIN, "*." + DOMAIN], output_dir=d)
                cfg.account_key = os.path.join(d, "account.key")
                cfg.cert_key = os.path.join(d, "privkey.pem")
                m.obtain_certificate(cfg)

                dns = _FakeDNS.instances[-1]
                # Both authorizations share one record name but need distinct
                # values, so two TXT records must be created there.
                self.assertEqual(len(dns.added), 2)
                self.assertEqual({f for f, _ in dns.added}, {FQDN})
                self.assertEqual(len({v for _, v in dns.added}), 2)
                self.assertEqual(set(dns.deleted), set(dns.added))
                for name in ("fullchain.pem", "cert.pem", "privkey.pem",
                             "account.key"):
                    self.assertTrue(os.path.exists(os.path.join(d, name)), name)

    def test_cleanup_skipped(self):
        _FakeDNS.instances.clear()
        with mock.patch.object(m, "DNSExitClient", _FakeDNS), \
             mock.patch.object(m, "ClientNetwork", _FakeNet), \
             mock.patch.object(m.acme_client, "ClientV2", _FakeACME), \
             mock.patch.object(m, "register_account", lambda a, e: object()), \
             mock.patch.object(m, "wait_for_propagation", lambda r, c: None):
            with tempfile.TemporaryDirectory() as d:
                cfg = m.Config(api_key="K", email="a@b.com", domains=[DOMAIN],
                               output_dir=d, no_cleanup=True)
                cfg.account_key = os.path.join(d, "account.key")
                cfg.cert_key = os.path.join(d, "privkey.pem")
                m.obtain_certificate(cfg)
                self.assertEqual(_FakeDNS.instances[-1].deleted, [])


class DoHQueryTests(unittest.TestCase):
    FQDN = FQDN
    VALUE = "TXT-VALUE-123"

    @staticmethod
    def _wire(fqdn, txt):
        query = dns.message.make_query(fqdn, "TXT")
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text(fqdn + ".", 60, "IN", "TXT", f'"{txt}"'))
        return response.to_wire()

    def test_rfc8484_wire_query(self):
        class FakeResp:
            content = DoHQueryTests._wire(DoHQueryTests.FQDN,
                                          DoHQueryTests.VALUE)

            def raise_for_status(self):
                pass

        captured = {}

        def fake_get(url, params=None, headers=None, timeout=None):
            captured.update(url=url, params=params, headers=headers)
            return FakeResp()

        with mock.patch.object(m.requests, "get", fake_get):
            values = m._doh_query_txt(DoHQueryTests.FQDN,
                                      "https://dns.google/dns-query")
        self.assertEqual(values, {DoHQueryTests.VALUE})
        self.assertEqual(captured["headers"]["Accept"], "application/dns-message")
        self.assertIn("dns", captured["params"])

    def test_query_txt_unions_classic_and_doh(self):
        with mock.patch.object(m, "_classic_query_txt", lambda f, ns: {"CLASSIC"}), \
             mock.patch.object(m, "_doh_query_txt", lambda f, u: {"DOH"}):
            values = m.query_txt(FQDN, ["1.1.1.1",
                                        "https://dns.google/dns-query"])
        self.assertEqual(values, {"CLASSIC", "DOH"})

    def test_broken_doh_is_tolerated(self):
        def boom(*a, **k):
            raise RuntimeError("network down")

        with mock.patch.object(m, "_classic_query_txt", lambda f, ns: {"CLASSIC"}), \
             mock.patch.object(m, "_doh_query_txt", boom):
            values = m.query_txt(FQDN, ["1.1.1.1", "https://bad.example/q"])
        self.assertEqual(values, {"CLASSIC"})

    def test_classic_falls_back_to_system_resolver(self):
        with mock.patch.object(m, "_classic_query_txt", lambda f, ns: {"SYS"}):
            self.assertEqual(m.query_txt(FQDN, []), {"SYS"})


class ChallengeMathTests(unittest.TestCase):
    def test_dns01(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jose.JWKRSA(key=key)
        chall = challenges.DNS01(token=b"1234567890abcdef")
        value = chall.validation(jwk)
        self.assertEqual(len(value), 43)
        self.assertEqual(chall.validation_domain_name(DOMAIN), FQDN)
        self.assertEqual(chall.response(jwk).key_authorization,
                         chall.response(jwk).key_authorization)


if __name__ == "__main__":
    unittest.main(verbosity=2)
