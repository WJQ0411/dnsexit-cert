#!/usr/bin/env python3
"""Obtain Let's Encrypt certificates using the DNS-01 challenge with DNSExit.

This is a small, self-contained ACME client that talks to the DNSExit DNS API
to create the ``_acme-challenge`` TXT records required for the DNS-01
validation.  It can issue both regular and wildcard certificates.

Examples
--------
Staging, wildcard + apex, new key::

    python3 acme_dnsexit.py \\
        --api-key "$DNSEXIT_API_KEY" \\
        --email you@example.com \\
        --staging \\
        --domain example.com --domain '*.example.com' \\
        --output-dir ./certs/example.com

Production renewal (reuses the keys in the output directory)::

    python3 acme_dnsexit.py --config config.json

"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import logging
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import dns.exception
import dns.message
import dns.rdatatype
import dns.resolver
import josepy as jose
import requests
from acme import challenges as acme_challenges
from acme import client as acme_client
from acme import crypto_util, errors, messages
from acme.client import ClientNetwork
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography import x509

from dnsexit import DNSExitClient, DNSExitError

log = logging.getLogger("acme-dnsexit")

VERSION = "1.0.0"

LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Public DNS-over-HTTPS endpoints used when --doh/--doh-url is requested
# without a custom endpoint.
DEFAULT_DOH_RESOLVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]


def _dedupe(items: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    api_key: str = ""
    email: str = ""
    domains: List[str] = field(default_factory=list)
    directory_url: str = LETSENCRYPT_PRODUCTION
    output_dir: str = "./certs"
    account_key: str = ""
    cert_key: str = ""
    key_type: str = "ecdsa"
    rsa_key_size: int = 2048
    elliptic_curve: str = "secp256r1"
    ttl: int = 1
    propagation_timeout: int = 300
    propagation_interval: int = 10
    dns_resolvers: List[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    skip_propagation_check: bool = False
    finalize_timeout: int = 120
    no_cleanup: bool = False
    zones: Dict[str, str] = field(default_factory=dict)
    http_timeout: int = 30


def load_config_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _first(*values):
    for value in values:
        if value is not None:
            return value
    return None


def build_config(args: argparse.Namespace) -> Config:
    file_cfg: dict = {}
    if args.config:
        file_cfg = load_config_file(args.config)

    cfg = Config()

    cfg.api_key = _first(args.api_key, os.environ.get("DNSEXIT_API_KEY"),
                         file_cfg.get("api_key"), "") or ""
    cfg.email = _first(args.email, os.environ.get("ACME_EMAIL"),
                       file_cfg.get("email"), "") or ""
    cfg.domains = list(_first(args.domain, file_cfg.get("domains"), []) or [])
    cfg.directory_url = _first(args.directory, file_cfg.get("directory_url"),
                               cfg.directory_url)
    if args.staging:
        cfg.directory_url = LETSENCRYPT_STAGING
    if args.production:
        cfg.directory_url = LETSENCRYPT_PRODUCTION

    cfg.output_dir = _first(args.output_dir, file_cfg.get("output_dir"),
                            cfg.output_dir)
    cfg.account_key = _first(args.account_key, file_cfg.get("account_key"), "") or ""
    cfg.cert_key = _first(args.cert_key, file_cfg.get("cert_key"), "") or ""

    if args.key_type is not None:
        cfg.key_type = args.key_type
    elif "key_type" in file_cfg:
        cfg.key_type = file_cfg["key_type"]

    cfg.rsa_key_size = int(_first(args.rsa_key_size, file_cfg.get("rsa_key_size"),
                                  cfg.rsa_key_size))
    cfg.elliptic_curve = _first(args.elliptic_curve, file_cfg.get("elliptic_curve"),
                                cfg.elliptic_curve)
    cfg.ttl = int(_first(args.ttl, file_cfg.get("ttl"), cfg.ttl))
    cfg.propagation_timeout = int(_first(
        args.propagation_timeout, file_cfg.get("propagation_timeout"),
        cfg.propagation_timeout))
    cfg.propagation_interval = int(_first(
        args.propagation_interval, file_cfg.get("propagation_interval"),
        cfg.propagation_interval))

    resolvers = _first(args.dns_resolvers, file_cfg.get("dns_resolvers"))
    explicit_resolvers = resolvers is not None
    if resolvers:
        cfg.dns_resolvers = [r.strip() for r in resolvers if r.strip()]

    # DNS-over-HTTPS endpoints (https://...).  They may either be mixed
    # directly into dns_resolvers or supplied through the dedicated options
    # below.
    doh_urls: List[str] = list(args.doh_url or [])
    doh_urls.extend(file_cfg.get("doh_resolvers", []) or [])
    doh_urls = [u.strip() for u in doh_urls if u and u.strip()]
    doh_enabled = bool(_first(args.doh, file_cfg.get("doh"), False)) \
        or bool(args.doh_url)

    if doh_enabled:
        if not doh_urls:
            doh_urls = list(DEFAULT_DOH_RESOLVERS)
        if explicit_resolvers:
            cfg.dns_resolvers = _dedupe(cfg.dns_resolvers + doh_urls)
        else:
            cfg.dns_resolvers = _dedupe(doh_urls)

    cfg.skip_propagation_check = bool(_first(
        args.skip_propagation_check, file_cfg.get("skip_propagation_check"), False))
    cfg.finalize_timeout = int(_first(args.finalize_timeout,
                                      file_cfg.get("finalize_timeout"),
                                      cfg.finalize_timeout))
    cfg.no_cleanup = bool(_first(args.no_cleanup, file_cfg.get("no_cleanup"), False))
    cfg.http_timeout = int(_first(args.http_timeout, file_cfg.get("http_timeout"),
                                  cfg.http_timeout))

    zones = dict(file_cfg.get("zones", {}) or {})
    if args.zone:
        zones.setdefault("", args.zone)
    cfg.zones = zones

    # Fallbacks for key paths.
    if not cfg.account_key:
        cfg.account_key = os.path.join(cfg.output_dir, "account.key")
    if not cfg.cert_key:
        cfg.cert_key = os.path.join(cfg.output_dir, "privkey.pem")

    return cfg


def validate_config(cfg: Config) -> None:
    problems = []
    if not cfg.api_key:
        problems.append("DNSExit API key is required (--api-key or DNSEXIT_API_KEY)")
    if not cfg.email:
        problems.append("contact e-mail is required (--email or ACME_EMAIL)")
    if not cfg.domains:
        problems.append("at least one --domain is required")
    if cfg.key_type not in ("rsa", "ecdsa"):
        problems.append(f"unsupported --key-type {cfg.key_type!r}")
    if cfg.key_type == "ecdsa" and cfg.elliptic_curve not in (
            "secp256r1", "secp384r1", "secp521r1"):
        problems.append(f"unsupported --elliptic-curve {cfg.elliptic_curve!r}")
    if cfg.propagation_interval <= 0:
        problems.append("--propagation-interval must be > 0")
    if problems:
        raise SystemExit("Configuration error:\n  - " + "\n  - ".join(problems))


# --------------------------------------------------------------------------- #
# Key helpers
# --------------------------------------------------------------------------- #
def generate_key(key_type: str, rsa_key_size: int, curve: str):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
    curves = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    return ec.generate_private_key(curves[curve])


def key_to_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def write_private(path: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except Exception:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        raise


def write_public(path: str, data: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def load_or_create_key(path: str, key_type: str, rsa_key_size: int,
                       curve: str, label: str):
    if os.path.exists(path):
        log.info("Using existing %s: %s", label, path)
        return load_key(path)
    log.info("Generating new %s (%s)...", label, key_type)
    key = generate_key(key_type, rsa_key_size, curve)
    write_private(path, key_to_pem(key))
    log.info("Saved %s to %s", label, path)
    return key


# --------------------------------------------------------------------------- #
# ACME helpers
# --------------------------------------------------------------------------- #
def register_account(acme: acme_client.ClientV2, email: str):
    try:
        regr = acme.new_account(messages.NewRegistration.from_data(
            email=email, terms_of_service_agreed=True))
        log.info("Registered new ACME account: %s", regr.uri)
        return regr
    except errors.ConflictError as exc:
        log.info("Account already exists, reusing: %s", exc.location)
        placeholder = messages.RegistrationResource(
            uri=exc.location, body=messages.Registration())
        return acme.query_registration(placeholder)


def resolve_zone_override(fqdn: str, zones: Dict[str, str]) -> Optional[str]:
    """Pick the DNSExit zone override whose key is a suffix of ``fqdn``."""
    best_key = None
    for key, zone in zones.items():
        if key == "":
            continue
        if fqdn == key or fqdn.endswith("." + key):
            if best_key is None or len(key) > len(best_key):
                best_key = key
    if best_key is not None:
        return zones[best_key]
    # Fall back to a catch-all entry, if present.
    return zones.get("")


# --------------------------------------------------------------------------- #
# DNS propagation
# --------------------------------------------------------------------------- #
def _is_doh(resolver: str) -> bool:
    return resolver.startswith("http://") or resolver.startswith("https://")


def _classic_query_txt(fqdn: str, nameservers: Sequence[str]) -> set:
    """Query plain DNS (UDP/TCP) and return the TXT strings seen."""
    if nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers)
    else:
        resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(fqdn, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return set()
    values = set()
    for rdata in answer:
        try:
            values.add(b"".join(rdata.strings).decode("utf-8", "replace"))
        except Exception:  # pragma: no cover - defensive
            values.add(str(rdata))
    return values


def _doh_query_txt(fqdn: str, url: str, timeout: float = 5.0) -> set:
    """Query a DNS-over-HTTPS endpoint (RFC 8484) and return TXT strings."""
    query = dns.message.make_query(fqdn, dns.rdatatype.TXT)
    dns_param = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")
    response = requests.get(
        url,
        params={"dns": dns_param},
        headers={"Accept": "application/dns-message"},
        timeout=timeout,
    )
    response.raise_for_status()
    message = dns.message.from_wire(response.content)
    values = set()
    for rrset in message.answer:
        if rrset.rdtype != dns.rdatatype.TXT:
            continue
        for rdata in rrset:
            try:
                values.add(b"".join(rdata.strings).decode("utf-8", "replace"))
            except Exception:  # pragma: no cover - defensive
                values.add(str(rdata))
    return values


def query_txt(fqdn: str, resolvers: Sequence[str]) -> set:
    """Return the union of TXT values seen across all configured resolvers.

    Entries starting with ``http://``/``https://`` are treated as
    DNS-over-HTTPS endpoints; everything else is a plain-DNS server address.
    """
    classic = [r for r in resolvers if not _is_doh(r)]
    doh = [r for r in resolvers if _is_doh(r)]

    values = _classic_query_txt(fqdn, classic)
    for url in doh:
        try:
            values |= _doh_query_txt(fqdn, url)
        except Exception as exc:  # DNS errors must not abort the wait loop
            log.debug("DoH query for %s via %s failed: %s", fqdn, url, exc)
    return values


def wait_for_propagation(records: List[Tuple[str, str]], cfg: Config) -> None:
    """Block until every ``(fqdn, value)`` is visible via the resolvers."""
    if cfg.skip_propagation_check:
        log.warning("Skipping DNS propagation check (--skip-propagation-check)")
        return

    pending = list(records)
    deadline = time.monotonic() + cfg.propagation_timeout
    log.info("Waiting for DNS propagation of %d TXT record(s) via %s ...",
             len(pending), ", ".join(cfg.dns_resolvers))

    while pending:
        for fqdn in sorted({r[0] for r in pending}):
            seen = query_txt(fqdn, cfg.dns_resolvers)
            log.debug("TXT %s -> %s", fqdn, seen or "<none>")
        still_pending = []
        for fqdn, value in pending:
            if value in query_txt(fqdn, cfg.dns_resolvers):
                log.info("  [ok] %s = %s", fqdn, value)
            else:
                still_pending.append((fqdn, value))
        pending = still_pending

        if not pending:
            break
        if time.monotonic() >= deadline:
            names = ", ".join(sorted({r[0] for r in pending}))
            raise SystemExit(
                f"Timed out after {cfg.propagation_timeout}s waiting for TXT "
                f"records to propagate: {names}")
        log.info("  %d record(s) not visible yet, retrying in %ds...",
                 len(pending), cfg.propagation_interval)
        time.sleep(cfg.propagation_interval)


# --------------------------------------------------------------------------- #
# Certificate output
# --------------------------------------------------------------------------- #
PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def save_certificate(output_dir: str, fullchain_pem: str, key_pem: bytes) -> None:
    os.makedirs(output_dir, exist_ok=True)
    certs = PEM_CERT_RE.findall(fullchain_pem)
    if not certs:
        raise SystemExit("ACME server returned no certificate")

    write_public(os.path.join(output_dir, "fullchain.pem"),
                 "\n".join(certs) + "\n")
    write_public(os.path.join(output_dir, "cert.pem"), certs[0] + "\n")
    if len(certs) > 1:
        write_public(os.path.join(output_dir, "chain.pem"),
                     "\n".join(certs[1:]) + "\n")
    write_private(os.path.join(output_dir, "privkey.pem"), key_pem)

    try:
        leaf = x509.load_pem_x509_certificate(certs[0].encode())
        log.info("Certificate issued for: %s",
                 ", ".join(n.value for n in leaf.subject))
        log.info("Valid until: %s", leaf.not_valid_after_utc)
    except Exception:  # pragma: no cover - best effort
        pass

    log.info("Wrote fullchain.pem / cert.pem / chain.pem / privkey.pem to %s",
             output_dir)


# --------------------------------------------------------------------------- #
# Main flow
# --------------------------------------------------------------------------- #
def obtain_certificate(cfg: Config) -> None:
    """Run the full issuance flow, always cleaning up TXT records."""
    dns_client = DNSExitClient(cfg.api_key, timeout=cfg.http_timeout)
    created_records: List[Dict[str, str]] = []
    try:
        _run_issuance(cfg, dns_client, created_records)
    except errors.Error as exc:
        log.error("ACME error: %s", exc)
        for rec in created_records:
            log.error("  pending TXT: %s = %s", rec["fqdn"], rec["value"])
        raise
    finally:
        if created_records and not cfg.no_cleanup:
            log.info("Cleaning up %d TXT record(s)...", len(created_records))
            for rec in created_records:
                dns_client.delete_txt(rec["fqdn"], rec["value"], zone=rec["zone"])
        dns_client.close()


def _run_issuance(cfg: Config, dns_client: DNSExitClient,
                  created_records: List[Dict[str, str]]) -> None:
    # --- Account key + ACME client ------------------------------------- #
    os.makedirs(cfg.output_dir, exist_ok=True)
    account_key = load_or_create_key(cfg.account_key, "rsa", 2048,
                                     "secp256r1", "ACME account key")
    account_jwk = jose.JWKRSA(key=account_key)

    net = ClientNetwork(key=account_jwk,
                        user_agent=f"acme-dnsexit/{VERSION}")
    log.info("Fetching ACME directory: %s", cfg.directory_url)
    directory = messages.Directory.from_json(net.get(cfg.directory_url).json())
    acme = acme_client.ClientV2(directory, net)

    register_account(acme, cfg.email)

    # --- Certificate key + CSR ----------------------------------------- #
    cert_key = load_or_create_key(cfg.cert_key, cfg.key_type, cfg.rsa_key_size,
                                  cfg.elliptic_curve, "certificate key")
    cert_key_pem = key_to_pem(cert_key)
    domains = sorted(set(cfg.domains))
    log.info("Requesting certificate for: %s", ", ".join(domains))
    csr_pem = crypto_util.make_csr(cert_key_pem, domains=domains)

    # --- Create order --------------------------------------------------- #
    orderr = acme.new_order(csr_pem)
    log.info("Order created: %s", orderr.uri)

    challenges_to_answer = []

    # --- Provision TXT records ----------------------------------------- #
    for authzr in orderr.authorizations:
        identifier = authzr.body.identifier.value
        if authzr.body.status == messages.STATUS_VALID:
            log.info("Authorization already valid for %s, skipping", identifier)
            continue

        chosen = None
        for challb in authzr.body.challenges:
            if isinstance(challb.chall, acme_challenges.DNS01):
                chosen = challb
                break
        if chosen is None:
            raise SystemExit(f"No dns-01 challenge offered for {identifier}")

        response = chosen.chall.response(account_jwk)
        value = chosen.chall.validation(account_jwk)
        fqdn = chosen.chall.validation_domain_name(identifier)
        zone_override = resolve_zone_override(fqdn, cfg.zones)

        zone, name = dns_client.add_txt(
            fqdn, value, ttl=cfg.ttl, zone_override=zone_override)
        created_records.append(
            {"fqdn": fqdn, "value": value, "zone": zone, "name": name})
        challenges_to_answer.append((authzr, chosen, response))

    # --- Wait for propagation ------------------------------------------ #
    wait_for_propagation([(r["fqdn"], r["value"]) for r in created_records], cfg)

    # --- Tell the ACME server to validate ------------------------------ #
    for authzr, challb, response in challenges_to_answer:
        acme.answer_challenge(challb, response)
        log.info("Answered dns-01 challenge for %s",
                 authzr.body.identifier.value)

    # --- Finalize ------------------------------------------------------- #
    deadline = datetime.datetime.now() + datetime.timedelta(
        seconds=cfg.finalize_timeout)
    orderr = acme.poll_and_finalize(orderr, deadline)
    fullchain = orderr.fullchain_pem
    if isinstance(fullchain, bytes):
        fullchain = fullchain.decode()
    save_certificate(cfg.output_dir, fullchain, cert_key_pem)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acme_dnsexit.py",
        description="Obtain Let's Encrypt certificates with the DNS-01 "
                    "challenge via the DNSExit DNS API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--config", help="JSON configuration file")

    p.add_argument("--api-key", help="DNSExit API key (or env DNSEXIT_API_KEY)")
    p.add_argument("--email", help="ACME account contact e-mail (or env ACME_EMAIL)")
    p.add_argument("--domain", action="append", default=None,
                   help="Domain to include; repeat for SANs. Wildcards "
                        "(e.g. '*.example.com') are supported.")
    p.add_argument("--zone", help="DNSExit zone override for all domains")

    p.add_argument("--directory", help="ACME directory URL")
    staging = p.add_mutually_exclusive_group()
    staging.add_argument("--staging", action="store_true",
                         help="Use the Let's Encrypt staging environment")
    staging.add_argument("--production", action="store_true",
                         help="Use the Let's Encrypt production environment")

    p.add_argument("--output-dir", help="Where to write certificates and keys")
    p.add_argument("--account-key", help="ACME account private key path")
    p.add_argument("--cert-key", help="Certificate private key path")
    p.add_argument("--key-type", choices=["rsa", "ecdsa"],
                   help="Certificate key type")
    p.add_argument("--rsa-key-size", type=int, help="RSA key size in bits")
    p.add_argument("--elliptic-curve", choices=["secp256r1", "secp384r1", "secp521r1"],
                   help="ECDSA curve")

    p.add_argument("--ttl", type=int, help="TXT record TTL in minutes")
    p.add_argument("--propagation-timeout", type=int,
                   help="Seconds to wait for DNS propagation")
    p.add_argument("--propagation-interval", type=int,
                   help="Seconds between propagation checks")
    p.add_argument("--dns-resolvers", action="append",
                   help="Resolver IP (or DoH URL) to query; repeat or "
                        "comma-separate")
    p.add_argument("--doh", action="store_true", default=None,
                   help="Check propagation over DNS-over-HTTPS (uses the "
                        "default DoH endpoints unless --doh-url is given)")
    p.add_argument("--doh-url", action="append", default=None,
                   help="Custom DNS-over-HTTPS endpoint; repeat or "
                        "comma-separate (implies --doh)")
    p.add_argument("--skip-propagation-check", action="store_true", default=None,
                   help="Do not wait for TXT records to appear")
    p.add_argument("--finalize-timeout", type=int,
                   help="Seconds to wait for the CA to validate")
    p.add_argument("--no-cleanup", action="store_true", default=None,
                   help="Leave the TXT records in place")
    p.add_argument("--http-timeout", type=int,
                   help="DNSExit API HTTP timeout in seconds")

    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Only log warnings and errors")
    return p


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    if args.quiet:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args)

    # Allow comma separated values in a single --dns-resolvers/--doh-url.
    if args.dns_resolvers:
        flat = []
        for item in args.dns_resolvers:
            flat.extend(part for part in item.split(",") if part.strip())
        args.dns_resolvers = flat

    if args.doh_url:
        flat = []
        for item in args.doh_url:
            urls = [part.strip() for part in item.split(",") if part.strip()]
            flat.extend(urls)
        args.doh_url = flat

    cfg = build_config(args)
    validate_config(cfg)

    try:
        obtain_certificate(cfg)
    except DNSExitError as exc:
        log.error("DNSExit error: %s", exc)
        return 2
    except errors.Error as exc:
        log.error("ACME error: %s", exc)
        return 3
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
