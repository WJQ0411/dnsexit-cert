"""Minimal DNSExit DNS API client.

Only the small subset of the API needed for ACME DNS-01 validation is
implemented: adding and deleting TXT records.

API reference: https://dnsexit.com/dns/dns-api/

Notes
-----
* The API expects ``domain`` to be the *registered zone* (e.g. ``example.com``)
  and ``name`` to be the record name relative to that zone (e.g.
  ``_acme-challenge`` or ``_acme-challenge.www``).  Passing a fully qualified
  name in ``name`` is also tolerated by the server, but we normalise it.
* The JSON API has no "list zones" call, so the zone is discovered by trying
  the operation at each parent level of the record (same trick used by the
  acme.sh ``dns_dnsexit`` plugin).
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger("dnsexit")

API_URL = "https://api.dnsexit.com/dns/"

# Reply codes documented at https://dnsexit.com/dns/dns-api/#server-reply
CODE_OK = 0
CODE_EXECUTION_PROBLEM = 1


class DNSExitError(Exception):
    """Raised when the DNSExit API returns an error we cannot recover from."""


class DNSExitClient:
    """Thin client around the DNSExit JSON DNS API."""

    def __init__(self, api_key: str, timeout: int = 30,
                 api_url: str = API_URL):
        if not api_key:
            raise DNSExitError("DNSExit API key is missing")
        self.api_key = api_key.strip().strip('"')
        self.timeout = timeout
        self.api_url = api_url
        self._session = requests.Session()
        # Cache: fully-qualified record name -> (zone, relative_name)
        self._zone_cache: Dict[str, Tuple[str, str]] = {}

    # ------------------------------------------------------------------ #
    # Low level
    # ------------------------------------------------------------------ #
    def _post(self, payload: dict) -> dict:
        headers = {
            "apikey": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            resp = self._session.post(self.api_url, json=payload,
                                      headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise DNSExitError(f"HTTP request to DNSExit failed: {exc}") from exc

        if resp.status_code >= 400:
            raise DNSExitError(
                f"DNSExit API returned HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise DNSExitError(
                f"DNSExit API returned invalid JSON: {resp.text[:300]}") from exc
        return data

    @staticmethod
    def _message(data: dict) -> str:
        return str(data.get("message", data))

    # ------------------------------------------------------------------ #
    # Zone discovery
    # ------------------------------------------------------------------ #
    @staticmethod
    def _candidates(fqdn: str) -> List[Tuple[str, str]]:
        """Return ``(zone, name)`` pairs from longest to shortest suffix."""
        labels = fqdn.rstrip(".").split(".")
        out: List[Tuple[str, str]] = []
        for i in range(len(labels)):
            zone = ".".join(labels[i:])
            name = ".".join(labels[:i])
            out.append((zone, name))
        return out

    # ------------------------------------------------------------------ #
    # Public operations
    # ------------------------------------------------------------------ #
    def add_txt(self, fqdn: str, value: str, ttl: int = 1,
                zone_override: Optional[str] = None) -> Tuple[str, str]:
        """Create a TXT record for ``fqdn`` with ``value``.

        Returns the ``(zone, name)`` that the record was written under.

        ``overwrite`` is deliberately ``False`` so that several TXT values can
        coexist at the same name (needed for ``example.com`` together with
        ``*.example.com``, which both use ``_acme-challenge.example.com``).
        """
        fqdn = fqdn.rstrip(".")
        cached = self._zone_cache.get(fqdn)
        if cached is not None:
            candidates = [cached]
        elif zone_override:
            zone = zone_override.rstrip(".")
            if fqdn != zone and not fqdn.endswith("." + zone):
                raise DNSExitError(
                    f"zone override {zone!r} is not a suffix of {fqdn!r}")
            name = fqdn[: -len(zone) - 1] if fqdn != zone else ""
            candidates = [(zone, name)]
        else:
            candidates = self._candidates(fqdn)

        last: Optional[dict] = None
        problem: Optional[Tuple[str, str, dict]] = None
        for zone, name in candidates:
            payload = {
                "domain": zone,
                "add": {
                    "type": "TXT",
                    "name": name,
                    "content": value,
                    "ttl": ttl,
                    "overwrite": False,
                },
            }
            log.debug("DNSExit add TXT payload: %s", payload)
            data = self._post(payload)
            code = data.get("code")
            if code == CODE_OK:
                self._zone_cache[fqdn] = (zone, name)
                log.info("Added TXT %s = %s (zone=%s, name=%s)",
                         fqdn, value, zone, name or "@")
                return zone, name

            last = data
            if code == CODE_EXECUTION_PROBLEM and problem is None:
                # A recognised zone that still reported a problem, most likely
                # because this exact record already exists.
                problem = (zone, name, data)
            if zone_override or cached is not None:
                # We know the intended zone, so a failure is meaningful.
                break
            # Unknown zone: DNSExit reports any non-zero code (often 5).
            # Keep trying shorter suffixes until it is accepted as a zone.
            log.debug("DNSExit rejected zone %s for %s: %s (code=%s)",
                      zone, fqdn, self._message(data), code)

        # On a re-run the record may already exist, in which case adding it
        # again can return a non-zero code.  Do not fail hard: fall back to
        # the cached zone (if any) and let the propagation check be the judge.
        if cached is not None:
            zone, name = cached
            log.warning(
                "DNSExit reported a problem re-adding TXT %s (%s); continuing "
                "and relying on the propagation check",
                fqdn, self._message(last or {}))
            return zone, name

        if problem is not None:
            zone, name, data = problem
            self._zone_cache[fqdn] = (zone, name)
            log.warning(
                "DNSExit reported a problem adding TXT %s (%s); it may already "
                "exist. Continuing and relying on the propagation check",
                fqdn, self._message(data))
            return zone, name

        raise DNSExitError(
            f"Could not add TXT record {fqdn!r}: {self._message(last or {})}")

    def delete_txt(self, fqdn: str, value: str,
                   zone: Optional[str] = None) -> None:
        """Delete the TXT record ``fqdn`` with ``value``.

        Cleanup is best-effort: failures are logged but not raised.
        """
        fqdn = fqdn.rstrip(".")
        cached = self._zone_cache.get(fqdn)
        if cached is not None:
            candidates = [cached]
        elif zone:
            zone = zone.rstrip(".")
            name = fqdn[: -len(zone) - 1] if fqdn != zone else ""
            candidates = [(zone, name)]
        else:
            candidates = self._candidates(fqdn)

        last: Optional[dict] = None
        for z, name in candidates:
            payload = {
                "domain": z,
                "delete": {
                    "type": "TXT",
                    "name": name,
                    "content": value,
                },
            }
            log.debug("DNSExit delete TXT payload: %s", payload)
            try:
                data = self._post(payload)
            except DNSExitError as exc:
                last = {"message": str(exc)}
                continue
            if data.get("code") == CODE_OK:
                log.info("Removed TXT %s = %s (zone=%s, name=%s)",
                         fqdn, value, z, name or "@")
                self._zone_cache.pop(fqdn, None)
                return
            last = data
            # Wrong zone guess: try the next level.
            if zone is None and cached is None:
                continue
            break

        log.warning("Could not remove TXT %s = %s: %s",
                    fqdn, value, self._message(last or {}))

    def close(self) -> None:
        self._session.close()
