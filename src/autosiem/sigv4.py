"""AWS Signature Version 4 request signing, stdlib only.

``boto3`` is barred from the core (see CONTRIBUTING and the zero-dependency
rule), so CloudTrail's connector has to sign its own requests. This module is
deliberately separate from ``connectors.py``: signing is cryptographic, it is
the one place a silent mistake produces a 403 rather than wrong data, and it is
the only part of a connector that can be checked against vectors published by
the vendor instead of fixtures we invented.

Scope: header-based (not presigned) signing of a single request, which is all
the CloudTrail-over-S3 connector needs. No chunked payloads, no STS session
negotiation - a session token is carried if the caller already has one.

Reference: "Signature Version 4 signing process" in the AWS General Reference.
The four steps below are named after the ones in that document so they can be
compared side by side.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Iterable, Mapping
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"
TERMINATOR = "aws4_request"

#: Hash of the empty string, the payload hash for every GET this module signs.
EMPTY_PAYLOAD_SHA256 = hashlib.sha256(b"").hexdigest()

#: RFC 3986 unreserved characters. Everything else is percent-encoded with
#: UPPERCASE hex digits, which the canonical request requires.
_UNRESERVED = "-_.~"


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def uri_encode(value: str, *, is_path: bool) -> str:
    """Percent-encode per the canonical-request rules.

    ``is_path`` keeps ``/`` literal, which is what S3 expects; a query string
    component encodes it. AWS requires uppercase hex, which ``quote`` produces.
    """
    safe = _UNRESERVED + ("/" if is_path else "")
    return quote(value, safe=safe)


def canonical_query_string(query: Mapping[str, str] | Iterable[tuple[str, str]]) -> str:
    """Sorted, encoded ``k=v`` pairs joined by ``&``.

    Sorting is by encoded key then encoded value, because the signature is over
    the encoded form and a pre-encoding sort can order them differently.
    """
    pairs = list(query.items()) if isinstance(query, Mapping) else list(query)
    encoded = sorted(
        (uri_encode(str(key), is_path=False), uri_encode(str(value), is_path=False))
        for key, value in pairs
    )
    return "&".join(f"{key}={value}" for key, value in encoded)


def canonical_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    """Return ``(canonical_headers_block, signed_headers_list)``.

    Names lowercase and sorted; values stripped. Sequential inner spaces should
    also collapse, but no header this module sends carries them, so that is
    deliberately not implemented rather than implemented untested.
    """
    lowered = sorted((name.lower().strip(), str(value).strip()) for name, value in headers.items())
    block = "".join(f"{name}:{value}\n" for name, value in lowered)
    signed = ";".join(name for name, _ in lowered)
    return block, signed


def canonical_request(method: str, path: str, query: Mapping[str, str],
                      headers: Mapping[str, str], payload_hash: str) -> tuple[str, str]:
    """Step 1. Returns ``(canonical_request, signed_headers)``."""
    header_block, signed = canonical_headers(headers)
    return "\n".join([
        method.upper(),
        uri_encode(path or "/", is_path=True),
        canonical_query_string(query),
        header_block,
        signed,
        payload_hash,
    ]), signed


def credential_scope(date_stamp: str, region: str, service: str) -> str:
    return f"{date_stamp}/{region}/{service}/{TERMINATOR}"


def string_to_sign(amz_date: str, scope: str, request: str) -> str:
    """Step 2."""
    return "\n".join([ALGORITHM, amz_date, scope, _sha256_hex(request.encode("utf-8"))])


def signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """Step 3. The date-scoped key chain, so a leaked key is bounded in time."""
    key = _hmac(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    key = _hmac(key, region)
    key = _hmac(key, service)
    return _hmac(key, TERMINATOR)


def sign(secret_key: str, date_stamp: str, region: str, service: str, to_sign: str) -> str:
    """Step 4. Hex signature over the string to sign."""
    return hmac.new(
        signing_key(secret_key, date_stamp, region, service),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign_request(*, method: str, host: str, path: str, query: Mapping[str, str],
                 region: str, service: str, access_key: str, secret_key: str,
                 session_token: str = "", payload: bytes = b"",
                 headers: Mapping[str, str] | None = None,
                 now: datetime | None = None) -> dict[str, str]:
    """Return the headers a signed request needs, Authorization included.

    The caller sends exactly these headers. Adding or dropping one afterwards
    invalidates the signature, because the set is named in ``SignedHeaders``.
    """
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = moment.strftime("%Y%m%d")
    payload_hash = _sha256_hex(payload)

    signed_headers: dict[str, str] = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if session_token:
        # Part of the signature: a token swapped after signing is rejected.
        signed_headers["x-amz-security-token"] = session_token
    signed_headers.update({k.lower(): v for k, v in (headers or {}).items()})

    request, signed_list = canonical_request(method, path, query, signed_headers, payload_hash)
    scope = credential_scope(date_stamp, region, service)
    signature = sign(secret_key, date_stamp, region, service,
                     string_to_sign(amz_date, scope, request))
    signed_headers["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_list}, Signature={signature}"
    )
    return signed_headers
