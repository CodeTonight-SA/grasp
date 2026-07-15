"""S3-compatible object-storage backend — standard library only.

No boto3: request signing is AWS Signature Version 4 implemented with
``hmac`` + ``hashlib`` + ``urllib`` (HMAC chaining over stdlib hashes —
not a hand-rolled cipher), preserving the package's load-bearing
standard-library-only invariant. Works against AWS S3 and S3-compatibles
(set the endpoint override for MinIO et al.).

Configuration (constructor args override environment):
  bucket   — ``GRASP_S3_BUCKET``
  region   — ``GRASP_S3_REGION`` (default ``us-east-1``)
  endpoint — ``GRASP_S3_ENDPOINT`` (default the AWS virtual-hosted URL)
  credentials — the standard AWS key-id / secret (+ optional session
  token) environment variables.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from grasp.storage import ProbeResult

_ALGORITHM = "AWS4-HMAC-SHA256"


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret: str, date: str, region: str, service: str = "s3") -> bytes:
    """SigV4 key derivation: AWS4+secret -> date -> region -> service -> aws4_request."""
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


class S3Adapter:
    name = "s3"

    def __init__(self, bucket: str | None = None, region: str | None = None,
                 endpoint: str | None = None) -> None:
        self._bucket = bucket or os.environ.get("GRASP_S3_BUCKET", "")
        self._region = region or os.environ.get("GRASP_S3_REGION", "us-east-1")
        host_default = f"{self._bucket}.s3.{self._region}.amazonaws.com" if self._bucket else ""
        self._endpoint = (endpoint or os.environ.get("GRASP_S3_ENDPOINT", "")
                          or (f"https://{host_default}" if host_default else ""))

    # -- credentials -------------------------------------------------------
    @staticmethod
    def _credentials() -> tuple[str, str, str]:
        return (os.environ.get("AWS_ACCESS_KEY_ID", ""),
                os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
                os.environ.get("AWS_SESSION_TOKEN", ""))

    def _configured(self) -> bool:
        key_id, secret, _ = self._credentials()
        return bool(self._bucket and self._endpoint and key_id and secret)

    # -- SigV4 request ------------------------------------------------------
    def _request(self, method: str, key: str, body: bytes = b"") -> bytes:
        key_id, secret, token = self._credentials()
        url = urllib.parse.urlparse(self._endpoint)
        host = url.netloc
        canonical_uri = urllib.parse.quote(f"{url.path.rstrip('/')}/{key}", safe="/-_.~")
        now = _dt.datetime.now(_dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()

        headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        if token:
            headers["x-amz-security-token"] = token
        signed_names = ";".join(sorted(headers))
        canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
        canonical_request = "\n".join(
            [method, canonical_uri, "", canonical_headers, signed_names, payload_hash])
        scope = f"{date}/{self._region}/s3/aws4_request"
        string_to_sign = "\n".join(
            [_ALGORITHM, amz_date, scope,
             hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
        signature = hmac.new(derive_signing_key(secret, date, self._region),
                             string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        request = urllib.request.Request(
            f"{self._endpoint.rstrip('/')}/{urllib.parse.quote(key, safe='/-_.~')}",
            data=body if method == "PUT" else None, method=method)
        for name, value in headers.items():
            if name != "host":  # urllib sets Host itself
                request.add_header(name, value)
        request.add_header(
            "Authorization",
            f"{_ALGORITHM} Credential={key_id}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}")
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read()

    # -- StorageAdapter ------------------------------------------------------
    def put(self, record_id: str, blob: bytes) -> str:
        key = f"records/{hashlib.sha256(record_id.encode()).hexdigest()[:24]}"
        self._request("PUT", key, blob)
        return f"{self._endpoint.rstrip('/')}/{key}"

    def get(self, record_id: str) -> bytes | None:
        key = f"records/{hashlib.sha256(record_id.encode()).hexdigest()[:24]}"
        try:
            return self._request("GET", key)
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            raise

    def anchor(self, merkle_root: str) -> str | None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        key = f"anchors/{merkle_root[:16]}-{stamp}.json"
        body = json.dumps({"root": merkle_root, "ts": stamp}, sort_keys=True).encode()
        self._request("PUT", key, body)
        return f"{self._endpoint.rstrip('/')}/{key}"

    def probe(self) -> ProbeResult:
        if not self._configured():
            return ProbeResult(
                name=self.name,
                ready=False,
                detail="bucket or credentials not configured",
                remedy="set the GRASP S3 bucket/region env vars and standard AWS credentials",
            )
        try:
            self._request("GET", "")  # bucket-root reachability round-trip
        except urllib.error.HTTPError:
            pass  # any HTTP status proves the signed round-trip reached S3
        except (urllib.error.URLError, OSError) as exc:
            return ProbeResult(
                name=self.name, ready=False,
                detail=f"endpoint unreachable: {exc}",
                remedy="check the endpoint/region and network access",
            )
        return ProbeResult(name=self.name, ready=True,
                           detail=f"objects persist to {self._endpoint}")
