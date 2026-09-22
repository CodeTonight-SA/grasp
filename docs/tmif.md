# GRASP as a TMIF reference Claimant

[TMIF](https://datatracker.ietf.org/doc/draft-laurie-tmif/) —
*A Standard for Claiming Transparency and Falsifiability*
(`draft-laurie-tmif-02`, Laurie et al., IETF Informational Internet-Draft,
September 2026, expires 20 March 2027) — is a JSON interchange format in
which a system declares, per threat, a mitigation and a transparency level
(1 = binary available … 5 = formal proof), signs the declaration, and points
evaluators at artifacts they can verify. TMIF produces no provenance records
itself; it is a **declaration layer**.

## Engine, not format

GRASP is **not** an implementation of TMIF. GRASP is the
falsifiable-by-construction engine — signed decision records, Merkle
commitment, deterministic replay, receipt-bound citations. TMIF is a
format for *declaring* what an engine mitigates. The two compose: this
directory publishes GRASP's claims **as** a TMIF Claimant document, so a
TMIF Evaluator can consume them without reading our docs.

One divergence, stated openly: TMIF Claimants **self-assert** a
transparency level. Under GRASP's exogenous-anchor rule a level is only
worth what a third party can re-derive — the record survives independent
refutation or it does not. GRASP therefore **under-claims by policy**:
`transparency_level_lower_bound: 3` (source available, weakest-link
honest), rising to level 4 only where the verification is a deterministic
re-derivation any party can reproduce offline from published inputs — the
replay leg, and the Bitcoin-anchored production chain whose replay bundle
is in [`tmif/anchor/`](tmif/anchor/README.md).

## Files

| File | What it is |
|---|---|
| [`tmif/grasp-tmif-claimant.json`](tmif/grasp-tmif-claimant.json) | The TMIF document (schema per `draft-laurie-tmif-02` §4.1; carries `issued_at` and `valid_until`) |
| [`tmif/grasp-tmif-claimant.jws`](tmif/grasp-tmif-claimant.jws) | The same bytes, signed — RFC 7515 compact JWS, alg `EdDSA` (Ed25519, RFC 8037), the form `draft-laurie-tmif-02` §5.1.1 requires |
| [`tmif/claimant-public-key.jwk.json`](tmif/claimant-public-key.jwk.json) | The verifying key (JWK), `kid: grasp-tmif-claimant-2026` |
| [`tmif/anchor/`](tmif/anchor/README.md) | The replay bundle behind the level-4 anchor claim: manifest, upgraded OpenTimestamps proof (Bitcoin blocks 956991 and 956992), the 501 leaf hashes, and a standard-library `verify.py` |

The document was re-issued on 2026-09-22 against `draft-laurie-tmif-02`. It
supersedes the July 2026 issue; that earlier `.jws` still verifies against its
own payload, so treat any copy of it as superseded, not as forged.

## Verify the signature and the payload (no trust in us needed for that step)

Requires only Python and the `cryptography` package
(`pip install cryptography`). Run from the repo root:

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pad = lambda s: s + "=" * (-len(s) % 4)
jws = open("docs/tmif/grasp-tmif-claimant.jws").read().strip()
jwk = json.load(open("docs/tmif/claimant-public-key.jwk.json"))
h, p, s = jws.split(".")

Ed25519PublicKey.from_public_bytes(
    base64.urlsafe_b64decode(pad(jwk["x"]))
).verify(base64.urlsafe_b64decode(pad(s)), f"{h}.{p}".encode())

payload = json.loads(base64.urlsafe_b64decode(pad(p)))
assert payload == json.load(open("docs/tmif/grasp-tmif-claimant.json"))
print("signature OK:", payload["system_identifier"])
```

A forged or altered document fails the `verify` call; a `.jws` whose
payload drifts from the published `.json` fails the assert. What this step
does **not** establish is whose key that is: the JWK is published beside the
JWS in this repository, and nothing outside the repository binds it to
CodeTonight yet. An Evaluator who needs the key's identity, not just its
consistency, should treat this repository as the (only) root of trust for
`kid: grasp-tmif-claimant-2026` until an out-of-band binding is published.

The claims inside point at artifacts you can check the same way — the public
verifier at [grasp-web-chi.vercel.app/try](https://grasp-web-chi.vercel.app/try),
this source tree, and the production decision chain whose Merkle root is
attested in Bitcoin blocks 956991 and 956992: [`tmif/anchor/`](tmif/anchor/README.md)
holds the manifest, the OpenTimestamps proof and the 501 leaf hashes, and
`python3 docs/tmif/anchor/verify.py` re-derives the root and prints the block
merkle roots to compare on any explorer (verify the proof with the upstream
OpenTimestamps client, not our code).

## Falsifier

This positioning is wrong — and this document gets re-examined — if TMIF
(or a successor) begins producing tamper-evident agent-runtime records
itself: that would make it a competing engine, not a declaration format.
The claimant document expires `2026-12-31`; the underlying draft expires
20 March 2027. Stale declarations are worse than none — if you are
reading this after expiry and no refreshed `.jws` exists, treat the
declaration (not the engine) as lapsed.
