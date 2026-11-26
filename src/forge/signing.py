"""Cryptographic artifact provenance signing and verification using Ed25519."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from forge.models import AttestationRecord, utc_now_iso
from forge.sbom import sha256_file
from forge.storage import ForgeStore


def generate_keypair(private_key_path: Path, public_key_path: Path) -> str:
    """Generate a local Ed25519 signing keypair with strict 0600 permissions on private key."""
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_path.write_bytes(priv_pem)
    os.chmod(private_key_path, 0o600)
    public_key_path.write_bytes(pub_pem)
    return hashlib.sha256(pub_pem).hexdigest()[:16]


def _canonical_statement(artifact_name: str, artifact_sha256: str, git_commit: str, signed_at: str) -> bytes:
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://forge.local/provenance/v1",
        "subject": [{"name": artifact_name, "digest": {"sha256": artifact_sha256}}],
        "predicate": {"git_commit": git_commit, "signed_at": signed_at},
    }
    return json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_artifact(
    artifact_path: str | Path,
    private_key_path: str | Path,
    git_commit: str,
    envelope_out_path: str | Path,
    store: ForgeStore | None = None,
) -> tuple[AttestationRecord, dict[str, Any]]:
    """Sign an artifact's SHA-256 digest and source commit into a DSSE-style JSON envelope."""
    apath = Path(artifact_path).resolve()
    priv_pem = Path(private_key_path).read_bytes()
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key.")

    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_fp = hashlib.sha256(pub_pem).hexdigest()[:16]
    digest = sha256_file(apath)
    signed_at = utc_now_iso()
    payload_bytes = _canonical_statement(apath.name, digest, git_commit, signed_at)
    sig = priv.sign(payload_bytes)
    sig_b64 = base64.b64encode(sig).decode("ascii")

    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": pub_fp, "alg": "Ed25519", "sig": sig_b64}],
    }
    out_path = Path(envelope_out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    rec = AttestationRecord(
        attestation_id=f"ATT-{uuid.uuid4().hex[:10].upper()}",
        artifact_path=str(apath),
        artifact_sha256=digest,
        git_commit=git_commit,
        public_key_fingerprint=pub_fp,
        signature_b64=sig_b64,
        signed_at=signed_at,
        verified=True,
        verification_detail="Signed with local Ed25519 key; run verify_artifact() to validate.",
    )
    if store:
        store.save_attestation(rec)
    return rec, envelope


def verify_artifact(
    artifact_path: str | Path,
    envelope_path: str | Path,
    public_key_path: str | Path,
) -> tuple[bool, str]:
    """Verify Ed25519 signature AND match current artifact SHA-256 digest against signed statement."""
    apath = Path(artifact_path).resolve()
    if not apath.exists():
        return False, f"Artifact missing: {apath}"
    epath = Path(envelope_path)
    if not epath.exists():
        return False, f"Attestation envelope missing: {epath}"

    pub_pem = Path(public_key_path).read_bytes()
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, Ed25519PublicKey):
        return False, "Invalid public key type; Ed25519 required."

    try:
        envelope = json.loads(epath.read_text(encoding="utf-8"))
        payload_bytes = base64.b64decode(envelope["payload"])
        sig_entry = envelope["signatures"][0]
        sig_bytes = base64.b64decode(sig_entry["sig"])
    except (KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
        return False, f"Malformed attestation envelope: {exc}"

    try:
        pub.verify(sig_bytes, payload_bytes)
    except InvalidSignature:
        return False, "SIGNATURE_INVALID: Ed25519 cryptographic signature verification failed."

    stmt = json.loads(payload_bytes.decode("utf-8"))
    expected_digest = stmt["subject"][0]["digest"]["sha256"]
    actual_digest = sha256_file(apath)
    if actual_digest != expected_digest:
        return False, f"DIGEST_MISMATCH: Artifact modified after signing (expected {expected_digest[:12]}, got {actual_digest[:12]})."

    return True, f"VERIFIED: Ed25519 signature and SHA-256 digest ({actual_digest[:12]}) match commit {stmt['predicate']['git_commit']}."
