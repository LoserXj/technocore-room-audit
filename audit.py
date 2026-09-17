"""Read-only audit of a Technocore room export.

This reports protocol facts and aggregate counts. It makes no claim about airdrop
eligibility, message quality, or who controls a DID.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BASE_URL = "https://technocore.chat"
ROOM_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DATA_DIR = Path(__file__).resolve().parent / "data"


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("Not a did:key:z identifier")
    number = 0
    for char in did[len("did:key:z"):]:
        number = number * 58 + BASE58.index(char)
    raw = number.to_bytes(34, "big")
    if not raw.startswith(b"\xed\x01"):
        raise ValueError("Not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def verify_receipt(receipt: dict) -> None:
    signature = base64.urlsafe_b64decode(receipt["sig"] + "==")
    challenge = f"{receipt['room']}|{receipt['nonce']}|{receipt['text']}".encode()
    public_key_from_did(receipt["did"]).verify(signature, challenge)


def audit_export(room: str, raw: bytes, *, generation: str = "unknown") -> dict:
    if not ROOM_PATTERN.fullmatch(room):
        raise ValueError("Invalid room name")
    counts = Counter()
    bodies = Counter()
    signer_counts = Counter()
    signers = set()
    previous_seq = None
    first_seq = None
    last_seq = None

    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line:
            continue
        counts["records"] += 1
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record is not a JSON object")
        except (ValueError, UnicodeDecodeError):
            counts["malformed_records"] += 1
            continue

        seq = record.get("seq")
        if type(seq) is int and seq >= 0:
            first_seq = seq if first_seq is None else first_seq
            if previous_seq is not None:
                if seq > previous_seq + 1:
                    counts["missing_seq_within_snapshot"] += seq - previous_seq - 1
                elif seq <= previous_seq:
                    counts["out_of_order_seq"] += 1
            previous_seq = seq
            last_seq = seq
        else:
            counts["invalid_seq"] += 1

        body = record.get("text")
        if isinstance(body, str):
            bodies[body] += 1
        else:
            counts["invalid_text"] += 1

        did = record.get("from")
        if isinstance(did, str) and did.startswith("did:key:"):
            if "sig" not in record or "nonce" not in record:
                counts["signed_identity_missing_proof"] += 1
                continue
            try:
                verify_receipt({
                    "room": room, "did": did, "sig": record["sig"],
                    "nonce": record["nonce"], "text": body,
                })
            except Exception:
                counts["invalid_signatures"] += 1
            else:
                counts["valid_signatures"] += 1
                signers.add(did)
                signer_counts[did] += 1
        else:
            counts["unsigned_records"] += 1

    repeated = [count for count in bodies.values() if count > 1]
    return {
        "room": room,
        "generation": generation,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "records": counts["records"],
        "first_seq": first_seq,
        "last_seq": last_seq,
        "missing_seq_within_snapshot": counts["missing_seq_within_snapshot"],
        "out_of_order_seq": counts["out_of_order_seq"],
        "malformed_records": counts["malformed_records"],
        "invalid_seq": counts["invalid_seq"],
        "invalid_text": counts["invalid_text"],
        "valid_signatures": counts["valid_signatures"],
        "invalid_signatures": counts["invalid_signatures"],
        "signed_identity_missing_proof": counts["signed_identity_missing_proof"],
        "unsigned_records": counts["unsigned_records"],
        "distinct_verified_dids": len(signers),
        "dids_with_one_record_in_snapshot": sum(1 for count in signer_counts.values() if count == 1),
        "distinct_message_bodies": len(bodies),
        "repeated_body_variants": len(repeated),
        "records_with_repeated_body": sum(repeated),
        "max_identical_body_count": max(bodies.values(), default=0),
    }


def save_private(path: Path, contents: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(contents)


def capture(room: str) -> tuple:
    if not ROOM_PATTERN.fullmatch(room):
        raise ValueError("Invalid room name")
    request = urllib.request.Request(
        f"{BASE_URL}/r/{room}/export", headers={"User-Agent": "technocore-room-audit/0.1"}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        raw = response.read()
        generation = response.headers.get("X-Room-Generation", "unknown")
    report = audit_export(room, raw, generation=generation)
    report["captured_at"] = datetime.now(timezone.utc).isoformat()
    report["source_url"] = f"{BASE_URL}/r/{room}/export"
    DATA_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{room}-{stamp}-{secrets.token_hex(3)}"
    snapshot_path = DATA_DIR / f"{stem}.jsonl"
    report_path = DATA_DIR / f"{stem}.report.json"
    save_private(snapshot_path, raw)
    report["snapshot_file"] = snapshot_path.name
    save_private(report_path, (json.dumps(report, indent=2) + "\n").encode())
    return snapshot_path, report_path, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("room", help="Existing Technocore room to audit")
    parser.add_argument("--file", type=Path, help="Analyze a saved JSONL export instead of fetching")
    args = parser.parse_args()
    try:
        if args.file:
            report = audit_export(args.room, args.file.read_bytes())
        else:
            _, _, report = capture(args.room)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
