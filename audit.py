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
    signed_bodies = Counter()
    body_signers = {}
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
                signed_bodies[body] += 1
                body_signers.setdefault(body, set()).add(did)
        else:
            counts["unsigned_records"] += 1

    repeated = [count for count in bodies.values() if count > 1]
    cross_did_bodies = {body for body, dids in body_signers.items() if len(dids) > 1}
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
        "body_variants_shared_by_multiple_verified_dids": len(cross_did_bodies),
        "valid_signed_records_on_cross_did_bodies": sum(signed_bodies[body] for body in cross_did_bodies),
        "max_verified_dids_on_one_body": max((len(dids) for dids in body_signers.values()), default=0),
    }


def compare_exports(old: bytes, new: bytes, *, old_generation: str, new_generation: str) -> dict:
    """Compare the exact stored bytes of records retained in both exports."""
    if not old_generation or not new_generation or "unknown" in (old_generation, new_generation):
        raise ValueError("Both export generations are required to compare sequence numbers")
    if old_generation != new_generation:
        raise ValueError("Room generations differ; sequence overlap cannot be compared")

    def index(raw: bytes) -> dict:
        records = {}
        for line in raw.splitlines():
            if not line:
                continue
            record = json.loads(line)
            if not isinstance(record, dict) or "seq" not in record:
                raise ValueError("Export has a record without a sequence number")
            seq = record["seq"]
            if type(seq) is not int or seq < 0 or seq in records:
                raise ValueError("Export has an invalid or duplicate sequence number")
            records[seq] = line
        return records

    earlier, later = index(old), index(new)
    shared = earlier.keys() & later.keys()
    changed = [seq for seq in shared if earlier[seq] != later[seq]]
    return {
        "old_sha256": hashlib.sha256(old).hexdigest(),
        "new_sha256": hashlib.sha256(new).hexdigest(),
        "old_generation": old_generation,
        "new_generation": new_generation,
        "old_records": len(earlier),
        "new_records": len(later),
        "shared_seq_count": len(shared),
        "identical_raw_records_on_shared_seqs": len(shared) - len(changed),
        "changed_raw_records_on_shared_seqs": len(changed),
        "first_changed_seq": min(changed, default=None),
        "old_only_seq_count": len(earlier.keys() - later.keys()),
        "new_only_seq_count": len(later.keys() - earlier.keys()),
        "first_shared_seq": min(shared, default=None),
        "last_shared_seq": max(shared, default=None),
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
    parser.add_argument("--compare", type=Path, help="Compare this saved export to --file by exact record bytes")
    parser.add_argument("--generation", help="Generation of --file from its export header")
    parser.add_argument("--compare-generation", help="Generation of --compare from its export header")
    args = parser.parse_args()
    try:
        if args.compare:
            if not args.file:
                parser.error("--compare requires --file")
            if not args.generation or not args.compare_generation:
                parser.error("--compare requires --generation and --compare-generation from the export headers")
            report = compare_exports(args.file.read_bytes(), args.compare.read_bytes(),
                                     old_generation=args.generation, new_generation=args.compare_generation)
        elif args.file:
            report = audit_export(args.room, args.file.read_bytes())
        else:
            _, _, report = capture(args.room)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
