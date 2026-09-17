import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit import BASE58, audit_export, compare_exports


def did_from_key(key):
    public = key.public_key().public_bytes_raw()
    number = int.from_bytes(b"\xed\x01" + public, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = BASE58[remainder] + result
    return "did:key:z" + result


class AuditExportTests(unittest.TestCase):
    def test_compare_exports_detects_changed_raw_record_and_new_tail(self):
        old = b'{"seq":1,"text":"a"}\n{"seq":2,"text":"b"}\n'
        new = b'{"seq":1,"text":"a"}\n{"seq":2,"text":"changed"}\n{"seq":3,"text":"c"}\n'
        report = compare_exports(old, new, old_generation="0", new_generation="0")
        self.assertEqual(report["shared_seq_count"], 2)
        self.assertEqual(report["identical_raw_records_on_shared_seqs"], 1)
        self.assertEqual(report["changed_raw_records_on_shared_seqs"], 1)
        self.assertEqual(report["first_changed_seq"], 2)
        self.assertEqual(report["new_only_seq_count"], 1)
        with self.assertRaisesRegex(ValueError, "generations differ"):
            compare_exports(old, new, old_generation="0", new_generation="1")

    def test_verifies_signatures_and_reports_gaps_without_exposing_text(self):
        key = Ed25519PrivateKey.generate()
        did = did_from_key(key)

        def signed(seq, nonce, text, *, tamper=False):
            sig = base64.urlsafe_b64encode(
                key.sign(f"lobby|{nonce}|{text}".encode())
            ).rstrip(b"=").decode()
            return {
                "seq": seq, "from": did, "nonce": nonce, "sig": sig,
                "text": text + "!" if tamper else text,
            }

        records = [
            signed(10, 1, "same message"),
            signed(11, 2, "same message"),
            signed(13, 3, "tampered", tamper=True),
            {"seq": 14, "from": "~nick", "text": "unsigned"},
        ]
        raw = b"".join((json.dumps(r) + "\n").encode() for r in records)
        report = audit_export("lobby", raw, generation="2")
        self.assertEqual(report["records"], 4)
        self.assertEqual(report["valid_signatures"], 2)
        self.assertEqual(report["invalid_signatures"], 1)
        self.assertEqual(report["unsigned_records"], 1)
        self.assertEqual(report["missing_seq_within_snapshot"], 1)
        self.assertEqual(report["records_with_repeated_body"], 2)
        self.assertEqual(report["distinct_verified_dids"], 1)
        self.assertEqual(report["dids_with_one_record_in_snapshot"], 0)
        self.assertNotIn("same message", json.dumps(report))

    def test_shared_text_distinguishes_distinct_verified_dids(self):
        keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        records = []
        for seq, key in enumerate((keys[0], keys[0], keys[1]), 1):
            did = did_from_key(key)
            sig = base64.urlsafe_b64encode(
                key.sign(f"lobby|{seq}|shared text".encode())
            ).rstrip(b"=").decode()
            records.append({"seq": seq, "from": did, "nonce": seq, "sig": sig, "text": "shared text"})
        raw = b"".join((json.dumps(r) + "\n").encode() for r in records)
        report = audit_export("lobby", raw)
        self.assertEqual(report["body_variants_shared_by_multiple_verified_dids"], 1)
        self.assertEqual(report["valid_signed_records_on_cross_did_bodies"], 3)
        self.assertEqual(report["max_verified_dids_on_one_body"], 2)


if __name__ == "__main__":
    unittest.main()
