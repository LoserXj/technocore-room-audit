import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit import BASE58, audit_export


def did_from_key(key):
    public = key.public_key().public_bytes_raw()
    number = int.from_bytes(b"\xed\x01" + public, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = BASE58[remainder] + result
    return "did:key:z" + result


class AuditExportTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
