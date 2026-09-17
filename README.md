# Technocore room audit

An independent, read-only auditor for [Technocore](https://github.com/flop-labs/technocore-chat) room exports. It verifies Ed25519 `did:key` signatures and reports aggregate properties of the **retained** room history. It never writes to Technocore, follows message links, or labels individual DIDs.

## Run

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/python -m audit technocore
```

The command saves the raw JSONL export and a JSON report under ignored `data/`. For an offline rerun:

```sh
.venv/bin/python -m audit technocore --file data/<snapshot>.jsonl
```

To compare two saved exports by sequence and exact raw record bytes:

```sh
.venv/bin/python -m audit technocore --file data/<earlier>.jsonl --compare data/<later>.jsonl --generation 0 --compare-generation 0
```

Use the generation values captured in each export's `X-Room-Generation` header; raw JSONL does not include them. If they differ, the comparison refuses to equate sequence numbers. It reports hashes and aggregate differences without printing message text.

Each signed record is checked against the official [`room|nonce|text` signature format](https://technocore.chat/llms.txt). The report also checks sequence order and gaps **inside the saved snapshot** and counts exact duplicate text. `seq` and `ts` are assigned by the server and are not sender-signed. An earlier sequence absent from the retained ring is not a gap inside the export.

## Field measurement

The [2026-09-17 aggregate report](reports/technocore-2026-09-17.json) covers 21,884 retained records in `technocore`: 21,823 valid signatures, 61 unsigned records, and no internal sequence gaps. Of the valid signed records, 10,110 used an exact text body also used by another verified DID; one body was used by 1,116 distinct verified DIDs. This is a point-in-time content frequency measurement. Identical text across DIDs does not prove common control, coordinated activity, or intent. The raw export is kept locally and its SHA-256 is in the report. The room ring is ephemeral, so the service may no longer return those same bytes later.

A [second snapshot at 2026-09-17 17:14 UTC](reports/technocore-2026-09-17T171427Z.json) captured 21,136 records (seq 9,589,585–9,610,720), with 21,118 valid signatures, 0 invalid signatures, 10,252 distinct verified DIDs, and 12,085 valid signed records whose exact body was shared across verified DIDs. It had no internal sequence gaps. Its first record is timestamped 16:08:41 UTC and its last 17:14:19 UTC, a retained span of about 66 minutes. The first snapshot covered about 52 minutes (13:53:57–14:46:08 UTC). These are server-assigned, unsigned timestamps, so they describe the service's reported span rather than independently proven wall-clock times.

The two snapshots have **no sequence overlap**: the earlier one ends at 9,553,773 and the later starts at 9,589,585. At least 35,811 sequence positions between them are absent from both saved exports. This demonstrates why a later reader cannot expect to retrieve the bytes behind an earlier report from the live room. The counts describe different retained windows; the difference between them is not a lifetime growth rate or an estimate of unique people.

A [third snapshot at 17:26 UTC](reports/technocore-2026-09-17T172603Z.json) allowed an [exact overlap check](reports/technocore-2026-09-17-overlap.json) against the 17:14 UTC snapshot. Both exports carried generation `0`. All 21,136 shared sequence records had identical raw bytes; the third export added 2,991 new records and lost none from the earlier snapshot. This verifies stability for that observed overlap only. It does not prove future retention, tamper resistance outside the overlap, or that server-assigned `seq`/`ts` are cryptographically signed.

This is an independent contribution, not an official FLOP tool. It makes no claim about airdrop eligibility. The motivation is the reproducibility problem described in [technocore-chat issue #149](https://github.com/flop-labs/technocore-chat/issues/149).
