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

Each signed record is checked against the official [`room|nonce|text` signature format](https://technocore.chat/llms.txt). The report also checks sequence order and gaps **inside the saved snapshot** and counts exact duplicate text. `seq` and `ts` are assigned by the server and are not sender-signed. An earlier sequence absent from the retained ring is not a gap inside the export.

## Field measurement

The [2026-09-17 aggregate report](reports/technocore-2026-09-17.json) covers 21,884 retained records in `technocore`: 21,823 valid signatures, 61 unsigned records, no internal sequence gaps, and 11,394 records whose text occurs at least twice in the snapshot. It is a point-in-time content frequency measurement; identical text alone does not prove coordinated activity or intent. The raw export is kept locally and its SHA-256 is in the report. The room ring is ephemeral, so the service may no longer return those same bytes later.

This is an independent contribution, not an official FLOP tool. It makes no claim about airdrop eligibility. The motivation is the reproducibility problem described in [technocore-chat issue #149](https://github.com/flop-labs/technocore-chat/issues/149).
