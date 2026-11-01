# Sentinel offline verifier

This directory checks an exported receipt and an evidence manifest.
It does not include the execution engine, database adapters, or network clients.

The license is Apache-2.0. See `LICENSE`.

## Install

From this directory:

```bash
python -m pip install -e .
```

## Check the example packages

Each package embeds its public keys in the `keys` array. Pass that same file to `--trust-store` and to `--bundle`.

Intact package. The process exit code is 0 and the JSON status is `VERIFIED`.

```bash
python -m sentinel_verify.cli --trust-store examples/bundle_valid.json --bundle examples/bundle_valid.json
```

Package with one flipped bit in the receipt signature. The process exit code is 1 and the JSON status is `FAILED`.

```bash
python -m sentinel_verify.cli --trust-store examples/bundle_corrupted.json --bundle examples/bundle_corrupted.json
```

## Tests

```bash
python -m pytest
```

`docs/threat_model.md` states what these checks cover and what they leave out.
