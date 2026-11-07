# Canonical command/batch envelope (Gate A LOW-1)

Status: SOURCE-ONLY / NOT A GRANT / NOT OWNER PRESENCE

Issue: infrastructure-tools #209. This is the missing concrete encoding named by the Gate A review of PR #214. It does not replace `commander/docs/SESSION_TRUST_CONTRACT.md`.

`canonical_command_batch.py` accepts one closed UTF-8 JSON document, version `ldw.commander.command-batch.v1`. The only privilege mode string it accepts is `SYNTHETIC_BATCH_IDENTITY_ONLY`. A matching document is not an Administrator or root authorization.

The canonical bytes are UTF-8 JSON with NFC strings, code-point-sorted object keys, array order preserved, and no insignificant whitespace. SHA-256 is computed over those exact bytes. `intent_text` is display wording. `payload_sha256` is the digest of the separate payload bytes and is not derived from the intent. This module does not launch the payload.

It refuses duplicate keys, invalid UTF-8, noncanonical whitespace, key order, or escapes, unsafe Unicode, path aliases, type mismatches, stale generation, wrong host or mode, nested shell or download argv, hash mismatch, and repeated command IDs inside one batch. It does not check a signature, store a key, consume a replay journal, or prove pre-spawn OS enforcement. Those remain unresolved Gate A gates.

No new dependency, listener, credential, or host task is added. Cost: $0.
