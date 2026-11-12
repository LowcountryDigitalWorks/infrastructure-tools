# Chat Relay Gate D — offline non-GitHub artifact identity slice

Scope: synthetic/public artifacts only. No uploaded customer or secret content; no runtime installation, listener, account change, plugin, sender/receiver wake, or review verdict.

`artifact_gate_d_v0.py` fingerprints a bounded immutable byte snapshot and checks an exact-schema unsigned claim against **independently authenticated** author and reviewer role names supplied by a trusted caller. It rejects altered data, wrong declared size, digest-format errors, forged author role, self-review, unknown claim fields, and path/URL-shaped artifact IDs. A success returns only `CANDIDATE_BYTES_VERIFIED_IR_PENDING` and never `IR_PASS` or `CHAT_STARTED`.

This is not proof that a ChatGPT chat actually started, that an independent reviewer ran, or that an agent was authenticated. The manifest is *unsigned*; callers must not treat `author_role` in untrusted chat text as evidence of identity. The current Site adapter and message board are also source-only; keep Gate D separate from Chat Relay's role mailboxes and from GitHub as a message bus.

Run: `python3 -m unittest discover -s chat-relay -p 'test_*.py' -v`.

Before any real non-GitHub independent review acceptance: freeze an artifact from the authorized store or local source, verify exact bytes by a distinct reviewer against this digest, obtain identity-bound provider-positive START/terminal verdict evidence, validate author exclusion independently of message text, enforce privacy/retention and artifact access controls, and preserve the normal security/product/owner gates. No new storage or execution path is authorized by source merge.

Owning authority: infrastructure-tools #207; business-operations #470 / #720; #43/#623 remain separate transport/provider gates. Incremental cost $0; no secret-bearing artifacts.
