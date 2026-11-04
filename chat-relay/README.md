# LDW Chat Relay — standalone local transport proof

Status: SOURCE-ONLY / SYNTHETIC PROOF. Not deployed, not connected to ChatGPT.

This delivers a bidirectional, role-authenticated, owner-controlled local message transport without ChatGPT Work, GitHub runtime, an OpenAI API key, or Desktop Commander. It does not claim a native API for posting directly into an existing ChatGPT chat.

## V0 contract

- Python 3.11+ standard library only; loopback-only listener.
- Authenticated named roles, per-role HMAC tokens derived from protected 32+ byte master secret.
- POST /v1/send: exact message_id UUID, sender, recipient, body, optional reply_to UUID. Status IN_MAILBOX means transport acceptance only.
- GET /v1/receive?limit=20: only the authenticated recipient's unacknowledged messages.
- POST /v1/ack: only the authenticated recipient can acknowledge its message.
- GET /health: non-sensitive local status.
- 15-minute TTL, max 128 retained messages, max 8 KiB body.
- UUID replay is idempotent even after acknowledgement until expiry; changed content with the same UUID fails 409.
- In-memory only: no disk queues, external traffic, bearer/body logging, general shell, credentials or customer data.
- Only synthetic/public non-sensitive messages are within this proof scope.

## Run the synthetic tests

From the repository root:

    python3 -m unittest discover -s chat-relay -p test_relay.py -v

The test suite covers two-role delivery and reply, role spoofing refusal, changed-UUID conflict, retry after acknowledgement, expiry, size and schema rejection, mailbox capacity, loopback-only binding, invalid bearer, and non-sensitive health.

## Run the local proof service

Provision a random master secret of at least 32 bytes from a protected owner-local secret store into the process environment as LDW_CHAT_RELAY_SECRET. Never commit or paste the actual secret, put it in a command-line argument, or expose it in logs. Start:

    python3 chat-relay/relay.py

Default binding is 127.0.0.1:8767. No standing service/autostart is created. Role tokens are provisioned locally by the trusted owner integration using Mailbox.token_for_role(); there is deliberately no HTTP endpoint that reveals them.

## Required integration gates before claiming owner outcome

Gate A: synthetic local transport (this PR); transport ACK != ChatGPT turn START.

Gate B: build reviewed plugin/connector tools in two *normal ChatGPT Chat* conversations: send_message, receive_messages, ack_message. They must authenticate to an owner-private HTTPS gateway carrying the same typed message contract. Existing infrastructure-tools #43 owner-private Operations Bridge is the preferred transport; never expose this loopback HTTP listener publicly. Chat recipient identities and the gateway must be independently reviewed.

Gate C: verify whether supported Chat-mode mechanisms can wake a named receiving conversation automatically. Current published APIs do not document arbitrary ChatGPT-thread message injection or wake. Do not claim unattended Chat-to-Chat PASS from a mailbox receipt. If a native mechanism is unavailable, state the limitation. No ChatGPT UI scraping, session-cookie extraction, usage-cap circumvention or unreviewed browser-side automation.

Gate D: non-GitHub IR candidates may carry a separately verifiable immutable artifact fingerprint and review provenance. GitHub may remain a governed source-control system, but it is not the runtime message bus. An independent review needs genuinely separate model judgment, exact candidate, known start, terminal finding, and no author self-review.

Related authority: infrastructure-tools #207, #43, #52; business-operations #470, #720. Source merge would not authorize deployment, plugin installation, remote message exposure, new privileged authority or spending. Target incremental cash: $0.
