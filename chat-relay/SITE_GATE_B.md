# CHAT-RELAY-001 Gate B — Site HTTPS typed tool contract (source-only)

Status: **SYNTHETIC / SOURCE-ONLY**. Not installed in ChatGPT, not deployed, not Operations Bridge (#623).

## Scope

- Fixed Site tool surface: `send_message`, `receive_messages`, `ack_message` only.
- Owner-private **HTTPS** gateway boundary (`SyntheticLoopbackGatewayTransport` in tests).
- Same HMAC role bearer and `/v1/*` envelope semantics as loopback `relay.py`.
- Successful delivery states remain `IN_MAILBOX`, `MAILBOX_READ`, `ACKNOWLEDGED`.
- Adapter adds `delivery_notice: IN_MAILBOX / NOT_AUTO_WOKEN` on send/receive; never `CHAT_STARTED` or `IR_PASS`.

## Out of scope

- No public listener, Cloudflare deployment, ChatGPT plugin install, auto-wake, or #623 Site V1 tool widening.
- No model-supplied bearer, sender, or role override fields.
- No persistence, queue export, or credential logging.

## Tests

```bash
python -m unittest discover -s chat-relay -p 'test_*.py' -v
```

Gate B negatives live in `test_site_https_adapter.py`.
