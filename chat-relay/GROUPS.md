# LDW Chat Relay: fixed-membership group messaging proof

Status: SOURCE ONLY / SYNTHETIC LOCAL TRANSPORT / NOT CONNECTED TO CHATGPT CHATS.

Group extension on the independently reviewed PR #208 baseline, now merged to `main`. This child also hardens the shared direct-message parser and suppresses HTTP traceback/client-address logging after independent Challenger findings. It does not install or modify the Operations Bridge, Admin Broker, host privileges, browser sessions, or any ChatGPT account. The relay is not a native OpenAI group chat and cannot itself wake a ChatGPT conversation.

## Roles and setup

A GM Chat, IR Chat, and specialist Chat can each have a distinct role and participate in the same relay room. This local proof uses only per-role bearer tokens, not authenticated ChatGPT conversation IDs.

Set LDW_CHAT_RELAY_ROOMS to JSON from trusted local configuration, for example:

    {"ldw-ir":["gm17","ir02","ops04"]}

Provision LDW_CHAT_RELAY_SECRET securely (32+ bytes). Do not also set the legacy direct-only `LDW_CHAT_RELAY_ROLES` environment variable in group mode; ambiguous configs refuse to start. Duplicate room names in JSON are rejected. Start the local Python process with:

    python3 chat-relay/group_relay.py

No standing service or public listener is created. It binds only to 127.0.0.1:8767. Never put actual credentials in repository source, user-visible chat, shell history or logs.

## Group API

Existing direct-message API from PR #208 remains usable.

- GET /v1/groups: shows only groups of the authenticated role, including member roles.
- POST /v1/groups/send: message_id UUID, group_id, sender, body, optional reply_to UUID. Sender must equal authenticated group-member role. One logical message is offered to every other member.
- GET /v1/groups/receive?group_id=ldw-ir&limit=20: delivers the caller's pending group messages. Own messages are excluded.
- POST /v1/groups/ack: group_id and message_id. ACK affects only the authenticated recipient, not other members.

GROUP_IN_MAILBOX means the message was stored locally. It does not establish a receiving ChatGPT turn, a model response, independent IR, or API/provider usage.

## Security and lifecycle

- Membership is fixed when the trusted local process starts: maximum 16 rooms, 2–12 members per room, unique role names. No remote create/invite/member mutation.
- Role-scoped tokens with constant-time bearer verification; no secrets returned over HTTP.
- Same UUID namespace for direct/group messages. Exact duplicate sends idempotent until expiry; altered UUID contents or cross-mode reuse fail closed.
- TTL 15 minutes, 128 combined direct/group retained envelopes, maximum 8 KiB body, maximum 20 messages per read. One actor may retain **at most 16 total** across direct and group messages, and one room **at most 32**. These fairness quotas limit the impact of a single sender or room but do not make a shared in-memory mailbox a production multi-tenant queue. ACK tombstones continue to count until expiration so an old UUID cannot be replayed.
- Each member individually ACKs; outsiders, cross-group replies and sender impersonation are rejected. Nonmembers cannot distinguish a missing room from an existing room by HTTP status. Direct messages are intentionally independent of room membership but share each sender's global quota. Group token scope is by registered role, not by named ChatGPT conversation; no real user identity is implied.
- No auto-reply, auto-wake, bot fanout cascade, queue poller, public port, persistence or administrative commands.
- Memory-only synthetic/public data; not a durable conversation archive or approved customer/regulated-data system.

## Test

    python3 -m unittest discover -s chat-relay -p test_*.py -v

The inherited dedicated CI workflow discovers the extended group tests in this branch, including fairness, room isolation and malformed direct-request negatives. Independent exact-head review and required CI/security gates are still needed; the prior Challenger CHANGES_REQUIRED H0/M1/L7 was on the *older* group head and cannot be treated as accepted source.

## Remaining product milestones

Gate A: independent review and acceptance of group source after PR #208 baseline. The child now includes a small reviewed-in-this-child correction to legacy direct HTTP parsing and sanitized error handling; do not claim the original parent code stayed untouched.

Gate B: owner-private supported MCP/plugin tools callable by two distinct ordinary ChatGPT Chat conversations without Work/GitHub as the runtime message bus; authentication bound to each actual chat/role.

Gate C: supported automatic recipient chat wake/turn semantics. Official documentation does not establish unrestricted message injection into an arbitrary existing ChatGPT chat. No UI scraping, hidden endpoint or account-session reuse as substitute.

Gate D: independently reasoned exact-artifact IR with real provider-positive START, terminal review, provenance exclusion and measured plan usage; ACK is never an IR PASS.

A group mailbox can return `GROUP_IN_MAILBOX` without causing any existing ChatGPT conversation to receive a new turn. ChatGPT's supported connector and autonomous wake capabilities require separate live provider verification; no feature or entitlement is inferred from these tests. The retained TTL still uses wall-clock time and is not a hardened rollback-resistant expiry guarantee. Related: infrastructure-tools #207 and #43; business-operations #470. $0 incremental, no deployment/spend/new credentials or privilege authorized.
