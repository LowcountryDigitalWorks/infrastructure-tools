# LDW Chat Relay: fixed-membership group messaging proof

Status: SOURCE ONLY / SYNTHETIC LOCAL TRANSPORT / NOT CONNECTED TO CHATGPT CHATS.

Additive group extension stacked on PR #208. Original relay code remains unchanged. It does not install or modify the Operations Bridge, Admin Broker, host privileges, browser sessions, or any ChatGPT account. The relay is not a native OpenAI group chat and cannot itself wake a ChatGPT conversation.

## Roles and setup

A GM Chat, IR Chat, and specialist Chat can each have a distinct role and participate in the same relay room. This local proof uses only per-role bearer tokens, not authenticated ChatGPT conversation IDs.

Set LDW_CHAT_RELAY_ROOMS to JSON from trusted local configuration, for example:

    {"ldw-ir":["gm17","ir02","ops04"]}

Provision LDW_CHAT_RELAY_SECRET securely (32+ bytes), and start the local Python process with:

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
- TTL 15 minutes, 128 combined direct/group messages, maximum 8 KiB body, maximum 20 messages per read.
- Each member individually ACKs; outsiders, cross-group replies and sender impersonation are rejected.
- No auto-reply, auto-wake, bot fanout cascade, queue poller, public port, persistence or administrative commands.
- Memory-only synthetic/public data; not a durable conversation archive or approved customer/regulated-data system.

## Test

    python3 -m unittest discover -s chat-relay -p test_*.py -v

PR #208's already-existing dedicated CI workflow discovers the extended group tests in this stacked branch. Independent exact-head review and required CI/security gates are still needed.

## Remaining product milestones

Gate A: independent review and acceptance of group source after PR #208 baseline, without changing the original reviewed code.

Gate B: owner-private supported MCP/plugin tools callable by two distinct ordinary ChatGPT Chat conversations without Work/GitHub as the runtime message bus; authentication bound to each actual chat/role.

Gate C: supported automatic recipient chat wake/turn semantics. Official documentation does not establish unrestricted message injection into an arbitrary existing ChatGPT chat. No UI scraping, hidden endpoint or account-session reuse as substitute.

Gate D: independently reasoned exact-artifact IR with real provider-positive START, terminal review, provenance exclusion and measured plan usage; ACK is never an IR PASS.

OpenAI native user group chats began retirement July 2026. This is an LDW transport goal, not a claim of native feature availability. Related: infrastructure-tools #207 and #43; business-operations #470. $0 incremental, no deployment/spend/new credentials or privilege authorized.
