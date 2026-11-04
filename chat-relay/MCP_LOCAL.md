# LDW Local Chat Relay MCP Adapter — source-only proof

**Goal:** expose LDW's own group-message transport through a standard local tool interface so separately configured clients can communicate without ChatGPT Work or GitHub acting as the runtime message bus.

**Proof only:** NOT installed as a ChatGPT plugin. Not evidence of two actual ChatGPT conversations talking, that a separate ChatGPT chat starts autonomously, or that autonomous model replies consume zero usage.

## Architecture

- One shared, owner-controlled, loopback-only group transport from `group_relay.py`.
- A role-bound local MCP stdio client `mcp_local.py`, one process per trusted local role, launched by a future approved plugin or client. Only the trusted launcher supplies `LDW_CHAT_RELAY_MCP_ROLE` and a locally provisioned `LDW_CHAT_RELAY_MCP_BEARER`; model tool arguments never choose an identity or provide tokens.
- The MCP client connects only to `127.0.0.1:<reviewed port>` over HTTP, with 3-second deadline and bounded results. No direct host shell, file system, privileged agent, Browser or GitHub API.
- Minimal fixed four tools: `list_groups`, `receive_group_messages`, `send_group_message`, `ack_group_message`. Sender IDs come only from the local client role. Message IDs are caller-supplied UUIDs, so an ambiguous send is **not automatically retried with a new ID**.
- MCP legacy handshake `2025-11-25` stdio JSON-RPC, line-delimited and 16KiB frame limit. This specific candidate does not advertise the modern `2026-07-28` era; use a reviewed current SDK before production interoperability. No network service is started by the MCP subprocess.
- Local relay is still in-memory, fixed-member, short-TTL and synthetic/public-only. It is not a permanent customer correspondence store.

## Test

After parent PR #212 code is checked out:

    python3 -m unittest discover -s chat-relay -p 'test_*.py' -v

`test_mcp_local.py` spins up one shared ephemeral group relay plus three local MCP tool clients and verifies:
- group message -> two independent recipients -> one ACK does not acknowledge the other;
- group reply/parent correlation and trusted sender identity;
- no role or bearer override from model-supplied tool arguments;
- wrong role-bound token rejected;
- only four fixed tools exposed, no shell/wake tool;
- MCP stdio initialize, tool discovery and syntax error behavior;
- no token printed in tool responses.

Source success establishes an integration **contract and working synthetic transport**. To claim actual ChatGPT Chat group messaging, a future supported private plugin must connect to an *actual* ChatGPT desktop/web account with real per-chat identity and approval. Current official plugin documentation makes availability/installation plan- and workspace-dependent, and local MCP desktop-only publication may require provider partner allowlisting. Neither this test nor an installed plugin automatically wakes idle ChatGPT conversations.

## Gates and security

Parent PR #208 direct relay and PR #212 group relay must be independently accepted/merged in sequence; this feature is stacked after both, with its own reviewer-separated exact-head review and CI. Standalone future plugins require separate trusted owner-local secure secret provisioning (this proof uses process environment only), per-chat role binding, chat provider permissions and source authentication. **Do not embed actual tokens in plugin manifests, command args, GitHub, ChatGPT messages or logs.**

No public HTTP listener, Cloudflare resource, browser profile, connected ChatGPT plugin, MCP tunnel, live customer/regulated content, Administrator/root service or paid model API is created by this source. No automatic conversational invocation/Work bypass; $0 incremental runtime cost for pure local message transport.

Official MCP protocol documentation: https://modelcontextprotocol.io/specification ; OpenAI local plugin constraints: https://developers.openai.com/plugins/deploy/desktop-only .
