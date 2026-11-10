# message_board_ui_v0 — read-model capability (source-only)

**Authority:** infrastructure-tools #207 (`message_board_ui_v0` gate per owner comment 6730467322).
**Status:** SOURCE ONLY — no Site plugin deploy, no queue, no database, no ChatGPT wake.

## Purpose

Present **actionable honest per-role inbox rows** derived only from accepted Gate B `receive_messages` validation (`site_https_adapter.py`). This is a **read projection**, not a second mailbox.

## UI truth labels

| Field | Fixed value |
| --- | --- |
| `ui_representation` | `IN_MAILBOX` |
| `poll_notice` | `MANUAL_OR_TOOL_POLL_REQUIRED` |
| `wake_authority` (status) | `NONE` |

Never emit `CHAT_STARTED`, `IR_PASS`, `AUTO_WOKEN`, or fabricated delivery.

## Row schema (`poll_rows`)

Each row includes: `message_id`, `sender_role`, `recipient_role`, `reply_to`, bounded `preview` (no raw body; synthetic fixture regex only — not universal secret redaction), `age_seconds` or `UNKNOWN` (nonfinite/bool timestamps fail closed), `ttl_seconds_remaining` always `UNKNOWN` (relay TTL is monotonic server-side; envelopes carry `created_at` only), `delivery_state`=`IN_MAILBOX`, `ack_state`=`UNACKED_IN_MAILBOX`, `correlation_id` (= message_id), plus UI labels above.

## Future plugin sidebar/panel tools (not deployed)

Frozen read-only catalog from `MessageBoardUiV0.future_plugin_tools()`:

1. **`list_inbox_rows`** — optional `limit` 1..20; returns `poll_rows` envelope for the construction-bound role only.
2. **`inbox_status`** — protocol/role/delivery notice without message bodies.

Owner-private HTTPS + #43 Operations Bridge remains the future wire target; this document does not authorize Operations Site #623 mutation (frozen three-tool V1).

## Handoff to Gate B / #43

- Construction-bound role + bearer remain outside model tool arguments (same as Gate B).
- Two ordinary ChatGPT Chat plugin-connected role tests are required before claiming UI usability; until then status is **IN_MAILBOX / MANUAL_OR_TOOL_POLL_REQUIRED**.
- No GitHub message bus, no Work runtime, $0 incremental.
