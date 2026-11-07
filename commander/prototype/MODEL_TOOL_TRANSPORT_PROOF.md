# Simulated model tool result (default deny)

Status: SOURCE-ONLY / NOT A LIVE CONNECTOR

Issue: infrastructure-tools #209. `model_tool_result` always returns the fixed result from `project_model_output`. That result is `{"status": "MODEL_OUTPUT_BLOCKED"}`.

The function does not read, iterate, call, or log the payload. A generator is not advanced. A callback is not invoked. Flags such as `ok`, `approved`, or `safe` do not change the result. Reserved canary name strings do not either.

This is a simulated call only. It does not prove that a real MCP plugin, ChatGPT connector, host log, or telemetry path intercepts a stream. An owner-only raw output channel is not implemented.

No process, file, network, credential, or new dependency is used. Cost: $0.
