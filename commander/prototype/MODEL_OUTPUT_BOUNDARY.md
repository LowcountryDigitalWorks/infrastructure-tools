# Model output boundary (Gate B default deny)

Status: SOURCE-ONLY / NOT AN OWNER-ONLY CHANNEL

Issue: infrastructure-tools #209. Gate A requires raw command output to stay off the model-visible path. This module is only that refusal.

`project_model_output` returns `{"status": "MODEL_OUTPUT_BLOCKED"}` for every value that is not one of two exact strings: `SYNTHETIC_CANARY_NOT_STARTED` or `SYNTHETIC_CANARY_FINISHED`. Those two results are also a single status field. A matching string does not prove a process ran.

The function does not scan, decode, redact, or return part of the input. Base64, hex, chunks, nested objects, byte buffers, exceptions, and `safe` or `risk` fields are refused in full. An owner-only raw output channel is a future protected design and is not implemented here.

No process, file, network, credential, or new dependency is used. Cost: $0.
