# Model output boundary (Gate B default deny)

Status: SOURCE-ONLY / NOT AN OWNER-ONLY CHANNEL

Issue: infrastructure-tools #209. Gate A requires raw command output to stay off the model-visible path. This module is only that refusal.

`project_model_output` returns `{"status": "MODEL_OUTPUT_BLOCKED"}` for every input. The reserved names `SYNTHETIC_CANARY_NOT_STARTED` and `SYNTHETIC_CANARY_FINISHED` are not accepted. A matching string is not authenticated host provenance, and this module has no trusted status producer. A future owner-side validated fixed-status adapter is separate work and is not built here.

The function does not read, scan, decode, redact, or return part of the input. Base64, hex, chunks, nested objects, byte buffers, exceptions, subclasses, and `safe` or `risk` fields are refused in full. An owner-only raw output channel is a future protected design and is not implemented here.

No process, file, network, credential, or new dependency is used. Cost: $0.
