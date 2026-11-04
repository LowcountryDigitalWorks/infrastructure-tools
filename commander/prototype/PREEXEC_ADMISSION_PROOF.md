# LDW Commander — Gate B pre-execution admission canary

**SOURCE-ONLY / NON-ELEVATED / NOT A PRIVILEGED COMMAND CLASSIFIER**

Owning product: infrastructure-tools issue #209. This is a **stacked draft** on the real process-drain and synthetic host-session journal proof in PR #221, which itself depends on #219, #217, #215 and the independently unaccepted Gate A security design #214.

## Owner outcome and boundary

The future LDW Commander must support genuinely owner-authorized Administrator/root terminal, file, process and service operations. This small proof does **not** replace that mandate with a fixed command catalog. It demonstrates how a **separately reviewed local operation's safety class** is established by trusted source, rather than a model-supplied label, and how authorization is denied *before* the local executable or host session starts.

The only admitted action is `RUN_DISPOSABLE_CHILD_CANARY`. Its implementation is the existing fixed, harmless, nonprivileged Python parent-and-child workload. The request contains exactly four fields: `contract`, `host`, `operation`, `operation_id`. The host is pinned by the local trusted host agent. There is no field for shell command, argv, file path, destination, subprocess, environment, risk label, or data class. Extra fields, wrong host, unknown operation, malformed ID, altered contract or a textual approval claim cause `COMMAND_NOT_ADMITTED`.

An allowed pre-execution request is **not** sufficient authorization: the existing independently signed *synthetic* owner decision and session issuer/host checks must also pass. The host's one-use session tombstone is not consumed until admission passes. The actual process does not launch until both gates pass. No model-generated safety classification is trusted.

## Negative proof

The tests issue proposed operations containing sample external HTTP/DNS destinations, purported secret file reads, base64-encoded shell, PowerShell, arbitrary commands, risk labels and owner-approval text. They confirm refusal **before** the fixed workload launches or the host-session journal is consumed. Because this source never executes those proposals, it does not exfiltrate the strings.

**A parser-based rejection test cannot establish network isolation.** The disposable fixed process happens not to perform network calls, but it runs in a regular non-elevated OS context. This work does NOT prove an external firewall/VM/network-namespace egress boundary or block a hostile arbitrary child that attempts egress. Those require separately reviewed protected OS/VM enforcement and an actual denied-packet negative proof under Gate A2 before real full-admin use.

Run after installing the parent's already-pinned test dependency:

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

Hosted Windows and Linux CI tests plus Secret Scan and CodeQL must pass at this exact head.

## Protection and eventual product scope

An **unrestricted, real FULL_ADMIN session** cannot be made safe merely by scanning a shell string or trusting a user-supplied `safe` label. The accepted Gate A design requires separate genuine owner identity, risk acceptance and command/egress class policy, protected process/OS isolation, out-of-privilege network/sensitive-data controls where feasible, protected anti-rollback/session journals, authenticated and encrypted remote transport, verifiable process descendant/service/task cleanup, quarantine and trusted recovery. Actual arbitrary Administrator/root commands may intentionally evade normal-user process-group/Job Object protections or read secrets; do not claim otherwise.

In the full product, arbitrary commands will be possible only after the explicitly authenticated, host/session-scoped FULL_ADMIN grant and accepted host/risk policy are in place. The fixed canary operation exists only to prove **authorization ordering** and negative admission behavior without exposing owner machines. It is not the final product interface, a persistent agent, an installed Host Agent observer, a ChatGPT Chat connector or the browser controller.

This proof adds no new privileges, network listener, enrolled host, customer/regulated data, paid service, secret or ongoing host control. Incremental cost target **$0**. GM17 authored the source and cannot conduct terminal independent security acceptance. No merge/deployment while upstream review gates remain open.
