# Security policy

ILTrace is an offline byte/metadata parser for files supplied by the operator. Treat binaries and reports as potentially confidential. Target assemblies and dependencies are never loaded, invoked, or probed at runtime.

Report parser crashes, unbounded resource use, incorrect target execution, unsafe report writes, or graph-model violations through GitHub private vulnerability reporting when available. Otherwise open a minimal issue requesting a private reporting channel; do not post sensitive binaries publicly.

Please include the tool version, OS, command, and a minimal synthetic reproducer. Metadata references to process/network/native APIs are ordinary analysis findings and do not by themselves establish a vulnerability in ILTrace or the target.

Supported version: 0.1.x preview. The exact resource budgets and unsupported inputs are documented in docs/CONTRACT.md.
