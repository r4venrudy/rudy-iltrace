# Analysis contract

ILTrace reads one bounded byte snapshot through PEReader and MetadataReader. It does not use Assembly.Load, reflection over target runtime types, dependency probing, target callbacks, subprocesses, or network enrichment. Reflection over the platform's OpCodes constants builds the IL decoding table; target code remains data.

## Graph model

A node is a declared method definition, identified in reports by metadata token and a stable textual signature. Local call, callvirt, newobj and jmp sites can create graph edges. MethodSpec resolves through its underlying declaration. MemberRef records retain their metadata-named owner, method signature and assembly scope.

Callvirt names the declared target; the graph does not enumerate overrides. ldftn and ldvirtftn are function references rather than invocation edges. calli is reported as indirect. Unmatched members are retained as unresolved. Referenced assemblies are inventoried but never followed, downloaded, loaded or executed.

The graph does not add implicit edges for type initializers, module initializers, finalizers, event callbacks, reflection, delegates, dependency implementations or compiler-generated async/iterator continuations. These limitations also apply when an application is otherwise well formed.

Trace uses deterministic breadth-first search from the managed entry point, declared public/protected methods, or all methods. Each result is one shortest declared path to a catalogued observation. Roots are ordered by signature and edges by target/IL offset. Recursion groups use iterative strongly connected component traversal. No method is assumed safe because it is unreached.

## Input and resource limits

Default limits are a 64 MiB input, 50,000 methods, 500,000 call/reference sites, 2,000,000 decoded instructions and 32 MiB total IL. Additional fixed ceilings cover type/reference/resource tables, 1,024-byte signature blobs, 4,096-character decoded signatures/names, 32-level type nesting, 32-dimensional array shapes and 65,536 switch entries. Accumulated method/surface/call text has a 16-million-character budget. These are preview limits, not supported performance claims.

The CLI can raise the file limit to 512 MiB. The library accepts bounded custom method/call/instruction/IL limits within hard ceilings. An exceeded parse budget fails without claiming a complete report.

Trace defaults to 64 local-call hops and 2,000 paths, with configurable hard ceilings of 512 hops and 100,000 paths. A cutoff is represented in the report and returns CLI exit 2. DOT export is limited to 5,000 total local/external nodes and 20,000 edges.

NativeAOT, netmodules, non-IL bodies, invalid instruction operands, out-of-body or operand-interior branches, and malformed exception regions are rejected. This is structural decoding, not a complete ECMA-335 verifier.

## Findings and identity

Rules recognize metadata-named API targets and declared native boundaries. Names can be spoofed. No rule establishes who provides the implementation at runtime, what inputs reach it, what branch is taken, whether a process has permission to act, or whether behavior is malicious.

Scan fingerprints hash the rule ID, method signature, IL offset and target. They are deterministic for the same snapshot, but IL movement can change a fingerprint. Release capability comparison intentionally ignores IL offsets and deduplicates category/method/target identities. MethodDef row-number changes alone do not create API-surface changes.

Diff requires matching declared assembly names. It compares declared public/protected types, methods and fields, with visible enclosing types, and records assembly versions separately. Properties/events are represented through their accessors. It is not a complete binary-compatibility check: custom attributes, generic constraints, constants/default values, type layout, forwarded types and semantic behavior are not compared.

## Outputs

JSON schemas are identified as rudy-iltrace/assembly/v1, rudy-iltrace/trace/v1 and rudy-iltrace/diff/v1. Consumers should ignore unknown fields in future compatible extensions. Text output is for review, not parsing.

SARIF 2.1.0 reports logical method locations and IL offset properties. Trace SARIF includes code flows for the declared steps. Physical source line numbers are intentionally absent.

The CLI writes UTF-8 and uses exclusive new-file creation for --output. It never overwrites an existing file. Report metadata may expose private names, imports and dependencies from the supplied binary; treat reports according to the input's confidentiality.

## References

- [Microsoft PEReader](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.pereader)
- [Microsoft metadata method definitions](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.metadata.methoddefinition)
- [ECMA-335 Common Language Infrastructure](https://ecma-international.org/publications-and-standards/standards/ecma-335/)
