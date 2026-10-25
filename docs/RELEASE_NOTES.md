# Rudy ILTrace v0.1.0-preview

Portable C#/.NET 10 static inspection of managed PE metadata and IL.

- Declared call graphs, recursive groups, native imports and API capability observations.
- Shortest capability paths from entry/public/all roots with explicit dynamic-call coverage.
- Public/protected surface, assembly-reference and capability comparisons across releases.
- Text, JSON, SARIF code flows and Graphviz DOT.
- Bounded parsing, traversal cutoffs and new-file-only reports.

The ZIP requires the .NET 10 runtime and includes synthetic inspection samples. The nupkg is an installable .NET tool distributed through this release. Verify each download against SHA256SUMS.

This is a developer preview. Paths represent metadata-declared calls; virtual overrides, delegates, reflection, async continuations, implicit initialization and dependency bodies are not resolved. Reports do not establish runtime reachability, maliciousness or full binary compatibility.
