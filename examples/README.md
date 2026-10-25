# Reproducible examples

Build the solution in Release configuration first. The analyzer reads the generated fixture files without running them.

## Capability trace

    dotnet run --project src/Rudy.ILTrace.Cli -c Release --no-build -- trace tests/Fixtures/Probe/bin/Release/net10.0/Probe.dll --category process

The declared graph contains Main → Stage → Launch → Process.Start. It also contains a conditional branch, a P/Invoke declaration, an indirect call, a function reference, an exception handler, a switch, a generic method invocation and mutually recursive methods. The test runner checks these distinctions.

For a JSON inventory or graph export:

    dotnet run --project src/Rudy.ILTrace.Cli -c Release --no-build -- scan tests/Fixtures/Probe/bin/Release/net10.0/Probe.dll --format json
    dotnet run --project src/Rudy.ILTrace.Cli -c Release --no-build -- scan tests/Fixtures/Probe/bin/Release/net10.0/Probe.dll --format dot

## Release comparison

    dotnet run --project src/Rudy.ILTrace.Cli -c Release --no-build -- diff tests/Fixtures/Baseline/bin/Release/net10.0/VersionedFixture.dll tests/Fixtures/Candidate/bin/Release/net10.0/VersionedFixture.dll --format json

The candidate removes Api.Removed, adds Api.Added and a process-launch capability, and adds the process assembly reference. Api.Shared remains unchanged despite metadata token movement.

## CLI options

scan accepts text, JSON, SARIF and DOT. trace accepts text, JSON and SARIF, with --roots auto|entry|public|all, --category, --max-depth and --max-paths. diff accepts text and JSON. All commands accept --output NEW_FILE and --max-file-mib.

Use --fail-on none|note|warning for scan/trace. Use --fail-on none|api-removed|capability-added|any for diff. A matched gate exits 1. A truncated trace exits 2 even when it writes a partial report.

The portable release ZIP uses samples/Probe.dll, samples/baseline/VersionedFixture.dll and samples/candidate/VersionedFixture.dll instead of the build-tree paths above.
