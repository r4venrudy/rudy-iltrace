# Contributing

Use the .NET 10 SDK. The repository has no external package dependencies.

    dotnet build Rudy.ILTrace.slnx -c Release
    dotnet run --project tests/Rudy.ILTrace.Tests -c Release --no-build -- .

Parser and graph changes should include a small regression case. Prefer generated fixture assemblies or explicit synthetic IL byte arrays. Never execute an untrusted sample to prepare a contribution.

Keep the analysis contract accurate. Do not turn an unresolved target into a guessed edge, invent source-line locations, or label API references as proven runtime behavior. Document added rules, schema fields and comparison boundaries.

PowerShell 7 can build the release distribution with scripts/Package.ps1. Its output directory must be new.
