[CmdletBinding()]
param([string]$OutputDirectory = 'artifacts/release')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet command failed with exit $LASTEXITCODE" }
}

Push-Location $projectRoot
try {
    $releaseDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $releaseDirectory) {
        throw "Output directory must be new: $releaseDirectory"
    }
    New-Item -ItemType Directory -Path $releaseDirectory | Out-Null
    [xml]$buildProperties = Get-Content -Raw Directory.Build.props
    $packageVersion = [string]$buildProperties.Project.PropertyGroup.Version
    Invoke-Dotnet -Arguments @('build', 'Rudy.ILTrace.slnx', '-c', 'Release')
    Invoke-Dotnet -Arguments @('run', '--project', 'tests/Rudy.ILTrace.Tests', '-c', 'Release', '--no-build', '--', '.')
    Invoke-Dotnet -Arguments @('pack', 'src/Rudy.ILTrace.Cli', '-c', 'Release', '--no-build', '-o', $releaseDirectory)

    $portableDirectory = Join-Path $releaseDirectory 'portable'
    Invoke-Dotnet -Arguments @('publish', 'src/Rudy.ILTrace.Cli', '-c', 'Release', '--no-restore',
        '--no-self-contained', '-p:UseAppHost=false', '-o', $portableDirectory)
    Copy-Item README.md,LICENSE,NuGet.Config -Destination $portableDirectory
    Copy-Item -LiteralPath docs,assets -Destination $portableDirectory -Recurse
    $samplesDirectory = Join-Path $portableDirectory 'samples'
    $baselineDirectory = Join-Path $samplesDirectory 'baseline'
    $candidateDirectory = Join-Path $samplesDirectory 'candidate'
    New-Item -ItemType Directory -Force -Path $samplesDirectory,$baselineDirectory,$candidateDirectory | Out-Null
    Copy-Item tests/Fixtures/Probe/bin/Release/net10.0/Probe.dll -Destination $samplesDirectory
    Copy-Item tests/Fixtures/Baseline/bin/Release/net10.0/VersionedFixture.dll -Destination $baselineDirectory
    Copy-Item tests/Fixtures/Candidate/bin/Release/net10.0/VersionedFixture.dll -Destination $candidateDirectory
    Copy-Item examples/README.md -Destination (Join-Path $samplesDirectory 'README.md')

    $portableCli = Join-Path $portableDirectory 'Rudy.ILTrace.Cli.dll'
    $sampleAssembly = Join-Path $samplesDirectory 'Probe.dll'
    $smokePath = Join-Path $releaseDirectory 'portable-smoke.json'
    Invoke-Dotnet -Arguments @($portableCli, 'trace', $sampleAssembly, '--category', 'process', '--format', 'json', '--output', $smokePath)
    $smoke = Get-Content -Raw -LiteralPath $smokePath | ConvertFrom-Json
    if ($smoke.paths.Count -lt 1) { throw 'Portable trace smoke test found no process path.' }
    $archive = Join-Path $releaseDirectory "rudy-iltrace-portable-$packageVersion.zip"
    Compress-Archive -Path (Join-Path $portableDirectory '*') -DestinationPath $archive
    $releaseFiles = Get-ChildItem -LiteralPath $releaseDirectory -File |
        Where-Object { $_.Extension -in @('.zip','.nupkg') } | Sort-Object Name
    if ($releaseFiles.Count -ne 2) { throw 'Expected exactly one ZIP and one nupkg.' }
    $checksumLines = foreach ($releaseFile in $releaseFiles) {
        $digest = (Get-FileHash -LiteralPath $releaseFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$digest  $($releaseFile.Name)"
    }
    [IO.File]::WriteAllLines((Join-Path $releaseDirectory 'SHA256SUMS'), [string[]]$checksumLines, [Text.UTF8Encoding]::new($false))
    Write-Output "Packaged and smoke-tested $packageVersion in $releaseDirectory"
}
finally { Pop-Location }
