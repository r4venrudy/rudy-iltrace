using System.Security.Cryptography;
using System.Text.Json;
using Rudy.ILTrace;
using Rudy.ILTrace.Cli;

int checks = 0;
void Check(bool condition, string message)
{
    checks++;
    if (!condition) throw new InvalidOperationException("FAILED: " + message);
}
void Reject(Action action, string code)
{
    checks++;
    try { action(); }
    catch (AnalysisException ex) when (ex.Code == code) { return; }
    throw new InvalidOperationException("Expected rejection " + code);
}
string root = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
string Fixture(string name, string assembly) => Path.Combine(root, "tests", "Fixtures", name, "bin", "Release", "net10.0", assembly + ".dll");
string probePath = Fixture("Probe", "Probe");
string baselinePath = Fixture("Baseline", "VersionedFixture"), candidatePath = Fixture("Candidate", "VersionedFixture");

Check(IlDecoder.Decode([0x2a]).Count == 1, "ret opcode");
Check(IlDecoder.Decode([0x2b, 0x00, 0x2a])[0].BranchTargets.Single() == 2, "short branch target");
Check(IlDecoder.Decode([0xfe, 0x01, 0x2a]).Count == 2, "two-byte opcode");
Reject(() => IlDecoder.Decode([0xfe]), "IL.TRUNCATED");
Reject(() => IlDecoder.Decode([0xff]), "IL.OPCODE");
Reject(() => IlDecoder.Decode([0x28, 1]), "IL.TRUNCATED");
Reject(() => IlDecoder.Decode([0x21, 1, 2]), "IL.TRUNCATED");
Reject(() => IlDecoder.Decode([0x2b, 0xff, 0x2a]), "IL.BRANCH");
Reject(() => IlDecoder.Decode([0x2b, 0x7f, 0x2a]), "IL.BRANCH");
Reject(() => IlDecoder.Decode([0x45, 0xff, 0xff, 0xff, 0x7f]), "IL.SWITCH");
Reject(() => IlDecoder.Decode([0x45, 0xff, 0xff, 0xff, 0xff]), "IL.SWITCH");
Reject(() => IlDecoder.Decode([0x2a, 0x2a], 1), "LIMIT.INSTRUCTIONS");
var switchIl = new byte[] { 0x45, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a };
Check(IlDecoder.Decode(switchIl)[0].BranchTargets.Single() == 9, "switch target base");

var report = AssemblyAnalyzer.Analyze(probePath);
Check(report.AssemblyName == "Probe", "assembly identity");
Check(report.EntryPointToken is not null, "managed entry point");
Check(report.Sha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(probePath))).ToLowerInvariant(), "snapshot digest");
Check(report.Methods.Count > 15 && report.DecodedInstructions > 50, "real metadata and IL decoded");
Check(report.References.Any(r => r.Name == "System.Diagnostics.Process"), "assembly references");
Check(report.Resources.Any(r => r.Embedded && r.Name.EndsWith("marker.txt", StringComparison.Ordinal)), "resource inventory");
Check(report.Findings.Any(f => f.RuleId == "IL.PROCESS_START"), "process capability");
Check(report.Findings.Any(f => f.RuleId == "IL.NATIVE_IMPORT"), "native boundary");
Check(report.Findings.Any(f => f.Category == "network"), "network capability");
Check(report.Findings.Any(f => f.Category == "dynamic-load"), "assembly-load capability");
Check(report.Findings.Any(f => f.Category == "reflection"), "reflection capability");
Check(report.Findings.Any(f => f.Category == "indirect"), "calli coverage");
Check(report.Calls.Any(c => c.Kind == "function-reference" && c.Target.Contains("OnlyReferenced", StringComparison.Ordinal)), "function reference retained");
Check(report.Calls.Any(c => c.Kind == "local" && c.Target.Contains("Echo", StringComparison.Ordinal)), "generic method-spec local edge");
Check(report.Calls.Any(c => c.IsVirtual && c.Target.Contains("Probe.Base::Execute", StringComparison.Ordinal)), "declared virtual target");
Check(report.PublicSurface.All(a => !a.Id.Contains("OnlyReferenced", StringComparison.Ordinal)), "private method excluded from public surface");
Check(report.RecursiveGroups.Any(g => g.Any(t => report.Methods.Single(m => m.Token == t).Name == "CycleA") && g.Count == 2), "iterative SCC finds mutual recursion");
var entryTrace = GraphQueries.Trace(report, "entry");
Check(entryTrace.Paths.Any(p => p.Category == "process" && p.Steps.Count >= 3), "multi-hop entry to process path");
Check(entryTrace.Paths.Any(p => p.Category == "native" && p.Steps.Last().OpCode == "native-import"), "entry to native boundary");
Check(entryTrace.Paths.All(p => !p.Root.Contains("OnlyReferenced", StringComparison.Ordinal)), "entry roots are explicit");
Check(entryTrace.Paths.All(p => p.Category != "network"), "unreached public capability not assumed reachable");
Check(entryTrace.UnreachedFindings > 0, "unreached count retained");
Check(GraphQueries.Trace(report, "entry", "process").Paths.All(p => p.Category == "process"), "category filter");
Check(GraphQueries.Trace(report, "entry", maxDepth: 0).DepthLimitReached, "depth cutoff reported");
Check(GraphQueries.Trace(report, "all", maxPaths: 1).PathLimitReached, "path cutoff reported");
Check(GraphQueries.Trace(report, "all").IndirectCallSites == 1, "indirect count");
Check(GraphQueries.Trace(report, "all").DeclaredVirtualCallSites > 0, "virtual coverage count");
Check(GraphQueries.Trace(report, "all").MethodsWithoutBody > 0, "bodyless method count");
Reject(() => GraphQueries.Trace(report, maxDepth: 513), "LIMIT.TRACE");
Reject(() => GraphQueries.Trace(report, roots: "invalid"), "CLI.ROOTS");
Reject(() => AssemblyAnalyzer.Analyze(probePath, new(MaxFileBytes: 4)), "LIMIT.FILE");
Reject(() => AssemblyAnalyzer.Analyze(probePath, new(MaxMethods: 1)), "LIMIT.METADATA");
Reject(() => AssemblyAnalyzer.Analyze(probePath, new(MaxInstructions: 1)), "LIMIT.INSTRUCTIONS");
Reject(() => AssemblyAnalyzer.Analyze(probePath, new(MaxCallSites: 1)), "LIMIT.CALLS");
Reject(() => AssemblyAnalyzer.Analyze(probePath, new(MaxFileBytes: 0)), "LIMIT.CONFIG");

using (var json = JsonDocument.Parse(ReportFormats.Render(report, "json")))
    Check(json.RootElement.GetProperty("schema").GetString() == "rudy-iltrace/assembly/v1", "JSON schema id");
using (var sarif = JsonDocument.Parse(ReportFormats.Render(report, "sarif")))
{
    Check(sarif.RootElement.GetProperty("version").GetString() == "2.1.0", "SARIF version");
    var location = sarif.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0];
    Check(location.GetProperty("logicalLocations")[0].GetProperty("kind").GetString() == "function", "logical IL method location");
    Check(!location.GetProperty("physicalLocation").TryGetProperty("region", out _), "no invented source lines");
}
using (var sarif = JsonDocument.Parse(ReportFormats.Render(entryTrace, "sarif")))
    Check(sarif.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("codeFlows").GetArrayLength() == 1, "SARIF code-flow evidence");
Check(ReportFormats.Render(report, "dot").StartsWith("digraph ILTrace", StringComparison.Ordinal), "DOT graph");
Check(ReportFormats.Render(report, "json") == ReportFormats.Render(AssemblyAnalyzer.Analyze(probePath), "json"), "deterministic report");
Check(ReportFormats.Safe("\u001b[31m").StartsWith("\\u001b", StringComparison.Ordinal), "terminal escape sanitized");

var baseline = AssemblyAnalyzer.Analyze(baselinePath);
var candidate = AssemblyAnalyzer.Analyze(candidatePath);
var diff = GraphQueries.Diff(baseline, candidate);
Check(diff.ApiRemoved.Any(a => a.Id.Contains("Removed(", StringComparison.Ordinal)), "removed method surface");
Check(diff.ApiAdded.Any(a => a.Id.Contains("Added(", StringComparison.Ordinal)), "added method surface");
Check(diff.ApiAdded.All(a => !a.Id.Contains("Shared(", StringComparison.Ordinal)), "unchanged method survives token shifts");
Check(diff.CapabilitiesAdded.Any(c => c.StartsWith("process|", StringComparison.Ordinal)), "added capability");
Check(diff.ReferencesAdded.Any(r => r.StartsWith("System.Diagnostics.Process,", StringComparison.Ordinal)), "added assembly reference");
Check(GraphQueries.Diff(baseline, baseline).ApiAdded.Count == 0, "identity diff clean");
Check(GraphQueries.Diff(baseline, baseline).CapabilitiesAdded.Count == 0, "identity capability diff clean");
Reject(() => GraphQueries.Diff(baseline, candidate with { AssemblyName = "Other" }), "DIFF.IDENTITY");
Reject(() => GraphQueries.Trace(baseline, "entry"), "TRACE.NO_ENTRY");
using (var json = JsonDocument.Parse(ReportFormats.Render(diff, "json")))
    Check(json.RootElement.GetProperty("apiRemoved").GetArrayLength() > 0, "diff JSON");
Reject(() => ReportFormats.Render(diff, "sarif"), "CLI.FORMAT");

// Exercise SCC finish order with a diamond feeding a cycle, plus a long acyclic chain.
MethodNode Node(int token) => new(token, "M" + token, "Synthetic", "M" + token, "Public", true, true, false, null, null, 1);
CallSite Edge(int a, int b, int offset = 0) => new(a, offset, "call", "M" + b, b, "Synthetic", "local", false);
var graphNodes = Enumerable.Range(1, 6).Select(Node).ToArray();
var graphCalls = new[] { Edge(1, 2), Edge(1, 3, 1), Edge(2, 3), Edge(3, 4), Edge(4, 3), Edge(5, 6) };
var groups = GraphQueries.RecursiveGroups(graphNodes, graphCalls);
Check(groups.Count == 1 && groups[0].SequenceEqual([3, 4]), "SCC diamond finish order");
var longNodes = Enumerable.Range(1, 10_000).Select(Node).ToArray();
Check(GraphQueries.RecursiveGroups(longNodes, Enumerable.Range(1, 9999).Select(n => Edge(n, n + 1)).ToArray()).Count == 0, "iterative graph avoids stack recursion");
var fake = report with {
    Methods = graphNodes, Calls = [Edge(1, 2), Edge(2, 4), Edge(1, 4, 1)],
    EntryPointToken = 1, Findings = [new("SYNTHETIC", "note", "process", "test", 4, null, "external", "test")]
};
Check(GraphQueries.Trace(fake, "entry").Paths.Single().Steps.Count == 2, "BFS chooses shortest local path");
var referenceGraph = fake with { Calls = [new(1, 0, "ldftn", "M4", 4, "Synthetic", "function-reference", false)] };
Check(GraphQueries.Trace(referenceGraph, "entry").Paths.Count == 0, "ldftn is not an execution edge");

(int Code, string Out, string Error) Cli(params string[] a)
{
    using var output = new StringWriter(); using var error = new StringWriter();
    int code = CliApplication.Run(a, output, error);
    return (code, output.ToString(), error.ToString());
}
Check(Cli("--version").Code == 0, "CLI version");
Check(Cli("--help").Out.Contains("trace", StringComparison.Ordinal), "CLI help");
Check(Cli("scan", probePath, "--format", "json").Code == 0, "CLI JSON scan");
Check(Cli("scan", probePath, "--fail-on", "warning").Code == 1, "scan gate");
Check(Cli("trace", probePath, "--category", "process", "--fail-on", "warning").Code == 1, "trace gate");
Check(Cli("trace", probePath, "--max-depth", "0").Code == 2, "incomplete trace cannot pass gate");
Check(Cli("diff", baselinePath, candidatePath, "--fail-on", "api-removed").Code == 1, "diff API gate");
Check(Cli("diff", baselinePath, candidatePath, "--fail-on", "capability-added").Code == 1, "diff capability gate");
Check(Cli("scan", probePath, "--wat", "x").Code == 2, "unknown option");
Check(Cli("scan", probePath, "--format", "json", "--format", "text").Code == 2, "duplicate option");
Check(Cli("scan", probePath, "--max-file-mib", "-1").Code == 2, "invalid bound");
Check(Cli("trace", probePath, "--category", "typo").Code == 2, "invalid category");
Check(Cli("trace", baselinePath, "--roots", "entry").Code == 2, "missing entrypoint error");
Check(Cli("diff", baselinePath, candidatePath, "--format", "sarif").Code == 2, "unsupported format");
Check(Cli("scan", Path.Combine(root, "missing.dll")).Code == 2, "missing input");
byte[] before = SHA256.HashData(File.ReadAllBytes(probePath));
Check(Cli("scan", probePath, "--output", probePath).Code == 3, "input overwrite refused");
Check(before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(probePath))), "input hash unchanged");
string temp = Path.Combine(Path.GetTempPath(), "rudy-iltrace-test-" + Guid.NewGuid().ToString("N") + ".json");
try
{
    Check(Cli("scan", probePath, "--format", "json", "--output", temp).Code == 0, "new output file");
    byte[] original = File.ReadAllBytes(temp);
    Check(Cli("scan", probePath, "--format", "text", "--output", temp).Code == 3, "existing output preserved");
    Check(original.SequenceEqual(File.ReadAllBytes(temp)), "existing output bytes unchanged");
    using var json = JsonDocument.Parse(original);
    Check(json.RootElement.GetProperty("assemblyName").GetString() == "Probe", "UTF-8 report readable");
    File.WriteAllBytes(temp + ".bad", [1, 2, 3, 4]);
    Reject(() => AssemblyAnalyzer.Analyze(temp + ".bad"), "INPUT.MALFORMED");
}
finally { File.Delete(temp); File.Delete(temp + ".bad"); }
Console.WriteLine($"PASS: {checks} checks; generated assemblies inspected without executing fixture code.");
