using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Rudy.ILTrace;

public static class ReportFormats
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string Render(object report, string format) => format switch
    {
        "json" => JsonSerializer.Serialize(report, report.GetType(), JsonOptions) + "\n",
        "text" => Text(report),
        "sarif" when report is AssemblyReport assembly => Sarif(assembly),
        "sarif" when report is TraceReport trace => TraceSarif(trace),
        "dot" when report is AssemblyReport assembly => Dot(assembly),
        _ => throw new AnalysisException("CLI.FORMAT", "Unsupported format for this command.")
    };

    public static string Safe(string value) => string.Concat(value.Select(c =>
        char.IsControl(c) && c is not '\n' and not '\t' ? $"\\u{(int)c:x4}" : c.ToString()));

    private static string Text(object report)
    {
        var b = new StringBuilder("Rudy ILTrace 0.1.0 - offline .NET metadata review\n");
        switch (report)
        {
            case AssemblyReport r:
                var methods = r.Methods.ToDictionary(m => m.Token);
                b.AppendLine($"{Safe(r.AssemblyName)} {r.AssemblyVersion} | SHA256 {r.Sha256}");
                b.AppendLine($"{r.Methods.Count} methods | {r.DecodedInstructions} instructions | {r.Calls.Count} call/reference sites | {r.Findings.Count} capability/coverage observations");
                b.AppendLine($"{r.PublicSurface.Count} public/protected surface entries | {r.RecursiveGroups.Count} recursive groups | {r.Resources.Count} manifest resources");
                b.AppendLine("Model: metadata-declared calls; dynamic dispatch, delegates, reflection and dependency bodies remain incomplete.");
                foreach (var f in r.Findings)
                    b.AppendLine($"[{f.Severity}] {f.RuleId} | {methods[f.MethodToken].Id} | {(f.IlOffset is int offset ? $"IL_{offset:x4}" : "declaration")} -> {f.Target}\n  {f.Message}");
                if (r.Findings.Count == 0) b.AppendLine("No catalogued capability was observed. This does not establish safety.");
                break;
            case TraceReport r:
                b.AppendLine($"{Safe(r.AssemblyName)} | roots={r.RootMode} ({r.Roots.Count}) | paths={r.Paths.Count} | unreached observations={r.UnreachedFindings}");
                b.AppendLine($"Coverage: {r.IndirectCallSites} indirect calls; {r.FunctionReferences} function references; {r.UnresolvedCallSites} unresolved calls; {r.DeclaredVirtualCallSites} declared virtual targets; {r.MethodsWithoutBody} methods without IL bodies");
                b.AppendLine($"Limits: depth cutoff={r.DepthLimitReached}; path cutoff={r.PathLimitReached}");
                b.AppendLine("Each path is a shortest path in the declared local-call graph; it does not prove a runtime execution path.");
                foreach (var path in r.Paths)
                {
                    b.AppendLine($"\n[{path.Severity}] {path.RuleId} / {path.Category}\n  ROOT {path.Root}");
                    foreach (var step in path.Steps)
                        b.AppendLine($"    {(step.IlOffset is int offset ? $"IL_{offset:x4}" : "native boundary")} {step.OpCode} -> {step.To}{(step.DeclaredVirtualTarget ? " [declared virtual target]" : "")}");
                }
                break;
            case DiffReport r:
                b.AppendLine($"{Safe(r.BaselineName)} {r.BaselineVersion} -> {Safe(r.CandidateName)} {r.CandidateVersion}");
                b.AppendLine($"Surface: +{r.ApiAdded.Count} -{r.ApiRemoved.Count} | references: +{r.ReferencesAdded.Count} -{r.ReferencesRemoved.Count} | capabilities: +{r.CapabilitiesAdded.Count} -{r.CapabilitiesRemoved.Count}");
                foreach (var item in r.ApiRemoved) b.AppendLine($"API - {item.Kind}: {item.Id}");
                foreach (var item in r.ApiAdded) b.AppendLine($"API + {item.Kind}: {item.Id}");
                foreach (string item in r.ReferencesRemoved) b.AppendLine("REF - " + item);
                foreach (string item in r.ReferencesAdded) b.AppendLine("REF + " + item);
                foreach (string item in r.CapabilitiesRemoved) b.AppendLine("CAP - " + item);
                foreach (string item in r.CapabilitiesAdded) b.AppendLine("CAP + " + item);
                b.AppendLine("Surface comparison is not a complete binary/source compatibility verdict.");
                break;
            default: throw new AnalysisException("REPORT.TYPE", "Unknown report type.");
        }
        return b.ToString();
    }

    private static string Sarif(AssemblyReport report)
    {
        var methods = report.Methods.ToDictionary(m => m.Token);
        var rules = report.Findings.Select(f => f.RuleId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)
            .Select(id => new { id, name = id, shortDescription = new { text = id } }).ToArray();
        var results = report.Findings.Select(f => new
        {
            ruleId = f.RuleId,
            level = f.Severity,
            message = new { text = $"{f.Message} Target: {f.Target}" },
            locations = new[] { new {
                physicalLocation = new { artifactLocation = new { uri = Uri.EscapeDataString(report.FileName), index = 0 } },
                logicalLocations = new[] { new { fullyQualifiedName = methods[f.MethodToken].Id, kind = "function" } }
            } },
            properties = new { methodToken = $"0x{f.MethodToken:x8}", ilOffset = f.IlOffset, category = f.Category },
            partialFingerprints = new Dictionary<string, string> { ["rudyIltrace/v1"] = f.Fingerprint }
        }).ToArray();
        return SerializeSarif(new {
            tool = new { driver = new { name = "Rudy ILTrace", version = "0.1.0", informationUri = "https://github.com/r4venrudy/rudy-iltrace", rules } },
            artifacts = new[] { new { location = new { uri = Uri.EscapeDataString(report.FileName) }, hashes = new Dictionary<string, string> { ["sha-256"] = report.Sha256 } } },
            results,
            properties = new { model = "metadata-declared IL calls; no runtime reachability proof" }
        });
    }

    private static string TraceSarif(TraceReport report)
    {
        var rules = report.Paths.Select(p => p.RuleId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)
            .Select(id => new { id, shortDescription = new { text = id } }).ToArray();
        var results = report.Paths.Select(p => new
        {
            ruleId = p.RuleId,
            level = p.Severity,
            message = new { text = $"Declared path from {p.Root} to {p.Sink}. Runtime conditions and dynamic dispatch are not resolved." },
            partialFingerprints = new Dictionary<string, string> { ["rudyIltrace/v1"] = p.Fingerprint },
            codeFlows = new[] { new { threadFlows = new[] { new {
                locations = p.Steps.Select((s, i) => new {
                    executionOrder = i + 1,
                    location = new {
                        logicalLocations = new[] { new { fullyQualifiedName = s.From, kind = "function" } },
                        message = new { text = $"{s.OpCode} -> {s.To}; IL offset={s.IlOffset}; declaredVirtual={s.DeclaredVirtualTarget}" }
                    }
                }).ToArray()
            } } } }
        }).ToArray();
        return SerializeSarif(new {
            tool = new { driver = new { name = "Rudy ILTrace", version = "0.1.0", informationUri = "https://github.com/r4venrudy/rudy-iltrace", rules } },
            results,
            properties = new { report.RootMode, report.UnreachedFindings, report.IndirectCallSites, report.FunctionReferences,
                report.UnresolvedCallSites, report.DeclaredVirtualCallSites, report.MethodsWithoutBody, report.DepthLimitReached, report.PathLimitReached }
        });
    }

    private static string SerializeSarif(object run)
    {
        var sarif = new Dictionary<string, object>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new[] { run }
        };
        return JsonSerializer.Serialize(sarif, JsonOptions) + "\n";
    }

    private static string Dot(AssemblyReport report)
    {
        var edges = report.Calls.Where(c => c.Kind is "local" or "external" or "unresolved").ToArray();
        var externals = edges.Where(c => c.TargetToken is null).Select(c => c.Target).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (report.Methods.Count + externals.Length > 5000 || edges.Length > 20_000)
            throw new AnalysisException("LIMIT.DOT", "DOT export exceeds 5000 nodes or 20000 edges; use JSON for this assembly.");
        static string Quote(string s) => "\"" + s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "\"";
        static string ExternalId(string s) => "e" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
        var b = new StringBuilder("digraph ILTrace {\n  rankdir=LR;\n  graph [bgcolor=\"#0b1118\"];\n  node [shape=box,color=\"#55e0b6\",fontcolor=\"#e6edf3\"];\n  edge [color=\"#8ba4b8\",fontcolor=\"#8ba4b8\"];\n");
        foreach (var method in report.Methods) b.AppendLine($"  m{method.Token:x8} [label={Quote(method.Id)}];");
        foreach (string external in externals) b.AppendLine($"  {ExternalId(external)} [label={Quote(external)},style=dashed];");
        foreach (var edge in edges)
        {
            string dest = edge.TargetToken is int token ? $"m{token:x8}" : ExternalId(edge.Target);
            b.AppendLine($"  m{edge.SourceToken:x8} -> {dest} [label={Quote($"IL_{edge.IlOffset:x4} {edge.OpCode}")}];");
        }
        return b.AppendLine("}").ToString();
    }
}
