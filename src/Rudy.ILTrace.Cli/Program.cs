using System.Globalization;
using System.Text;
using Rudy.ILTrace;
using Rudy.ILTrace.Cli;

return CliApplication.Run(args, Console.Out, Console.Error);

namespace Rudy.ILTrace.Cli
{
    public static class CliApplication
    {
        public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
        {
            try
            {
                if (args.Length == 0 || args is ["--help"] or ["-h"]) { stdout.Write(Help); return 0; }
                if (args is ["--version"]) { stdout.WriteLine("Rudy ILTrace 0.1.0 (C# / .NET 10)"); return 0; }
                string command = args[0];
                if (command is not ("scan" or "trace" or "diff")) throw new AnalysisException("CLI.COMMAND", "Command must be scan, trace or diff.");
                var options = new Dictionary<string, string>(StringComparer.Ordinal);
                var files = new List<string>();
                for (int i = 1; i < args.Length; i++)
                {
                    if (!args[i].StartsWith("--", StringComparison.Ordinal)) { files.Add(args[i]); continue; }
                    string key = args[i];
                    bool allowed = key is "--format" or "--output" or "--fail-on" or "--max-file-mib" ||
                        command == "trace" && key is "--roots" or "--category" or "--max-depth" or "--max-paths";
                    if (!allowed || i + 1 >= args.Length || !options.TryAdd(key, args[++i]))
                        throw new AnalysisException("CLI.OPTION", $"Unknown, duplicate or incomplete option: {key}");
                }
                int expected = command == "diff" ? 2 : 1;
                if (files.Count != expected) throw new AnalysisException("CLI.FILES", $"{command} requires {expected} assembly file(s).");
                string format = options.GetValueOrDefault("--format", "text");
                string gate = options.GetValueOrDefault("--fail-on", "none");
                var limits = new AnalysisLimits(MaxFileBytes: Parse(options, "--max-file-mib", 64, 1, 512) * 1024L * 1024);
                object report;
                bool failed;
                bool incomplete = false;
                if (command == "diff")
                {
                    if (gate is not ("none" or "api-removed" or "capability-added" or "any"))
                        throw new AnalysisException("CLI.GATE", "Diff gate must be none, api-removed, capability-added or any.");
                    var diff = GraphQueries.Diff(AssemblyAnalyzer.Analyze(files[0], limits), AssemblyAnalyzer.Analyze(files[1], limits));
                    report = diff;
                    failed = gate switch
                    {
                        "api-removed" => diff.ApiRemoved.Count > 0,
                        "capability-added" => diff.CapabilitiesAdded.Count > 0,
                        "any" => diff.ApiAdded.Count + diff.ApiRemoved.Count + diff.ReferencesAdded.Count + diff.ReferencesRemoved.Count + diff.CapabilitiesAdded.Count + diff.CapabilitiesRemoved.Count > 0,
                        _ => false
                    };
                }
                else
                {
                    if (gate is not ("none" or "note" or "warning"))
                        throw new AnalysisException("CLI.GATE", "Scan/trace gate must be none, note or warning.");
                    var assembly = AssemblyAnalyzer.Analyze(files[0], limits);
                    if (command == "trace")
                    {
                        string? category = options.GetValueOrDefault("--category");
                        if (category is not (null or "process" or "network" or "native" or "dynamic-load" or "dynamic-code" or "reflection" or "deserialization" or "file-write" or "indirect"))
                            throw new AnalysisException("CLI.CATEGORY", "Unknown capability category.");
                        var trace = GraphQueries.Trace(assembly, options.GetValueOrDefault("--roots", "auto"), category,
                            Parse(options, "--max-depth", 64, 0, 512), Parse(options, "--max-paths", 2000, 1, 100_000));
                        report = trace;
                        incomplete = trace.DepthLimitReached || trace.PathLimitReached;
                        failed = gate != "none" && trace.Paths.Any(p => gate == "note" || p.Severity == "warning");
                    }
                    else
                    {
                        report = assembly;
                        failed = gate != "none" && assembly.Findings.Any(f => gate == "note" || f.Severity == "warning");
                    }
                }
                string rendered = ReportFormats.Render(report, format);
                if (options.TryGetValue("--output", out string? output))
                {
                    try
                    {
                        using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                        using var writer = new StreamWriter(file, new UTF8Encoding(false));
                        writer.Write(rendered);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        stderr.WriteLine("OUTPUT.WRITE: Report path must be new and writable; existing files are preserved.");
                        return 3;
                    }
                }
                else stdout.Write(rendered);
                if (incomplete)
                {
                    stderr.WriteLine("TRACE.INCOMPLETE: A depth or path cutoff was reached; review the report's coverage fields.");
                    return 2;
                }
                return failed ? 1 : 0;
            }
            catch (AnalysisException ex) { stderr.WriteLine($"{ex.Code}: {ReportFormats.Safe(ex.Message)}"); return 2; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine("INPUT.IO: " + ReportFormats.Safe(ex.Message));
                return 2;
            }
        }

        private static int Parse(IReadOnlyDictionary<string, string> options, string key, int fallback, int min, int max)
        {
            if (!options.TryGetValue(key, out string? text)) return fallback;
            if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value < min || value > max)
                throw new AnalysisException("CLI.NUMBER", $"{key} must be an integer in {min}..{max}.");
            return value;
        }

        private const string Help = """
Rudy ILTrace - offline .NET IL graphs and capability review

  rudy-iltrace scan ASSEMBLY [--format text|json|sarif|dot]
  rudy-iltrace trace ASSEMBLY [--roots auto|entry|public|all]
      [--category process|network|native|dynamic-load|dynamic-code|reflection|deserialization|file-write|indirect]
      [--max-depth 64] [--max-paths 2000] [--format text|json|sarif]
  rudy-iltrace diff BASELINE CANDIDATE [--format text|json]

Shared options: --output NEW_FILE, --max-file-mib 64
Scan/trace gates: --fail-on none|note|warning (default none)
Diff gates: --fail-on none|api-removed|capability-added|any (default none)
Exit codes: 0 completed/pass; 1 gate matched; 2 invalid/incomplete input; 3 output failure.

The tool reads metadata and IL bytes without loading target assemblies.
Call paths describe metadata declarations, not proven runtime execution.
""" + "\n";
    }
}
