namespace Rudy.ILTrace;

public static class GraphQueries
{
    internal static IReadOnlyList<IReadOnlyList<int>> RecursiveGroups(IReadOnlyList<MethodNode> methods, IReadOnlyList<CallSite> calls)
    {
        var nodes = methods.Select(m => m.Token).ToArray();
        var adjacency = nodes.ToDictionary(n => n, _ => new HashSet<int>());
        var reverse = nodes.ToDictionary(n => n, _ => new HashSet<int>());
        foreach (var call in calls.Where(c => c.Kind == "local" && c.TargetToken is not null))
        {
            adjacency[call.SourceToken].Add(call.TargetToken!.Value);
            reverse[call.TargetToken.Value].Add(call.SourceToken);
        }
        var visited = new HashSet<int>();
        var order = new List<int>();
        var ordered = adjacency.ToDictionary(p => p.Key, p => p.Value.Order().ToArray());
        foreach (int root in nodes)
        {
            if (!visited.Add(root)) continue;
            var stack = new Stack<(int Node, int Next)>();
            stack.Push((root, 0));
            while (stack.TryPop(out var item))
            {
                var edges = ordered[item.Node];
                if (item.Next >= edges.Length) { order.Add(item.Node); continue; }
                stack.Push((item.Node, item.Next + 1));
                int next = edges[item.Next];
                if (visited.Add(next)) stack.Push((next, 0));
            }
        }
        visited.Clear();
        var result = new List<IReadOnlyList<int>>();
        foreach (int root in order.AsEnumerable().Reverse())
        {
            if (!visited.Add(root)) continue;
            var component = new List<int>();
            var stack = new Stack<int>();
            stack.Push(root);
            while (stack.TryPop(out int current))
            {
                component.Add(current);
                foreach (int next in reverse[current]) if (visited.Add(next)) stack.Push(next);
            }
            if (component.Count > 1 || adjacency[root].Contains(root))
                result.Add(component.Order().ToArray());
        }
        return result.OrderBy(g => g[0]).ToArray();
    }

    public static TraceReport Trace(AssemblyReport report, string roots = "auto", string? category = null, int maxDepth = 64, int maxPaths = 2000)
    {
        if (maxDepth is < 0 or > 512 || maxPaths is < 1 or > 100_000)
            throw new AnalysisException("LIMIT.TRACE", "Trace depth must be 0..512 and path count 1..100000.");
        if (roots == "auto") roots = report.EntryPointToken is null ? "public" : "entry";
        var methods = report.Methods.ToDictionary(m => m.Token);
        int[] rootTokens = roots switch
        {
            "entry" => report.EntryPointToken is int entry ? [entry] :
                throw new AnalysisException("TRACE.NO_ENTRY", "Assembly has no managed entry point; select public or all roots."),
            "public" => report.Methods.Where(m => m.IsPublicApi).Select(m => m.Token).ToArray(),
            "all" => report.Methods.Select(m => m.Token).ToArray(),
            _ => throw new AnalysisException("CLI.ROOTS", "Root mode must be auto, entry, public or all.")
        };
        var adjacency = report.Calls.Where(c => c.Kind == "local" && c.TargetToken is not null)
            .GroupBy(c => c.SourceToken).ToDictionary(g => g.Key,
                g => g.OrderBy(c => c.Target, StringComparer.Ordinal).ThenBy(c => c.IlOffset).ToArray());
        var predecessor = new Dictionary<int, CallSite?>();
        var depth = new Dictionary<int, int>();
        var rootOf = new Dictionary<int, int>();
        var queue = new Queue<int>();
        foreach (int root in rootTokens.OrderBy(t => methods[t].Id, StringComparer.Ordinal))
            if (predecessor.TryAdd(root, null)) { depth[root] = 0; rootOf[root] = root; queue.Enqueue(root); }
        bool depthHit = false;
        while (queue.TryDequeue(out int current))
        {
            if (!adjacency.TryGetValue(current, out var edges)) continue;
            foreach (var edge in edges)
            {
                int next = edge.TargetToken!.Value;
                if (predecessor.ContainsKey(next)) continue;
                if (depth[current] >= maxDepth) { depthHit = true; continue; }
                predecessor[next] = edge; depth[next] = depth[current] + 1; rootOf[next] = rootOf[current];
                queue.Enqueue(next);
            }
        }
        var paths = new List<CapabilityPath>();
        var callByLocation = report.Calls.ToDictionary(c => (c.SourceToken, c.IlOffset));
        int unreached = 0;
        bool pathHit = false;
        foreach (var finding in report.Findings.Where(f => f.Category != "coverage" && (category is null || f.Category == category)))
        {
            if (!predecessor.ContainsKey(finding.MethodToken)) { unreached++; continue; }
            if (paths.Count >= maxPaths) { pathHit = true; continue; }
            var chain = new List<TraceStep>();
            int cursor = finding.MethodToken;
            while (predecessor[cursor] is CallSite edge)
            {
                chain.Add(new(methods[edge.SourceToken].Id, edge.IlOffset, edge.OpCode, methods[cursor].Id, edge.IsVirtual));
                cursor = edge.SourceToken;
            }
            chain.Reverse();
            var sinkCall = finding.IlOffset is int offset && callByLocation.TryGetValue((finding.MethodToken, offset), out var call) ? call : null;
            chain.Add(new(methods[finding.MethodToken].Id, finding.IlOffset, sinkCall?.OpCode ?? "native-import",
                finding.Target, sinkCall?.IsVirtual ?? false));
            paths.Add(new(finding.RuleId, finding.Category, finding.Severity, methods[rootOf[finding.MethodToken]].Id,
                finding.Target, chain, finding.Fingerprint));
        }
        return new("rudy-iltrace/trace/v1", report.AssemblyName, report.Sha256, roots,
            rootTokens.Select(t => methods[t].Id).Order(StringComparer.Ordinal).ToArray(), paths, unreached,
            report.Calls.Count(c => c.Kind == "indirect"), report.Calls.Count(c => c.Kind == "function-reference"),
            report.Calls.Count(c => c.Kind == "unresolved"), report.Calls.Count(c => c.IsVirtual),
            report.Methods.Count(m => !m.HasBody),
            depthHit, pathHit);
    }

    public static DiffReport Diff(AssemblyReport baseline, AssemblyReport candidate)
    {
        if (!string.Equals(baseline.AssemblyName, candidate.AssemblyName, StringComparison.Ordinal))
            throw new AnalysisException("DIFF.IDENTITY", "Compare releases with the same declared assembly name.");
        static string Ref(AssemblyReferenceInfo r) => $"{r.Name}, Version={r.Version}, Culture={r.Culture}, KeyOrToken={r.PublicKeyOrToken}";
        static IEnumerable<string> Capabilities(AssemblyReport r)
        {
            var methods = r.Methods.ToDictionary(m => m.Token);
            return r.Findings.Where(f => f.Category != "coverage").Select(f =>
                $"{f.Category}|{methods[f.MethodToken].Id}|{f.Target}").Distinct(StringComparer.Ordinal);
        }
        var beforeApi = baseline.PublicSurface.ToHashSet();
        var afterApi = candidate.PublicSurface.ToHashSet();
        var beforeRefs = baseline.References.Select(Ref).ToHashSet(StringComparer.Ordinal);
        var afterRefs = candidate.References.Select(Ref).ToHashSet(StringComparer.Ordinal);
        var beforeCaps = Capabilities(baseline).ToHashSet(StringComparer.Ordinal);
        var afterCaps = Capabilities(candidate).ToHashSet(StringComparer.Ordinal);
        return new("rudy-iltrace/diff/v1", baseline.AssemblyName, candidate.AssemblyName,
            baseline.AssemblyVersion, candidate.AssemblyVersion, baseline.Sha256, candidate.Sha256,
            afterApi.Except(beforeApi).OrderBy(a => a.Kind, StringComparer.Ordinal).ThenBy(a => a.Id, StringComparer.Ordinal).ToArray(),
            beforeApi.Except(afterApi).OrderBy(a => a.Kind, StringComparer.Ordinal).ThenBy(a => a.Id, StringComparer.Ordinal).ToArray(),
            afterRefs.Except(beforeRefs).Order(StringComparer.Ordinal).ToArray(), beforeRefs.Except(afterRefs).Order(StringComparer.Ordinal).ToArray(),
            afterCaps.Except(beforeCaps).Order(StringComparer.Ordinal).ToArray(), beforeCaps.Except(afterCaps).Order(StringComparer.Ordinal).ToArray());
    }
}
