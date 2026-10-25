namespace Rudy.ILTrace;

public sealed record AnalysisLimits(
    long MaxFileBytes = 64L * 1024 * 1024,
    int MaxMethods = 50_000,
    int MaxCallSites = 500_000,
    int MaxInstructions = 2_000_000,
    int MaxTotalIlBytes = 32 * 1024 * 1024);

public sealed class AnalysisException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record MethodNode(
    int Token, string Id, string Type, string Name, string Visibility,
    bool IsPublicApi, bool HasBody, bool IsNativeImport, string? NativeModule,
    string? NativeEntryPoint, int IlBytes);

public sealed record CallSite(
    int SourceToken, int IlOffset, string OpCode, string Target,
    int? TargetToken, string? TargetAssembly, string Kind, bool IsVirtual);

public sealed record Finding(
    string RuleId, string Severity, string Category, string Message,
    int MethodToken, int? IlOffset, string Target, string Fingerprint);

public sealed record AssemblyReferenceInfo(string Name, string Version, string Culture, string PublicKeyOrToken);
public sealed record ApiItem(string Kind, string Id);
public sealed record ResourceInfo(string Name, string Visibility, bool Embedded);

public sealed record AssemblyReport(
    string Schema, string FileName, string Sha256, string AssemblyName, string AssemblyVersion,
    int? EntryPointToken, int DecodedInstructions, int TotalIlBytes,
    IReadOnlyList<MethodNode> Methods, IReadOnlyList<CallSite> Calls,
    IReadOnlyList<AssemblyReferenceInfo> References, IReadOnlyList<ApiItem> PublicSurface,
    IReadOnlyList<ResourceInfo> Resources, IReadOnlyList<Finding> Findings,
    IReadOnlyList<IReadOnlyList<int>> RecursiveGroups);

public sealed record TraceStep(string From, int? IlOffset, string OpCode, string To, bool DeclaredVirtualTarget);
public sealed record CapabilityPath(string RuleId, string Category, string Severity, string Root, string Sink,
    IReadOnlyList<TraceStep> Steps, string Fingerprint);
public sealed record TraceReport(
    string Schema, string AssemblyName, string Sha256, string RootMode,
    IReadOnlyList<string> Roots, IReadOnlyList<CapabilityPath> Paths,
    int UnreachedFindings, int IndirectCallSites, int FunctionReferences,
    int UnresolvedCallSites, int DeclaredVirtualCallSites, int MethodsWithoutBody,
    bool DepthLimitReached, bool PathLimitReached);

public sealed record DiffReport(
    string Schema, string BaselineName, string CandidateName, string BaselineVersion, string CandidateVersion,
    string BaselineSha256, string CandidateSha256,
    IReadOnlyList<ApiItem> ApiAdded, IReadOnlyList<ApiItem> ApiRemoved,
    IReadOnlyList<string> ReferencesAdded, IReadOnlyList<string> ReferencesRemoved,
    IReadOnlyList<string> CapabilitiesAdded, IReadOnlyList<string> CapabilitiesRemoved);
