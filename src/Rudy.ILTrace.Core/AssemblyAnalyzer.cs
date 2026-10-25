using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace Rudy.ILTrace;

public static class AssemblyAnalyzer
{
    private sealed record Target(string Id, string Owner, string Name, int? Token, string? Assembly);

    public static AssemblyReport Analyze(string path, AnalysisLimits? limits = null)
    {
        limits ??= new();
        if (limits.MaxFileBytes is < 1 or > 512L * 1024 * 1024 ||
            limits.MaxMethods is < 1 or > 200_000 || limits.MaxCallSites is < 1 or > 2_000_000 ||
            limits.MaxInstructions is < 1 or > 10_000_000 || limits.MaxTotalIlBytes is < 1 or > 256 * 1024 * 1024)
            throw new AnalysisException("LIMIT.CONFIG", "Analysis limits are outside supported ceilings.");
        try
        {
            byte[] snapshot = Snapshot(path, limits.MaxFileBytes);
            using var stream = new MemoryStream(snapshot, writable: false);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata || pe.PEHeaders.CorHeader is null)
                throw new AnalysisException("PE.NOT_MANAGED", "Input has no CLR metadata; supply a managed .NET PE assembly.");
            var md = pe.GetMetadataReader(MetadataReaderOptions.None);
            if (!md.IsAssembly) throw new AnalysisException("META.NETMODULE", "Standalone netmodules are outside the preview contract.");
            if (md.MethodDefinitions.Count > limits.MaxMethods || md.TypeDefinitions.Count > 50_000 ||
                md.AssemblyReferences.Count > 10_000 || md.ManifestResources.Count > 10_000 ||
                md.GetTableRowCount(TableIndex.InterfaceImpl) > 100_000 || md.FieldDefinitions.Count > 100_000 ||
                md.MemberReferences.Count > 200_000 || md.TypeReferences.Count > 100_000 ||
                md.GetTableRowCount(TableIndex.TypeSpec) > 50_000)
                throw new AnalysisException("LIMIT.METADATA", "Metadata table budget exceeded.");

            var names = new SignatureNames(md);
            long textCharacters = 0;
            void Charge(params string[] values)
            {
                foreach (string value in values) textCharacters += value.Length;
                if (textCharacters > 16 * 1024 * 1024)
                    throw new AnalysisException("LIMIT.TEXT", "Decoded report text exceeds 16 million characters.");
            }
            var assembly = md.GetAssemblyDefinition();
            string assemblyName = names.Text(assembly.Name);
            string version = assembly.Version.ToString();
            var methods = new Dictionary<int, MethodNode>();
            var localIds = new Dictionary<string, int>(StringComparer.Ordinal);
            var publicSurface = new List<ApiItem>();
            foreach (var typeHandle in md.TypeDefinitions)
            {
                var type = md.GetTypeDefinition(typeHandle);
                if (!IsVisibleType(md, typeHandle)) continue;
                string typeName = names.TypeName(typeHandle);
                string baseName = type.BaseType.IsNil ? "" : names.TypeName(type.BaseType);
                string interfaces = string.Join(",", type.GetInterfaceImplementations()
                    .Select(h => names.TypeName(md.GetInterfaceImplementation(h).Interface)).Order(StringComparer.Ordinal));
                string typeId = $"{typeName} [base={baseName};interfaces={interfaces};flags={type.Attributes & (TypeAttributes.Interface | TypeAttributes.Abstract | TypeAttributes.Sealed)}]";
                Charge(typeId);
                publicSurface.Add(new("type", typeId));
                foreach (var fieldHandle in type.GetFields())
                {
                    var field = md.GetFieldDefinition(fieldHandle);
                    var access = field.Attributes & FieldAttributes.FieldAccessMask;
                    if (access is not (FieldAttributes.Public or FieldAttributes.Family or FieldAttributes.FamORAssem)) continue;
                    names.CheckBlob(field.Signature);
                    string fieldType = field.DecodeSignature(names, (object?)null);
                    string fieldId = $"{typeName}::{names.Text(field.Name)}:{fieldType} [{field.Attributes}]";
                    Charge(fieldId);
                    publicSurface.Add(new("field", fieldId));
                }
            }

            foreach (var handle in md.MethodDefinitions)
            {
                var definition = md.GetMethodDefinition(handle);
                names.CheckBlob(definition.Signature);
                var signature = definition.DecodeSignature(names, (object?)null);
                string owner = names.TypeName(definition.GetDeclaringType());
                string name = names.Text(definition.Name);
                string id = SignatureNames.MethodId(owner, name, signature);
                Charge(id, owner, name);
                int token = MetadataTokens.GetToken(handle);
                var access = definition.Attributes & MethodAttributes.MemberAccessMask;
                bool api = IsVisibleType(md, definition.GetDeclaringType()) &&
                    access is MethodAttributes.Public or MethodAttributes.Family or MethodAttributes.FamORAssem;
                bool native = (definition.Attributes & MethodAttributes.PinvokeImpl) != 0;
                string? module = null, entry = null;
                if (native)
                {
                    var import = definition.GetImport();
                    if (import.Module.IsNil) throw new AnalysisException("META.IMPORT", "Native import has no module.");
                    module = names.Text(md.GetModuleReference(import.Module).Name);
                    entry = names.Text(import.Name);
                    Charge(module, entry);
                }
                var node = new MethodNode(token, id, owner, name, access.ToString(), api,
                    definition.RelativeVirtualAddress != 0, native, module, entry, 0);
                methods.Add(token, node);
                if (!localIds.TryAdd(id, token))
                    throw new AnalysisException("META.DUPLICATE_METHOD", "Duplicate method identity is outside the preview contract.");
                if (api)
                {
                    string apiId = id + $" [{definition.Attributes & (MethodAttributes.Abstract | MethodAttributes.Virtual | MethodAttributes.Final | MethodAttributes.NewSlot)}]";
                    Charge(apiId);
                    publicSurface.Add(new("method", apiId));
                }
            }

            var calls = new List<CallSite>();
            var findings = new List<Finding>();
            int totalIl = 0, instructions = 0;
            foreach (var handle in md.MethodDefinitions)
            {
                int sourceToken = MetadataTokens.GetToken(handle);
                var node = methods[sourceToken];
                var definition = md.GetMethodDefinition(handle);
                if (node.IsNativeImport)
                    findings.Add(MakeFinding("IL.NATIVE_IMPORT", "warning", "native", "Declared native import boundary.",
                        node, null, $"{node.NativeModule}!{node.NativeEntryPoint}"));
                if (definition.RelativeVirtualAddress == 0) continue;
                if ((definition.ImplAttributes & MethodImplAttributes.CodeTypeMask) != MethodImplAttributes.IL)
                    throw new AnalysisException("IL.NATIVE_BODY", "Non-IL method body is outside the preview contract.");
                var body = pe.GetMethodBody(definition.RelativeVirtualAddress);
                byte[] il = body.GetILBytes() ?? [];
                if ((long)totalIl + il.Length > limits.MaxTotalIlBytes)
                    throw new AnalysisException("LIMIT.IL_BYTES", "Total IL byte budget exceeded.");
                totalIl += il.Length;
                var decoded = IlDecoder.Decode(il, limits.MaxInstructions - instructions);
                instructions += decoded.Count;
                ValidateRegions(body, decoded, il.Length);
                methods[sourceToken] = node with { IlBytes = il.Length };
                foreach (var instruction in decoded)
                {
                    if (!instruction.IsCall && !instruction.IsFunctionReference && !instruction.IsIndirect) continue;
                    if (calls.Count >= limits.MaxCallSites) throw new AnalysisException("LIMIT.CALLS", "Call-site budget exceeded.");
                    if (instruction.MetadataToken is not int rawToken) throw new AnalysisException("META.CALL_TOKEN", "Call has no metadata token.");
                    if (instruction.IsIndirect)
                    {
                        var sigHandle = MetadataTokens.EntityHandle(rawToken);
                        if (sigHandle.Kind != HandleKind.StandaloneSignature)
                            throw new AnalysisException("META.CALLI", "Indirect call references an invalid standalone signature.");
                        var sig = md.GetStandaloneSignature((StandaloneSignatureHandle)sigHandle);
                        names.CheckBlob(sig.Signature);
                        _ = sig.DecodeMethodSignature(names, (object?)null);
                        calls.Add(new(sourceToken, instruction.Offset, instruction.OpCode, $"signature:0x{rawToken:x8}",
                            null, null, "indirect", false));
                        findings.Add(MakeFinding("IL.INDIRECT_CALL", "note", "indirect", "Indirect call target cannot be resolved by this model.",
                            node, instruction.Offset, $"signature:0x{rawToken:x8}"));
                        continue;
                    }
                    var target = Resolve(md, names, MetadataTokens.EntityHandle(rawToken), methods, localIds, assemblyName, 0);
                    Charge(target.Id, target.Id);
                    string kind = instruction.IsFunctionReference ? "function-reference" :
                        target.Token is not null ? "local" : target.Assembly is not null ? "external" : "unresolved";
                    calls.Add(new(sourceToken, instruction.Offset, instruction.OpCode, target.Id, target.Token,
                        target.Assembly, kind, instruction.IsVirtual));
                    if (instruction.IsFunctionReference) continue;
                    if (kind == "unresolved")
                        findings.Add(MakeFinding("IL.UNRESOLVED_CALL", "note", "coverage", "Declared member target could not be matched to a local method or assembly reference.",
                            node, instruction.Offset, target.Id));
                    else if (kind == "external")
                    {
                        var match = CapabilityRules.Classify(target.Owner, target.Name);
                        if (match is not null)
                            findings.Add(MakeFinding(match.Value.Rule, match.Value.Severity, match.Value.Category,
                                match.Value.Message, node, instruction.Offset, target.Id));
                    }
                }
            }

            int? entryPoint = null;
            var cor = pe.PEHeaders.CorHeader;
            if ((cor.Flags & CorFlags.NativeEntryPoint) == 0 && cor.EntryPointTokenOrRelativeVirtualAddress != 0)
            {
                int token = cor.EntryPointTokenOrRelativeVirtualAddress;
                if (!methods.ContainsKey(token)) throw new AnalysisException("META.ENTRYPOINT", "Entry point does not identify a declared method.");
                entryPoint = token;
            }
            var references = md.AssemblyReferences.Select(h =>
            {
                var reference = md.GetAssemblyReference(h);
                if (md.GetBlobReader(reference.PublicKeyOrToken).Length > 4096)
                    throw new AnalysisException("LIMIT.PUBLIC_KEY", "Assembly reference key/token exceeds 4096 bytes.");
                var result = new AssemblyReferenceInfo(names.Text(reference.Name), reference.Version.ToString(),
                    names.Text(reference.Culture), Convert.ToHexString(md.GetBlobBytes(reference.PublicKeyOrToken)).ToLowerInvariant());
                Charge(result.Name, result.Version, result.Culture, result.PublicKeyOrToken);
                return result;
            }).OrderBy(r => r.Name, StringComparer.Ordinal).ThenBy(r => r.Version, StringComparer.Ordinal).ToArray();
            var resources = md.ManifestResources.Select(h =>
            {
                var resource = md.GetManifestResource(h);
                var result = new ResourceInfo(names.Text(resource.Name), resource.Attributes.ToString(), resource.Implementation.IsNil);
                Charge(result.Name, result.Visibility);
                return result;
            }).OrderBy(r => r.Name, StringComparer.Ordinal).ToArray();
            var methodList = methods.Values.OrderBy(m => m.Id, StringComparer.Ordinal).ToArray();
            var callList = calls.OrderBy(c => methods[c.SourceToken].Id, StringComparer.Ordinal)
                .ThenBy(c => c.IlOffset).ThenBy(c => c.Target, StringComparer.Ordinal).ToArray();
            return new("rudy-iltrace/assembly/v1", Path.GetFileName(path), Convert.ToHexString(SHA256.HashData(snapshot)).ToLowerInvariant(),
                assemblyName, version, entryPoint, instructions, totalIl, methodList, callList, references,
                publicSurface.OrderBy(a => a.Kind, StringComparer.Ordinal).ThenBy(a => a.Id, StringComparer.Ordinal).ToArray(),
                resources, findings.OrderBy(f => methods[f.MethodToken].Id, StringComparer.Ordinal)
                    .ThenBy(f => f.IlOffset ?? -1).ThenBy(f => f.RuleId, StringComparer.Ordinal).ToArray(),
                GraphQueries.RecursiveGroups(methodList, callList));
        }
        catch (AnalysisException) { throw; }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or
                                   OverflowException or IndexOutOfRangeException or EndOfStreamException)
        {
            throw new AnalysisException("INPUT.MALFORMED", "Malformed or unsupported managed PE metadata/IL: " + ex.GetType().Name);
        }
    }

    private static byte[] Snapshot(string path, long maxBytes)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        long length = file.Length;
        if (length < 1 || length > maxBytes || length > int.MaxValue)
            throw new AnalysisException("LIMIT.FILE", "Input size is outside the configured file limit.");
        var bytes = new byte[(int)length];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1) throw new AnalysisException("INPUT.CHANGED", "Input grew while creating its bounded snapshot.");
        return bytes;
    }

    private static bool IsVisibleType(MetadataReader md, TypeDefinitionHandle handle)
    {
        for (int depth = 0; depth < 33; depth++)
        {
            var type = md.GetTypeDefinition(handle);
            var access = type.Attributes & TypeAttributes.VisibilityMask;
            var parent = type.GetDeclaringType();
            if (parent.IsNil) return access == TypeAttributes.Public;
            if (access is not (TypeAttributes.NestedPublic or TypeAttributes.NestedFamily or TypeAttributes.NestedFamORAssem)) return false;
            handle = parent;
        }
        throw new AnalysisException("LIMIT.TYPE_DEPTH", "Visible type nesting exceeds 32.");
    }

    private static Target Resolve(MetadataReader md, SignatureNames names, EntityHandle handle,
        IReadOnlyDictionary<int, MethodNode> methods, IReadOnlyDictionary<string, int> localIds, string assemblyName, int depth)
    {
        if (depth > 32) throw new AnalysisException("META.METHOD_CYCLE", "Method specification recursion exceeds 32.");
        if (handle.Kind == HandleKind.MethodDefinition)
        {
            int token = MetadataTokens.GetToken(handle);
            if (!methods.TryGetValue(token, out var method)) throw new AnalysisException("META.METHOD", "Call references a missing method.");
            return new(method.Id, method.Type, method.Name, token, assemblyName);
        }
        if (handle.Kind == HandleKind.MethodSpecification)
        {
            var spec = md.GetMethodSpecification((MethodSpecificationHandle)handle);
            names.CheckBlob(spec.Signature);
            var arguments = spec.DecodeSignature(names, (object?)null);
            var target = Resolve(md, names, spec.Method, methods, localIds, assemblyName, depth + 1);
            return target with { Id = target.Id + " <" + string.Join(",", arguments) + ">" };
        }
        if (handle.Kind == HandleKind.MemberReference)
        {
            var reference = md.GetMemberReference((MemberReferenceHandle)handle);
            if (reference.GetKind() != MemberReferenceKind.Method) throw new AnalysisException("META.METHOD", "Call references a field.");
            if (reference.Parent.Kind == HandleKind.MethodDefinition)
                return Resolve(md, names, reference.Parent, methods, localIds, assemblyName, depth + 1);
            names.CheckBlob(reference.Signature);
            var signature = reference.DecodeMethodSignature(names, (object?)null);
            string owner = names.TypeName(reference.Parent);
            string name = names.Text(reference.Name);
            string id = SignatureNames.MethodId(owner, name, signature);
            string? targetAssembly = names.TypeAssembly(reference.Parent);
            int? local = targetAssembly is null && localIds.TryGetValue(id, out int token) ? token : null;
            return new(id, owner, name, local, local is null ? targetAssembly : assemblyName);
        }
        throw new AnalysisException("META.METHOD", "Invocation references an unsupported metadata handle.");
    }

    private static void ValidateRegions(MethodBodyBlock body, IReadOnlyList<Instruction> instructions, int length)
    {
        var starts = instructions.Select(i => i.Offset).ToHashSet();
        foreach (var region in body.ExceptionRegions)
        {
            if (region.TryLength <= 0 || region.HandlerLength <= 0 ||
                !starts.Contains(region.TryOffset) || !starts.Contains(region.HandlerOffset) ||
                (long)region.TryOffset + region.TryLength > length || (long)region.HandlerOffset + region.HandlerLength > length)
                throw new AnalysisException("IL.EXCEPTION_REGION", "Exception region exceeds instruction boundaries.");
            int tryEnd = region.TryOffset + region.TryLength, handlerEnd = region.HandlerOffset + region.HandlerLength;
            if ((tryEnd != length && !starts.Contains(tryEnd)) || (handlerEnd != length && !starts.Contains(handlerEnd)) ||
                (region.Kind == ExceptionRegionKind.Filter && !starts.Contains(region.FilterOffset)))
                throw new AnalysisException("IL.EXCEPTION_REGION", "Exception region ends inside an instruction.");
        }
    }

    private static Finding MakeFinding(string rule, string severity, string category, string message,
        MethodNode method, int? offset, string target)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"{rule}\n{method.Id}\n{offset}\n{target}"))).ToLowerInvariant();
        return new(rule, severity, category, message, method.Token, offset, target, fingerprint);
    }
}
