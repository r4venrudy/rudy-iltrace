using System.Collections.Immutable;
using System.Reflection.Metadata;

namespace Rudy.ILTrace;

internal sealed class SignatureNames(MetadataReader reader) : ISignatureTypeProvider<string, object?>
{
    private readonly HashSet<TypeSpecificationHandle> activeSpecifications = [];

    public string Text(StringHandle handle)
    {
        string value = reader.GetString(handle);
        if (value.Length > 4096) throw new AnalysisException("LIMIT.STRING", "Metadata name exceeds 4096 characters.");
        return string.Concat(value.Select(c => c == '\\' ? "\\\\" : char.IsControl(c) ? $"\\u{(int)c:x4}" : c.ToString()));
    }

    public void CheckBlob(BlobHandle handle)
    {
        if (reader.GetBlobReader(handle).Length > 1024)
            throw new AnalysisException("LIMIT.SIGNATURE", "Signature blob exceeds the 1024-byte preview limit.");
    }

    public string TypeName(EntityHandle handle, int depth = 0)
    {
        if (depth > 32) throw new AnalysisException("LIMIT.TYPE_DEPTH", "Metadata type nesting exceeds 32.");
        return handle.Kind switch
        {
            HandleKind.TypeDefinition => Definition((TypeDefinitionHandle)handle, depth),
            HandleKind.TypeReference => Reference((TypeReferenceHandle)handle, depth),
            HandleKind.TypeSpecification => GetTypeFromSpecification(reader, null, (TypeSpecificationHandle)handle, 0),
            _ => throw new AnalysisException("META.TYPE", "Invalid type metadata handle.")
        };
    }

    private string Definition(TypeDefinitionHandle handle, int depth)
    {
        var type = reader.GetTypeDefinition(handle);
        string name = Text(type.Name);
        var parent = type.GetDeclaringType();
        return parent.IsNil ? Qualified(Text(type.Namespace), name) : TypeName(parent, depth + 1) + "+" + name;
    }

    private string Reference(TypeReferenceHandle handle, int depth)
    {
        var type = reader.GetTypeReference(handle);
        string name = Text(type.Name);
        return type.ResolutionScope.Kind == HandleKind.TypeReference
            ? TypeName(type.ResolutionScope, depth + 1) + "+" + name
            : Qualified(Text(type.Namespace), name);
    }

    public string? TypeAssembly(EntityHandle handle, int depth = 0)
    {
        if (depth > 32) throw new AnalysisException("LIMIT.TYPE_DEPTH", "Type scope nesting exceeds 32.");
        if (handle.Kind == HandleKind.TypeReference)
        {
            var scope = reader.GetTypeReference((TypeReferenceHandle)handle).ResolutionScope;
            return scope.Kind == HandleKind.AssemblyReference
                ? Text(reader.GetAssemblyReference((AssemblyReferenceHandle)scope).Name)
                : scope.Kind == HandleKind.TypeReference ? TypeAssembly(scope, depth + 1) : null;
        }
        if (handle.Kind == HandleKind.TypeSpecification)
        {
            var signature = reader.GetTypeSpecification((TypeSpecificationHandle)handle).Signature;
            CheckBlob(signature);
            var blob = reader.GetBlobReader(signature);
            if (blob.RemainingBytes == 0) return null;
            byte kind = blob.ReadByte();
            if (kind == 0x15 && blob.RemainingBytes > 0) kind = blob.ReadByte();
            if (kind is 0x11 or 0x12) return TypeAssembly(blob.ReadTypeHandle(), depth + 1);
        }
        return null;
    }

    private static string Qualified(string ns, string name) => ns.Length == 0 ? name : ns + "." + name;
    private static string Bounded(string value) => value.Length <= 4096 ? value :
        throw new AnalysisException("LIMIT.SIGNATURE", "Decoded signature exceeds 4096 characters.");

    public static string MethodId(string owner, string name, MethodSignature<string> signature)
    {
        string generic = signature.GenericParameterCount == 0 ? "" : $"~g{signature.GenericParameterCount}";
        string mode = signature.Header.IsInstance ? "instance" : "static";
        return Bounded($"{owner}::{name}{generic}({string.Join(",", signature.ParameterTypes)}):{signature.ReturnType} [{mode};header={signature.Header.RawValue:x2};required={signature.RequiredParameterCount}]");
    }

    public string GetArrayType(string elementType, ArrayShape shape)
    {
        if (shape.Rank is < 1 or > 32 || shape.Sizes.Length > 32 || shape.LowerBounds.Length > 32)
            throw new AnalysisException("LIMIT.ARRAY_RANK", "Array signature shape exceeds the preview limit.");
        return Bounded(elementType + $"[rank={shape.Rank};sizes={string.Join(",", shape.Sizes)};lower={string.Join(",", shape.LowerBounds)}]");
    }
    public string GetByReferenceType(string elementType) => Bounded(elementType + "&");
    public string GetFunctionPointerType(MethodSignature<string> signature) => Bounded("methodptr(" + string.Join(",", signature.ParameterTypes) + $"):{signature.ReturnType}[header={signature.Header.RawValue:x2};required={signature.RequiredParameterCount}]");
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => Bounded(genericType + "<" + string.Join(",", typeArguments) + ">");
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => Bounded(unmodifiedType + (isRequired ? " modreq(" : " modopt(") + modifier + ")");
    public string GetPinnedType(string elementType) => Bounded(elementType + " pinned");
    public string GetPointerType(string elementType) => Bounded(elementType + "*");
    public string GetSZArrayType(string elementType) => Bounded(elementType + "[]");
    public string GetTypeFromDefinition(MetadataReader metadataReader, TypeDefinitionHandle handle, byte rawTypeKind) => TypeName(handle);
    public string GetTypeFromReference(MetadataReader metadataReader, TypeReferenceHandle handle, byte rawTypeKind) => TypeName(handle);
    public string GetTypeFromSpecification(MetadataReader metadataReader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
    {
        if (activeSpecifications.Count >= 32 || !activeSpecifications.Add(handle))
            throw new AnalysisException("META.TYPE_CYCLE", "Recursive or excessively nested type specification.");
        try
        {
            var type = reader.GetTypeSpecification(handle);
            CheckBlob(type.Signature);
            return Bounded(type.DecodeSignature(this, genericContext));
        }
        finally { activeSpecifications.Remove(handle); }
    }
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Void => "System.Void", PrimitiveTypeCode.Boolean => "System.Boolean",
        PrimitiveTypeCode.Char => "System.Char", PrimitiveTypeCode.SByte => "System.SByte",
        PrimitiveTypeCode.Byte => "System.Byte", PrimitiveTypeCode.Int16 => "System.Int16",
        PrimitiveTypeCode.UInt16 => "System.UInt16", PrimitiveTypeCode.Int32 => "System.Int32",
        PrimitiveTypeCode.UInt32 => "System.UInt32", PrimitiveTypeCode.Int64 => "System.Int64",
        PrimitiveTypeCode.UInt64 => "System.UInt64", PrimitiveTypeCode.Single => "System.Single",
        PrimitiveTypeCode.Double => "System.Double", PrimitiveTypeCode.String => "System.String",
        PrimitiveTypeCode.IntPtr => "System.IntPtr", PrimitiveTypeCode.UIntPtr => "System.UIntPtr",
        PrimitiveTypeCode.Object => "System.Object", PrimitiveTypeCode.TypedReference => "System.TypedReference",
        _ => throw new AnalysisException("META.PRIMITIVE", "Unsupported primitive signature type.")
    };
}
