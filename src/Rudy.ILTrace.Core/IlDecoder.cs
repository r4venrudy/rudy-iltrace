using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;

namespace Rudy.ILTrace;

public sealed record Instruction(int Offset, int Size, string OpCode, int? MetadataToken,
    IReadOnlyList<int> BranchTargets, bool IsCall, bool IsFunctionReference, bool IsIndirect, bool IsVirtual);

public static class IlDecoder
{
    private static readonly IReadOnlyDictionary<ushort, OpCode> Codes =
        typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(OpCode))
            .Select(f => (OpCode)f.GetValue(null)!)
            .Where(c => c.OpCodeType != OpCodeType.Nternal && c.Name is not null)
            .ToDictionary(c => unchecked((ushort)c.Value));

    public static IReadOnlyList<Instruction> Decode(ReadOnlySpan<byte> il, int maxInstructions = 2_000_000)
    {
        var result = new List<Instruction>();
        int p = 0;
        while (p < il.Length)
        {
            if (result.Count >= maxInstructions) throw new AnalysisException("LIMIT.INSTRUCTIONS", "Instruction budget exceeded.");
            int start = p;
            ushort raw = il[p++];
            if (raw == 0xfe)
            {
                Require(il, p, 1);
                raw = (ushort)(0xfe00 | il[p++]);
            }
            if (!Codes.TryGetValue(raw, out var code))
                throw new AnalysisException("IL.OPCODE", $"Unknown or reserved opcode at IL_{start:x4}.");
            int? token = null;
            var branches = new List<int>();
            int length = code.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI or OperandType.InlineBrTarget or OperandType.ShortInlineR or
                OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineSig or
                OperandType.InlineString or OperandType.InlineTok or OperandType.InlineType => 4,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => -1,
                _ => throw new AnalysisException("IL.OPERAND", "Unsupported operand encoding.")
            };
            if (length < 0)
            {
                Require(il, p, 4);
                int count = BinaryPrimitives.ReadInt32LittleEndian(il[p..]);
                p += 4;
                if (count < 0 || count > 65_536 || (long)count * 4 > il.Length - p)
                    throw new AnalysisException("IL.SWITCH", "Switch table exceeds its body or safety ceiling.");
                int next = checked(p + count * 4);
                for (int i = 0; i < count; i++)
                {
                    long target = (long)next + BinaryPrimitives.ReadInt32LittleEndian(il[(p + i * 4)..]);
                    branches.Add(Target(target, il.Length));
                }
                p = next;
            }
            else
            {
                Require(il, p, length);
                if (code.OperandType is OperandType.InlineMethod or OperandType.InlineSig)
                    token = BinaryPrimitives.ReadInt32LittleEndian(il[p..]);
                if (code.OperandType == OperandType.InlineBrTarget)
                    branches.Add(Target((long)p + 4 + BinaryPrimitives.ReadInt32LittleEndian(il[p..]), il.Length));
                else if (code.OperandType == OperandType.ShortInlineBrTarget)
                    branches.Add(Target((long)p + 1 + unchecked((sbyte)il[p]), il.Length));
                p += length;
            }
            string name = code.Name!;
            result.Add(new(start, p - start, name, token, branches,
                name is "call" or "callvirt" or "newobj" or "jmp",
                name is "ldftn" or "ldvirtftn", name == "calli", name is "callvirt" or "ldvirtftn"));
        }
        var boundaries = result.Select(i => i.Offset).ToHashSet();
        foreach (var instruction in result)
            foreach (int target in instruction.BranchTargets)
                if (!boundaries.Contains(target))
                    throw new AnalysisException("IL.BRANCH", $"Branch at IL_{instruction.Offset:x4} targets an operand.");
        return result;
    }

    private static int Target(long target, int length)
    {
        if (target < 0 || target >= length) throw new AnalysisException("IL.BRANCH", "Branch target is outside the method body.");
        return (int)target;
    }

    private static void Require(ReadOnlySpan<byte> bytes, int p, int count)
    {
        if (p < 0 || count < 0 || count > bytes.Length - p)
            throw new AnalysisException("IL.TRUNCATED", "An IL operand extends beyond the method body.");
    }
}
