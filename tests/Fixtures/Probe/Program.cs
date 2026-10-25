using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Probe;

// Compiled test data. Tests inspect its bytes and never invoke these methods.
public static class Program
{
    public static void Main(string[] args) => Stage(args.Length);
    public static void Stage(int mode)
    {
        _ = Echo(mode);
        if (mode == 1729)
        {
            Launch("rudy-synthetic-command");
            _ = NativeProbe(mode);
        }
    }
    private static void Launch(string command) => _ = Process.Start(command);
    public static T Echo<T>(T value) => value;
    [DllImport("rudy-synthetic-native", EntryPoint = "probe")]
    public static extern int NativeProbe(int value);
    public static Task<string> Network(HttpClient client) => client.GetStringAsync("https://example.invalid");
    public static Assembly Load(byte[] bytes) => Assembly.Load(bytes);
    public static object? Invoke(MethodInfo method) => method.Invoke(null, null);
    public static int CycleA(int n) => n > 0 ? CycleB(n - 1) : 0;
    private static int CycleB(int n) => n > 0 ? CycleA(n - 1) : 0;
    public static Action<string> ReferenceOnly() => OnlyReferenced;
    private static void OnlyReferenced(string value) => _ = Process.Start(value);
    public static unsafe int Indirect(delegate* unmanaged<int> function) => function();
    public static int Switch(int value) => value switch
    {
        0 => 11, 1 => 22, 2 => 33, 3 => 44, 4 => 55, 5 => 66, _ => 77
    };
    public static int WithHandler(int value)
    {
        try { return 100 / value; }
        catch (DivideByZeroException) { return -1; }
    }
    public static void Dispatch(Base instance) => instance.Execute();
}
public class Base { public virtual void Execute() { } }
public sealed class Derived : Base { public override void Execute() => _ = Process.Start("synthetic"); }
