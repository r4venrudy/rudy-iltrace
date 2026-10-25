namespace Rudy.ILTrace;

public static class CapabilityRules
{
    public static (string Rule, string Severity, string Category, string Message)? Classify(string type, string method)
    {
        if (type == "System.Diagnostics.Process" && method == "Start")
            return ("IL.PROCESS_START", "warning", "process", "Metadata names a process-launch API.");
        if (type == "System.Reflection.Assembly" &&
            method.StartsWith("Load", StringComparison.Ordinal))
            return ("IL.DYNAMIC_LOAD", "warning", "dynamic-load", "Metadata names a dynamic assembly-load API.");
        if (type == "System.Runtime.InteropServices.NativeLibrary" && method is "Load" or "TryLoad")
            return ("IL.NATIVE_LOAD", "warning", "native", "Metadata names a dynamic native-library loader.");
        if ((type == "System.Net.Http.HttpClient" && method is "Send" or "SendAsync" or "GetAsync" or "GetStringAsync" or
                "GetByteArrayAsync" or "GetStreamAsync" or "PostAsync" or "PutAsync" or "DeleteAsync") ||
            (type == "System.Net.Sockets.Socket" && method is "Connect" or "ConnectAsync" or "Send" or "SendAsync" or "SendTo") ||
            (type == "System.Net.WebClient" && (method.StartsWith("Download", StringComparison.Ordinal) || method.StartsWith("Upload", StringComparison.Ordinal))))
            return ("IL.NETWORK", "note", "network", "Metadata names a network client API; destination and runtime reachability are unknown.");
        if ((type is "System.Reflection.MethodBase" or "System.Reflection.MethodInfo" or "System.Reflection.ConstructorInfo") && method == "Invoke")
            return ("IL.REFLECTION_INVOKE", "note", "reflection", "Reflection invocation has a runtime-selected target.");
        if (type.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal))
            return ("IL.DYNAMIC_CODE", "warning", "dynamic-code", "Metadata names a runtime code-emission API.");
        if (type is "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter" or "System.Runtime.Serialization.NetDataContractSerializer" &&
            method == "Deserialize")
            return ("IL.FORMATTER_DESERIALIZE", "warning", "deserialization", "Formatter deserialization deserves input-trust review; this model performs no taint analysis.");
        if (type == "System.IO.File" && method is "WriteAllText" or "WriteAllTextAsync" or "WriteAllBytes" or "WriteAllBytesAsync" or "AppendAllText" or "AppendAllTextAsync")
            return ("IL.FILE_WRITE", "note", "file-write", "Metadata names a file-write API.");
        return null;
    }
}
