# Capability catalogue

These observations identify review boundaries in metadata. They are not vulnerability or malware verdicts. All rules can be observed by scan; trace additionally requires a declared local-call path from the selected roots.

| Rule | Level | Category | Metadata condition |
| --- | --- | --- | --- |
| IL.PROCESS_START | warning | process | System.Diagnostics.Process.Start |
| IL.NATIVE_IMPORT | warning | native | MethodDef with a P/Invoke import module and entry point |
| IL.NATIVE_LOAD | warning | native | NativeLibrary.Load or TryLoad |
| IL.DYNAMIC_LOAD | warning | dynamic-load | Assembly methods beginning with Load |
| IL.DYNAMIC_CODE | warning | dynamic-code | API calls whose owner is under System.Reflection.Emit |
| IL.FORMATTER_DESERIALIZE | warning | deserialization | BinaryFormatter or NetDataContractSerializer.Deserialize |
| IL.NETWORK | note | network | Selected HttpClient request methods, Socket connect/send methods, WebClient upload/download methods |
| IL.FILE_WRITE | note | file-write | Selected File write/append methods |
| IL.REFLECTION_INVOKE | note | reflection | MethodBase, MethodInfo or ConstructorInfo.Invoke |
| IL.INDIRECT_CALL | note | indirect | calli instruction with a standalone method signature |
| IL.UNRESOLVED_CALL | note | coverage | An invocation member cannot be matched to a local method or assembly scope |

External API rules match the declared owner and method name. They do not authenticate assembly references or account for renamed/obfuscated wrappers. Native imports remain observations even when the target module is absent on the current OS.

IL.UNRESOLVED_CALL is included in scan coverage and scan gates. It is excluded from trace capability paths and release capability comparisons. Indirect calls are included as an unresolved behavior boundary, not resolved to a guessed callee.
