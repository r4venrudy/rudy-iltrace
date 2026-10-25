namespace Example;
public class Api
{
    public string Shared(int value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public void Added(string command) => _ = System.Diagnostics.Process.Start(command);
    public readonly int Field = 42;
}
