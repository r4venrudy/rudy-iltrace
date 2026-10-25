namespace Example;
public class Api
{
    public string Shared(int value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public int Removed(int value) => value + 1;
    public readonly int Field = 42;
}
