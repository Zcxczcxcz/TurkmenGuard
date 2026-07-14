namespace TurkmenGuard.ViewModels;

public class ComboOption(string value, string label)
{
    public string Value { get; } = value;
    public string Label { get; } = label;
}
