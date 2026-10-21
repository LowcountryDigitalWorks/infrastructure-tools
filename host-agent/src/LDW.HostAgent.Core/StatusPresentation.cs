namespace LDW.HostAgent.Core;

/// <summary>Owner-facing words and symbols for the existing, authoritative status colors.</summary>
public static class StatusPresentation
{
    public static T? SampleForDisplay<T>(T? sample, bool observationSucceeded) => observationSucceeded ? sample : default;

    public static (string Word, string Glyph) For(StatusColor color) => color switch
    {
        StatusColor.Green => ("Healthy", "✓"),
        StatusColor.Blue => ("Active", "▶"),
        StatusColor.Purple => ("Boost enabled", "⚡"),
        StatusColor.Yellow => ("Attention", "!"),
        StatusColor.Red => ("Failed", "×"),
        _ => ("Unknown", "?"),
    };
}
