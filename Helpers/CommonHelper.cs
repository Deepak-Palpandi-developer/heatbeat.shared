namespace HeatBeat.Shared.Helpers;

public static class CommonHelper
{
    public static string ToSnake(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return name ?? string.Empty;
        }

        return string.Concat(name.Select((c, i) =>
            i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
    }
}
