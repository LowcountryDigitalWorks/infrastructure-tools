using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class CiJitLocalProjectionReader
{
    internal static string ProjectionPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LDW",
        "CiJitStatus",
        "status.json");

    public CiJitStatusSnapshot Read()
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            if (!File.Exists(ProjectionPath))
                return CiJitLocalProjection.Unavailable(now);

            var json = File.ReadAllText(ProjectionPath);
            var boot = now - TimeSpan.FromMilliseconds(Environment.TickCount64);
            return CiJitLocalProjection.Parse(json, now, boot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return CiJitLocalProjection.Unavailable(now, "SOURCE_UNAVAILABLE");
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or ArgumentException or OverflowException)
        {
            return CiJitLocalProjection.Unavailable(now, "MALFORMED_STATE");
        }
    }
}
