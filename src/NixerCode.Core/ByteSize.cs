using System.Globalization;

namespace NixerCode.Core;

/// <summary>Formatea tamanos de bytes de forma legible para humanos.</summary>
public static class ByteSize
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB"];

    public static string Format(long bytes)
    {
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < Units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? string.Format(CultureInfo.InvariantCulture, "{0} {1}", bytes, Units[0])
            : string.Format(CultureInfo.InvariantCulture, "{0:N2} {1}", value, Units[unit]);
    }
}
