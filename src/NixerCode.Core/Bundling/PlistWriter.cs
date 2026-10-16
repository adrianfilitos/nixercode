using System.Globalization;
using System.Text;

namespace NixerCode.Core.Bundling;

/// <summary>
/// Escribe archivos plist en formato XML, el que entienden iOS y macOS.
/// Soporta textos, numeros, booleanos, listas y diccionarios anidados.
/// </summary>
public static class PlistWriter
{
    public static string ToXml(IReadOnlyDictionary<string, object?> values)
    {
        var builder = new StringBuilder();
        builder.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>").Append('\n');
        builder.Append("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ")
               .Append("\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">").Append('\n');
        builder.Append("<plist version=\"1.0\">").Append('\n');
        WriteDictionary(builder, values, 0);
        builder.Append("</plist>").Append('\n');
        return builder.ToString();
    }

    private static void WriteDictionary(StringBuilder builder, IReadOnlyDictionary<string, object?> values, int depth)
    {
        string pad = Indent(depth);
        builder.Append(pad).Append("<dict>").Append('\n');

        foreach ((string key, object? value) in values)
        {
            builder.Append(pad).Append("  <key>").Append(Escape(key)).Append("</key>").Append('\n');
            WriteValue(builder, value, depth + 1);
        }

        builder.Append(pad).Append("</dict>").Append('\n');
    }

    private static void WriteValue(StringBuilder builder, object? value, int depth)
    {
        string pad = Indent(depth);

        switch (value)
        {
            case null:
                builder.Append(pad).Append("<string></string>").Append('\n');
                break;
            case bool flag:
                builder.Append(pad).Append(flag ? "<true/>" : "<false/>").Append('\n');
                break;
            case int number:
                builder.Append(pad).Append("<integer>")
                       .Append(number.ToString(CultureInfo.InvariantCulture))
                       .Append("</integer>").Append('\n');
                break;
            case long number:
                builder.Append(pad).Append("<integer>")
                       .Append(number.ToString(CultureInfo.InvariantCulture))
                       .Append("</integer>").Append('\n');
                break;
            case string text:
                builder.Append(pad).Append("<string>").Append(Escape(text)).Append("</string>").Append('\n');
                break;
            case IReadOnlyDictionary<string, object?> dictionary:
                WriteDictionary(builder, dictionary, depth);
                break;
            case System.Collections.IEnumerable list:
                builder.Append(pad).Append("<array>").Append('\n');
                foreach (object? item in list)
                {
                    WriteValue(builder, item, depth + 1);
                }

                builder.Append(pad).Append("</array>").Append('\n');
                break;
            default:
                builder.Append(pad).Append("<string>").Append(Escape(value.ToString() ?? string.Empty))
                       .Append("</string>").Append('\n');
                break;
        }
    }

    private static string Indent(int depth) => new string(' ', depth * 2);

    private static string Escape(string value) => value
        .Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal);
}
