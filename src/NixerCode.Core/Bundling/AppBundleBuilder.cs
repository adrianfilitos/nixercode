using System.Text;

namespace NixerCode.Core.Bundling;

/// <summary>Datos para construir un paquete .app de iOS.</summary>
public sealed record AppBundleRequest
{
    /// <summary>Ruta de salida del paquete (se le anade .app si falta).</summary>
    public required string Destination { get; init; }

    /// <summary>Ejecutable Mach-O ya compilado y enlazado.</summary>
    public required string ExecutablePath { get; init; }

    /// <summary>Identificador inverso, por ejemplo com.ejemplo.hola.</summary>
    public required string BundleIdentifier { get; init; }

    /// <summary>Nombre visible de la app. Por defecto, el del ejecutable.</summary>
    public string? DisplayName { get; init; }

    public string Version { get; init; } = "1.0";
    public string Build { get; init; } = "1";
    public string MinimumOSVersion { get; init; } = "17.0";

    /// <summary>Nombre del SDK usado, por ejemplo iphoneos27.1.</summary>
    public string SdkName { get; init; } = "iphoneos";
}

/// <summary>Resultado de construir un paquete.</summary>
public sealed record AppBundleReport
{
    public required string Path { get; init; }
    public required string ExecutableName { get; init; }
    public required long ExecutableSize { get; init; }
    public required IReadOnlyList<string> Files { get; init; }
}

/// <summary>
/// Construye la estructura de un paquete .app de iOS:
/// el ejecutable, Info.plist y PkgInfo.
/// </summary>
public static class AppBundleBuilder
{
    public static AppBundleReport Build(AppBundleRequest request)
    {
        string hash = Path.GetFullPath(request.Destination);
        if (!hash.EndsWith(".app", StringComparison.OrdinalIgnoreCase))
        {
            hash += ".app";
        }

        if (!File.Exists(request.ExecutablePath))
        {
            throw new FileNotFoundException($"No existe el ejecutable '{request.ExecutablePath}'.", request.ExecutablePath);
        }

        if (Directory.Exists(hash))
        {
            Directory.Delete(hash, recursive: true);
        }

        Directory.CreateDirectory(hash);

        string executableName = Path.GetFileName(request.ExecutablePath);
        string executableTarget = Path.Combine(hash, executableName);
        File.Copy(request.ExecutablePath, executableTarget, overwrite: true);

        var info = new Dictionary<string, object?>
        {
            ["CFBundleDevelopmentRegion"] = "en",
            ["CFBundleDisplayName"] = request.DisplayName ?? Path.GetFileNameWithoutExtension(executableName),
            ["CFBundleExecutable"] = executableName,
            ["CFBundleIdentifier"] = request.BundleIdentifier,
            ["CFBundleInfoDictionaryVersion"] = "6.0",
            ["CFBundleName"] = Path.GetFileNameWithoutExtension(executableName),
            ["CFBundlePackageType"] = "APPL",
            ["CFBundleShortVersionString"] = request.Version,
            ["CFBundleSupportedPlatforms"] = new List<object?> { "iPhoneOS" },
            ["CFBundleVersion"] = request.Build,
            ["DTPlatformName"] = "iphoneos",
            ["DTSDKName"] = request.SdkName,
            ["LSRequiresIPhoneOS"] = true,
            ["MinimumOSVersion"] = request.MinimumOSVersion,
            ["UIDeviceFamily"] = new List<object?> { 1 },
            ["UIRequiredDeviceCapabilities"] = new List<object?> { "arm64" },
            ["UILaunchScreen"] = new Dictionary<string, object?>(),
            ["UISupportedInterfaceOrientations"] = new List<object?>
            {
                "UIInterfaceOrientationPortrait",
            },
        };

        File.WriteAllText(Path.Combine(hash, "Info.plist"), PlistWriter.ToXml(info), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(hash, "PkgInfo"), "APPL????", new UTF8Encoding(false));

        var files = new List<string>(Directory.GetFiles(hash, "*", SearchOption.AllDirectories));

        return new AppBundleReport
        {
            Path = hash,
            ExecutableName = executableName,
            ExecutableSize = new FileInfo(executableTarget).Length,
            Files = files,
        };
    }
}
