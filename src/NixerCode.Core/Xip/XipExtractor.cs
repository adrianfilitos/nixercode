using System.Diagnostics;

namespace NixerCode.Core.Xip;

/// <summary>Peticion de extraccion de un contenedor .xip.</summary>
public sealed record ExtractionRequest
{
    /// <summary>Carpeta donde se reconstruye el arbol.</summary>
    public required string Destination { get; init; }

    /// <summary>Si se indica, solo se extraen las rutas que contengan alguno de estos textos.</summary>
    public IReadOnlyList<string> Filters { get; init; } = [];

    /// <summary>Prefijo que se recorta de cada ruta antes de escribirla.</summary>
    public string? StripPrefix { get; init; }
}

/// <summary>Resumen de una extraccion.</summary>
public sealed record ExtractionReport
{
    public long EntriesWalked { get; init; }
    public long DirectoriesCreated { get; init; }
    public long FilesWritten { get; init; }
    public long SymlinksCreated { get; init; }
    public long BytesWritten { get; init; }

    /// <summary>Archivos que venian como marcador de deduplicacion.</summary>
    public long DeduplicatedFiles { get; init; }

    /// <summary>Marcadores que se pudieron reconstruir desde su copia real.</summary>
    public long DeduplicatedResolved { get; init; }

    /// <summary>Marcadores que no se pudieron reconstruir.</summary>
    public long DeduplicatedUnresolved { get; init; }

    public IReadOnlyList<string> PendingSymlinks { get; init; } = [];
    public IReadOnlyList<string> UnresolvedFiles { get; init; } = [];
    public TimeSpan Elapsed { get; init; }
}

/// <summary>
/// Extrae contenido de un contenedor .xip.
///
/// Los .xip de Apple guardan los archivos compartidos entre plataformas como enlaces
/// duros: el contenido real aparece UNA sola vez y las demas copias se rellenan con el
/// marcador "NULLcanary" seguido de ceros. Este extractor reconstruye esas copias
/// usando el numero de inodo, sin importar en que orden aparezcan.
/// </summary>
public static class XipExtractor
{
    /// <summary>Firma que Apple escribe en las copias deduplicadas.</summary>
    public const string PlaceholderMarker = "NULLcanary";

    private static readonly byte[] MarkerBytes = "NULLcanary"u8.ToArray();

    public static ExtractionReport Extract(
        string xipPath,
        ExtractionRequest request,
        Action<string>? progress = null)
    {
        var stopwatch = Stopwatch.StartNew();

        string destination = Path.GetFullPath(request.Destination);
        Directory.CreateDirectory(destination);

        string cacheDirectory = Path.Combine(destination, ".nixer-hardlinks");
        bool cacheUsed = false;

        using var archive = XarArchive.Open(xipPath);
        XarEntry content = archive.Find("Content")
            ?? throw new InvalidDataException("El contenedor no tiene una entrada 'Content'.");

        using Stream raw = archive.OpenEntryData(content);
        using var pbzx = PbzxStream.Over(raw);
        var cpio = new CpioReader(pbzx);

        long walked = 0;
        long directories = 0;
        long files = 0;
        long symlinks = 0;
        long bytes = 0;
        long deduplicated = 0;
        long resolved = 0;
        long unresolved = 0;
        long lastReport = 0;

        var pendingSymlinks = new List<string>();
        var unresolvedFiles = new List<string>();

        // Los numeros de inodo se repiten entre grupos distintos, asi que la identidad
        // de un grupo es (dispositivo, inodo, tamano): los miembros de un mismo grupo
        // de enlaces duros comparten los tres valores.
        var sourceByKey = new Dictionary<(long Dev, long Ino, long Size), string>();
        var pendingResolution = new List<(long Dev, long Ino, long Size, string Target)>();
        byte[] head = new byte[MarkerBytes.Length];

        CpioEntry? entry;
        while ((entry = cpio.MoveNext()) is not null)
        {
            walked++;

            if (stopwatch.ElapsedMilliseconds - lastReport >= 10000)
            {
                lastReport = stopwatch.ElapsedMilliseconds;
                progress?.Invoke(
                    $"{walked,9:N0} entradas | {files,7:N0} archivos | {ByteSize.Format(bytes),10} | {stopwatch.Elapsed.TotalSeconds,6:F0}s");
            }

            string relative = Strip(entry.Name, request.StripPrefix);
            bool wanted = IsWanted(entry.Name, request.Filters);
            bool dedupCandidate = entry.NLink > 1;

            if (entry.IsDirectory)
            {
                if (wanted && relative.Length > 0)
                {
                    Directory.CreateDirectory(ToLocal(destination, relative));
                    directories++;
                }

                continue;
            }

            if (!wanted && !dedupCandidate)
            {
                continue;
            }

            if (relative.Length == 0)
            {
                continue;
            }

            string targetPath = wanted
                ? ToLocal(destination, relative)
                : Path.Combine(cacheDirectory, entry.Ino.ToString());

            if (entry.IsSymlink)
            {
                if (!wanted)
                {
                    cpio.CopyCurrentData(Stream.Null);
                    continue;
                }

                symlinks++;
                string linkTarget = System.Text.Encoding.UTF8.GetString(cpio.ReadCurrentData());
                try
                {
                    string? parent = Path.GetDirectoryName(targetPath);
                    if (parent is not null)
                    {
                        Directory.CreateDirectory(parent);
                    }

                    if (File.Exists(targetPath))
                    {
                        File.Delete(targetPath);
                    }
                    else if (Directory.Exists(targetPath))
                    {
                        // Las carpetas vacias son marcadores de posicion que sustituimos
                        // por el enlace; si tienen contenido, no tocamos nada.
                        if (Directory.EnumerateFileSystemEntries(targetPath).Any())
                        {
                            throw new IOException("ya existe una carpeta con contenido");
                        }

                        Directory.Delete(targetPath);
                    }

                    string normalized = linkTarget.Replace('/', Path.DirectorySeparatorChar);
                    string resolvedTarget = Path.GetFullPath(Path.Combine(parent ?? destination, normalized));
                    bool targetIsDirectory = Directory.Exists(resolvedTarget)
                        || (!File.Exists(resolvedTarget) && !LooksLikeFileTarget(normalized));

                    if (targetIsDirectory)
                    {
                        Directory.CreateSymbolicLink(targetPath, normalized);
                    }
                    else
                    {
                        File.CreateSymbolicLink(targetPath, normalized);
                    }
                }
                catch (Exception)
                {
                    pendingSymlinks.Add($"{relative} -> {linkTarget}");
                }

                continue;
            }

            int headRead = cpio.ReadCurrent(head, 0, head.Length);
            bool isPlaceholder = headRead == MarkerBytes.Length
                && head.AsSpan().SequenceEqual(MarkerBytes);

            if (isPlaceholder)
            {
                deduplicated++;
            }

            bool storeForDedup = !wanted
                && dedupCandidate
                && !isPlaceholder
                && !sourceByKey.ContainsKey((entry.Dev, entry.Ino, entry.Size));

            if (wanted || storeForDedup)
            {
                string? parent = Path.GetDirectoryName(targetPath);
                if (parent is not null)
                {
                    Directory.CreateDirectory(parent);
                }

                if (!wanted)
                {
                    cacheUsed = true;
                }

                using (var output = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
                {
                    if (headRead > 0)
                    {
                        output.Write(head, 0, headRead);
                    }

                    bytes += headRead + cpio.CopyCurrentData(output);
                }

                if (wanted)
                {
                    files++;
                }
            }
            else
            {
                cpio.CopyCurrentData(Stream.Null);
            }

            if (isPlaceholder)
            {
                if (wanted)
                {
                    pendingResolution.Add((entry.Dev, entry.Ino, entry.Size, targetPath));
                }
            }
            else if (dedupCandidate && !sourceByKey.ContainsKey((entry.Dev, entry.Ino, entry.Size)))
            {
                sourceByKey[(entry.Dev, entry.Ino, entry.Size)] = targetPath;
            }
        }

        foreach ((long dev, long inode, long size, string target) in pendingResolution)
        {
            bool found = sourceByKey.TryGetValue((dev, inode, size), out string? source)
                && source is not null
                && File.Exists(source)
                && new FileInfo(source).Length == size;

            if (found && source is not null)
            {
                File.Delete(target);
                File.Copy(source, target, overwrite: true);
                resolved++;
            }
            else
            {
                unresolved++;
                if (unresolvedFiles.Count < 50)
                {
                    unresolvedFiles.Add(target);
                }
            }
        }

        if (cacheUsed)
        {
            try
            {
                Directory.Delete(cacheDirectory, recursive: true);
            }
            catch
            {
                // Si no se puede limpiar, no es grave: el contenido extraido ya es correcto.
            }
        }

        stopwatch.Stop();

        return new ExtractionReport
        {
            EntriesWalked = walked,
            DirectoriesCreated = directories,
            FilesWritten = files,
            SymlinksCreated = symlinks,
            BytesWritten = bytes,
            DeduplicatedFiles = deduplicated,
            DeduplicatedResolved = resolved,
            DeduplicatedUnresolved = unresolved,
            PendingSymlinks = pendingSymlinks,
            UnresolvedFiles = unresolvedFiles,
            Elapsed = stopwatch.Elapsed,
        };
    }

    private static bool IsWanted(string name, IReadOnlyList<string> filters)
    {
        if (filters.Count == 0)
        {
            return true;
        }

        foreach (string filter in filters)
        {
            if (name.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Strip(string name, string? stripPrefix)
    {
        string relative = name.StartsWith("./", StringComparison.Ordinal) ? name[2..] : name;
        if (stripPrefix is not null && relative.StartsWith(stripPrefix, StringComparison.OrdinalIgnoreCase))
        {
            relative = relative[stripPrefix.Length..].TrimStart('/');
        }

        return relative;
    }

    private static string ToLocal(string destination, string relative) =>
        Path.Combine(destination, relative.Replace('/', Path.DirectorySeparatorChar));

    private static bool LooksLikeFileTarget(string target)
    {
        string extension = Path.GetExtension(target).ToLowerInvariant();
        return extension is ".tbd" or ".dylib" or ".a" or ".h" or ".hpp" or ".plist" or ".swiftmodule" or ".diff";
    }
}
