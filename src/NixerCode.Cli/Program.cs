using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NixerCode.Core;
using NixerCode.Core.Xip;

const string Usage = """
nixer - herramientas de NixerCode

USO
  nixer xip info   <archivo.xip>              Estructura y firma del contenedor
  nixer xip verify <archivo.xip> [entrada]    Comprueba el SHA1 contra el indice
  nixer xip hex    <archivo.xip> <entrada> [desplazamiento] [bytes]
                                              Bytes crudos (sin descomprimir)
  nixer xip pbzx   <archivo.xip> [bytes]      Abre la capa pbzx y muestra el contenido
  nixer xip cpio   <archivo.xip> [entradas]   Lista el arbol cpio que hay dentro
  nixer xip scan   <archivo.xip> [archivos]   Recorre todo y resume: dirs, archivos, tamanos
  nixer xip find   <archivo.xip> <texto> [n]  Busca entradas por nombre
  nixer xip cat    <archivo.xip> <texto> [n]  Vuelca el contenido crudo de una entrada
  nixer xip pbzx-map <archivo.xip>            Mapa de todas las cabeceras pbzx (rapido)
  nixer xip extract <archivo.xip> <destino> [filtro...]
                                              Extrae a disco las entradas que coincidan
  nixer fs  symlinks <manifiesto> [raiz]      Crea enlaces simbolicos desde un manifiesto
""";

if (args.Length < 1)
{
    Console.WriteLine(Usage);
    return 1;
}

string command = args[0].ToLowerInvariant();
string path = args.Length > 2 ? args[2] : string.Empty;

try
{
    if (command == "fs")
    {
        if (args.Length < 3)
        {
            Console.WriteLine(Usage);
            return 1;
        }

        return args[1].ToLowerInvariant() switch
        {
            "symlinks" => FsSymlinks(args[2], args.Length > 3 ? args[3] : "."),
            _ => Unknown(args[1]),
        };
    }

    if (command != "xip" || args.Length < 3)
    {
        Console.WriteLine(Usage);
        return 1;
    }

    string action = args[1].ToLowerInvariant();

    return action switch
    {
        "info" => XipInfo(path),
        "verify" => XipVerify(path, args.Length > 3 ? args[3] : null),
        "hex" => XipHex(
            path,
            args.Length > 3 ? args[3] : "Content",
            args.Length > 4 ? int.Parse(args[4]) : 0,
            args.Length > 5 ? int.Parse(args[5]) : 128),
        "pbzx" => XipPbzx(path, args.Length > 3 ? int.Parse(args[3]) : 256),
        "cpio" => XipCpio(path, args.Length > 3 ? int.Parse(args[3]) : 40),
        "scan" => XipScan(path, args.Length > 3 ? int.Parse(args[3]) : 200),
        "find" when args.Length > 3 => XipFind(path, args[3], args.Length > 4 ? int.Parse(args[4]) : 20),
        "find" => Unknown("find (falta el texto a buscar)"),
        "cat" when args.Length > 3 => XipCat(path, args[3], args.Length > 4 ? int.Parse(args[4]) : 128),
        "cat" => Unknown("cat (falta el texto a buscar)"),
        "pbzx-map" => XipPbzxMap(path),
        "extract" when args.Length > 3 => XipExtract(path, args[3], args.Skip(4).ToArray()),
        "extract" => Unknown("extract (faltan destino y filtros)"),
        _ => Unknown(action),
    };
}
catch (FileNotFoundException)
{
    Console.Error.WriteLine($"ERROR: no existe el archivo '{path}'.");
    return 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    return 2;
}

static int Unknown(string action)
{
    Console.Error.WriteLine($"ERROR: accion desconocida '{action}'.");
    Console.WriteLine(Usage);
    return 1;
}

static int XipInfo(string path)
{
    var info = new FileInfo(path);
    using var xar = XarArchive.Open(path);

    Console.WriteLine();
    Console.WriteLine($"  Archivo                 : {info.Name}");
    Console.WriteLine($"  Formato                 : XAR v{xar.Version}");
    Console.WriteLine($"  Tamano real             : {ByteSize.Format(info.Length)}  ({info.Length:N0} bytes)");
    Console.WriteLine($"  Tamano segun su indice  : {ByteSize.Format(xar.DeclaredTotalSize)}  ({xar.DeclaredTotalSize:N0} bytes)");

    if (xar.DeclaredTotalSize == info.Length)
    {
        Console.WriteLine("  Integridad estructural  : COMPLETO");
    }
    else
    {
        long diff = xar.DeclaredTotalSize - info.Length;
        Console.WriteLine($"  Integridad estructural  : INCOMPLETO (faltan {ByteSize.Format(diff)})");
    }

    Console.WriteLine($"  Cabecera / indice       : {xar.HeaderSize} + {xar.TocCompressedLength:N0} bytes");
    Console.WriteLine($"  Inicio de datos (heap)  : {xar.HeapStart:N0}");
    Console.WriteLine($"  Creado                  : {xar.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
    Console.WriteLine($"  Firma RSA               : {(xar.IsSigned ? $"presente ({xar.SignatureCertificates.Count} certificados)" : "no")}");

    foreach (string der in xar.SignatureCertificates)
    {
        try
        {
            using X509Certificate2 certificate =
                X509CertificateLoader.LoadCertificate(Convert.FromBase64String(der));
            Console.WriteLine($"      - {certificate.Subject}");
        }
        catch
        {
            // Un certificado ilegible no debe impedir mostrar el resto.
        }
    }

    Console.WriteLine();
    Console.WriteLine($"  {"Entrada",-12} {"Almacenado",12} {"Declarado",12} {"Desplaz.",14}  Codificacion");
    Console.WriteLine($"  {new string('-', 12)} {new string('-', 12)} {new string('-', 12)} {new string('-', 14)}  {new string('-', 26)}");

    foreach (XarEntry entry in xar.Entries)
    {
        Console.WriteLine(
            $"  {entry.Name,-12} {ByteSize.Format(entry.Length),12} {ByteSize.Format(entry.Size),12} {entry.Offset,14:N0}  {entry.Encoding ?? "(nada)"}");
    }

    Console.WriteLine();
    return 0;
}

static int XipVerify(string path, string? entryName)
{
    using var xar = XarArchive.Open(path);

    IReadOnlyList<XarEntry> targets = entryName is null
        ? xar.Entries
        : xar.Entries.Where(e => e.Name.Contains(entryName, StringComparison.OrdinalIgnoreCase)).ToList();

    if (targets.Count == 0)
    {
        Console.Error.WriteLine($"ERROR: ninguna entrada coincide con '{entryName}'.");
        return 3;
    }

    Console.WriteLine();
    int failures = 0;
    foreach (XarEntry entry in targets)
    {
        Console.Write($"  {entry.Name,-12} {ByteSize.Format(entry.Length),12}  calculando SHA1... ");
        Console.Out.Flush();

        var stopwatch = Stopwatch.StartNew();
        bool ok = xar.Verify(entry);
        stopwatch.Stop();

        if (ok)
        {
            Console.WriteLine($"OK  ({stopwatch.Elapsed.TotalSeconds:F1}s)");
        }
        else
        {
            Console.WriteLine("FALLO");
            Console.WriteLine($"      esperado: {entry.ArchivedSha1}");
            Console.WriteLine($"      obtenido: {xar.ComputeSha1(entry)}");
            failures++;
        }
    }

    Console.WriteLine();
    if (failures == 0)
    {
        Console.WriteLine("  Resultado: TODO CORRECTO");
        return 0;
    }

    Console.WriteLine($"  Resultado: {failures} entrada(s) con FALLO");
    return 4;
}

static int XipHex(string path, string entryName, int offset, int count)
{
    if (offset < 0 || count <= 0 || count > 4096)
    {
        Console.Error.WriteLine("ERROR: desplazamiento >= 0 y bytes entre 1 y 4096.");
        return 3;
    }

    using var xar = XarArchive.Open(path);
    XarEntry? entry = xar.Find(entryName);
    if (entry is null)
    {
        Console.Error.WriteLine($"ERROR: la entrada '{entryName}' no existe.");
        return 3;
    }

    using Stream data = xar.OpenEntryData(entry);

    byte[] scratch = new byte[64 * 1024];
    int skip = offset;
    while (skip > 0)
    {
        int got = data.Read(scratch, 0, Math.Min(skip, scratch.Length));
        if (got <= 0)
        {
            break;
        }

        skip -= got;
    }

    byte[] buffer = new byte[count];
    int total = 0;
    while (total < count)
    {
        int got = data.Read(buffer, total, count - total);
        if (got <= 0)
        {
            break;
        }

        total += got;
    }

    Console.WriteLine();
    Console.WriteLine($"  Entrada '{entry.Name}' desde {offset:N0}  ({total} bytes de {entry.Length:N0})");
    PrintHex(buffer, total, offset);
    Console.WriteLine();
    return 0;
}

static int XipPbzx(string path, int peekBytes)
{
    if (peekBytes <= 0 || peekBytes > 4096)
    {
        Console.Error.WriteLine("ERROR: bytes entre 1 y 4096.");
        return 3;
    }

    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    Console.WriteLine();
    Console.WriteLine($"  Contenedor      : {Path.GetFileName(path)}");
    Console.WriteLine($"  Entrada         : Content ({ByteSize.Format(content.Length)} comprimidos)");

    using Stream raw = xar.OpenEntryData(content);
    using var pbzx = PbzxStream.Over(raw);

    Console.WriteLine($"  Version pbzx    : 0x{pbzx.Version:X}  ({pbzx.Version:N0})");

    var buffer = new byte[peekBytes];
    int total = 0;
    while (total < peekBytes)
    {
        int got = pbzx.Read(buffer, total, peekBytes - total);
        if (got <= 0)
        {
            break;
        }

        total += got;
    }

    Console.WriteLine($"  Bloques vistos  : {pbzx.Chunks.Count}");
    foreach (PbzxChunk chunk in pbzx.Chunks)
    {
        Console.WriteLine(
            $"      bloque {chunk.Index,4}: {ByteSize.Format(chunk.UncompressedSize),10} sin comprimir  <-  {ByteSize.Format(chunk.CompressedSize),10} comprimidos  [{((chunk.IsXz) ? "XZ/LZMA2" : "ALMACENADO")}]");
    }

    Console.WriteLine($"  Bytes abiertos  : {total:N0} (solo una muestra)");
    Console.WriteLine();
    Console.WriteLine("  Primeros bytes YA DESCOMPRIMIDOS:");
    PrintHex(buffer, total, 0);
    Console.WriteLine();
    return 0;
}

static void PrintHex(byte[] buffer, int total, long baseOffset)
{
    for (int line = 0; line < total; line += 16)
    {
        var hex = new StringBuilder();
        var ascii = new StringBuilder();
        for (int i = 0; i < 16; i++)
        {
            if (line + i < total)
            {
                byte b = buffer[line + i];
                hex.Append(b.ToString("x2"));
                hex.Append(i == 7 ? "  " : " ");
                ascii.Append(b >= 32 && b < 127 ? (char)b : '.');
            }
            else
            {
                hex.Append("   ");
                hex.Append(i == 7 ? " " : "");
            }
        }

        Console.WriteLine($"  {baseOffset + line:x8}  {hex} |{ascii}|");
    }
}

static int XipCpio(string path, int maxEntries)
{
    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    using Stream raw = xar.OpenEntryData(content);
    using var pbzx = PbzxStream.Over(raw);
    var cpio = new CpioReader(pbzx);

    Console.WriteLine();
    Console.WriteLine($"  {"#",5}  {"Permisos",10}  {"Tamano",12}  Nombre");
    Console.WriteLine($"  {new string('-', 5)}  {new string('-', 10)}  {new string('-', 12)}  {new string('-', 40)}");

    int shown = 0;
    CpioEntry? entry;
    while (shown < maxEntries && (entry = cpio.MoveNext()) is not null)
    {
        shown++;
        string size = entry.IsDirectory ? "<dir>" : ByteSize.Format(entry.Size);
        Console.WriteLine($"  {shown,5}  {entry.ModeText,10}  {size,12}  {entry.Name}");
    }

    Console.WriteLine();
    Console.WriteLine($"  Entradas mostradas: {shown}");
    return 0;
}

static int XipScan(string path, int maxFiles)
{
    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    using Stream raw = xar.OpenEntryData(content);
    using var pbzx = PbzxStream.Over(raw);
    var cpio = new CpioReader(pbzx);

    long directories = 0;
    long symlinks = 0;
    long dataBytes = 0;
    var files = new List<CpioEntry>();
    var stopwatch = Stopwatch.StartNew();

    Console.WriteLine();
    Console.WriteLine("  Recorriendo el archivo entero (esto descomprime todo)...");

    CpioEntry? entry;
    while (files.Count < maxFiles && (entry = cpio.MoveNext()) is not null)
    {
        if (entry.IsDirectory)
        {
            directories++;
        }
        else if (entry.IsSymlink)
        {
            symlinks++;
        }
        else
        {
            files.Add(entry);
            dataBytes += entry.Size;
        }
    }

    stopwatch.Stop();

    Console.WriteLine();
    Console.WriteLine($"  Directorios encontrados : {directories:N0}");
    Console.WriteLine($"  Enlaces simbolicos      : {symlinks:N0}");
    Console.WriteLine($"  Archivos con datos      : {files.Count:N0}");
    Console.WriteLine($"  Bytes de datos sumados  : {ByteSize.Format(dataBytes)}");
    Console.WriteLine($"  Bloques pbzx leidos     : {pbzx.Chunks.Count:N0}");
    Console.WriteLine($"  Comprimido consumido    : {ByteSize.Format(pbzx.Chunks.Sum(c => c.CompressedSize))}");
    Console.WriteLine($"  Tiempo                  : {stopwatch.Elapsed.TotalSeconds:F1}s");

    var primeros = files.Take(15).ToList();
    Console.WriteLine();
    Console.WriteLine("  Primeros archivos con datos:");
    foreach (CpioEntry file in primeros)
    {
        Console.WriteLine($"    {file.ModeText} {ByteSize.Format(file.Size),12}  {file.Name}");
    }

    Console.WriteLine();
    Console.WriteLine("  Los 10 mas grandes vistos:");
    foreach (CpioEntry file in files.OrderByDescending(f => f.Size).Take(10))
    {
        Console.WriteLine($"    {ByteSize.Format(file.Size),12}  {file.Name}");
    }

    Console.WriteLine();
    return 0;
}

static int XipFind(string path, string fragment, int maxResults)
{
    if (string.IsNullOrWhiteSpace(fragment))
    {
        Console.Error.WriteLine("ERROR: hace falta un texto a buscar.");
        return 3;
    }

    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    using Stream raw = xar.OpenEntryData(content);
    using var pbzx = PbzxStream.Over(raw);
    var cpio = new CpioReader(pbzx);

    Console.WriteLine();
    Console.WriteLine($"  Buscando \"{fragment}\"...");
    Console.WriteLine();

    var stopwatch = Stopwatch.StartNew();
    long walked = 0;
    int found = 0;
    long foundBytes = 0;

    CpioEntry? entry;
    while ((entry = cpio.MoveNext()) is not null)
    {
        walked++;
        if (!entry.Name.Contains(fragment, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        found++;
        if (!entry.IsDirectory && !entry.IsSymlink)
        {
            foundBytes += entry.Size;
        }

        string size = entry.IsDirectory ? "<dir>" : ByteSize.Format(entry.Size);
        Console.WriteLine($"  {entry.ModeText} {size,12}  ino={entry.Ino,-8} nlink={entry.NLink,-4}  {entry.Name}");

        if (found >= maxResults)
        {
            break;
        }
    }

    stopwatch.Stop();
    Console.WriteLine();
    Console.WriteLine($"  Entradas recorridas : {walked:N0}");
    Console.WriteLine($"  Coincidencias       : {found:N0}");
    Console.WriteLine($"  Datos encontrados   : {ByteSize.Format(foundBytes)}");
    Console.WriteLine($"  Tiempo              : {stopwatch.Elapsed.TotalSeconds:F1}s");
    return 0;
}

static int XipPbzxMap(string path)
{
    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    Stream stream = xar.BaseStream;
    xar.SeekToData(content);
    long start = stream.Position;
    long end = start + content.Length;

    byte[] prologue = new byte[12];
    if (ReadFull(stream, prologue) < 12)
    {
        Console.Error.WriteLine("ERROR: prologo pbzx truncado.");
        return 3;
    }

    string magic = System.Text.Encoding.ASCII.GetString(prologue, 0, 4);
    long version = ReadBigEndian64(prologue, 4);

    Console.WriteLine();
    Console.WriteLine($"  Firma           : {magic}");
    Console.WriteLine($"  Version/campo   : 0x{version:X} ({version:N0})");
    Console.WriteLine($"  Datos desde     : {start:N0} hasta {end:N0}  ({ByteSize.Format(content.Length)})");
    Console.WriteLine();

    long position = start + 12;
    int index = 0;
    long sumCompressed = 0;
    long sumDeclared = 0;
    int xzOk = 0;
    int xzBad = 0;
    var rows = new List<string>();
    var badRows = new List<string>();

    while (position + 16 <= end)
    {
        stream.Position = position;

        byte[] header = new byte[16];
        if (ReadFull(stream, header) < 16)
        {
            break;
        }

        long field1 = ReadBigEndian64(header, 0);
        long field2 = ReadBigEndian64(header, 8);

        if (field1 == 0 && field2 == 0)
        {
            break;
        }

        index++;
        sumCompressed += field2;
        sumDeclared += field1;

        byte[] peek = new byte[6];
        int got = ReadFull(stream, peek);
        bool isXz = got == 6
            && peek[0] == 0xFD && peek[1] == 0x37 && peek[2] == 0x7A
            && peek[3] == 0x58 && peek[4] == 0x5A && peek[5] == 0x00;

        if (isXz)
        {
            xzOk++;
        }
        else
        {
            xzBad++;
            if (badRows.Count < 8)
            {
                byte[] sample = new byte[24];
                stream.Position = position + 16;
                int sampleRead = ReadFull(stream, sample);
                string sampleHex = string.Join(' ', sample.Take(sampleRead).Select(b => b.ToString("x2")));
                string sampleAscii = new string(sample.Take(sampleRead).Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                badRows.Add($"  pos={position,14:N0}  c1={field1,12:N0}  c2={field2,12:N0}  {sampleHex}  |{sampleAscii}|");
            }
        }

        if (rows.Count < 30)
        {
            rows.Add($"  #{index,5}  campo1={field1,14:N0}  campo2={field2,14:N0}  XZ={(isXz ? "si" : "NO")}  pos={position:N0}");
        }

        if (field2 <= 0)
        {
            break;
        }

        position += 16 + field2;
    }

    foreach (string row in rows)
    {
        Console.WriteLine(row);
    }

    if (badRows.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  Cabeceras SIN firma XZ (primeras 8):");
        foreach (string row in badRows)
        {
            Console.WriteLine(row);
        }
    }

    Console.WriteLine();
    Console.WriteLine($"  Bloques detectados      : {index:N0}");
    Console.WriteLine($"  Cabeceras con XZ valido : {xzOk:N0}");
    Console.WriteLine($"  Cabeceras SIN XZ valido : {xzBad:N0}");
    Console.WriteLine($"  Suma campo1             : {sumDeclared:N0}  ({ByteSize.Format(sumDeclared)})");
    Console.WriteLine($"  Suma campo2 (comprimido): {sumCompressed:N0}  ({ByteSize.Format(sumCompressed)})");
    Console.WriteLine($"  Espacio esperado (datos-12): {content.Length - 12:N0}  ({ByteSize.Format(content.Length - 12)})");

    if (index > 30)
    {
        Console.WriteLine($"  (solo se muestran las 30 primeras cabeceras de {index:N0})");
    }

    return 0;
}

static int ReadFull(Stream stream, byte[] buffer)
{
    int total = 0;
    while (total < buffer.Length)
    {
        int got = stream.Read(buffer, total, buffer.Length - total);
        if (got <= 0)
        {
            break;
        }

        total += got;
    }

    return total;
}

static long ReadBigEndian64(byte[] buffer, int offset)
{
    long value = 0;
    for (int i = 0; i < 8; i++)
    {
        value = (value << 8) | buffer[offset + i];
    }

    return value;
}

static int XipExtract(string path, string destination, string[] filters)
{
    var wanted = new List<string>();
    string? stripPrefix = null;
    foreach (string filter in filters)
    {
        if (filter.StartsWith("--strip=", StringComparison.OrdinalIgnoreCase))
        {
            stripPrefix = filter["--strip=".Length..];
        }
        else
        {
            wanted.Add(filter);
        }
    }

    Console.WriteLine();
    Console.WriteLine($"  Destino : {Path.GetFullPath(destination)}");
    Console.WriteLine($"  Filtros : {(wanted.Count == 0 ? "(todos)" : string.Join(", ", wanted))}");
    if (stripPrefix is not null)
    {
        Console.WriteLine($"  Recortar prefijo: {stripPrefix}");
    }

    Console.WriteLine();

    ExtractionReport report = XipExtractor.Extract(
        path,
        new ExtractionRequest
        {
            Destination = destination,
            Filters = wanted,
            StripPrefix = stripPrefix,
        },
        message => Console.WriteLine("    ... " + message));

    if (report.PendingSymlinks.Count > 0)
    {
        string manifestPath = Path.Combine(Path.GetFullPath(destination), "_symlinks.txt");
        File.WriteAllLines(manifestPath, report.PendingSymlinks);
    }

    Console.WriteLine();
    Console.WriteLine($"  Entradas recorridas   : {report.EntriesWalked:N0}");
    Console.WriteLine($"  Directorios creados   : {report.DirectoriesCreated:N0}");
    Console.WriteLine($"  Archivos escritos     : {report.FilesWritten:N0}");
    Console.WriteLine(
        $"  Enlaces simbolicos    : {report.SymlinksCreated:N0}"
        + (report.PendingSymlinks.Count > 0 ? $" ({report.PendingSymlinks.Count} anotados en _symlinks.txt)" : string.Empty));
    Console.WriteLine($"  Datos escritos        : {ByteSize.Format(report.BytesWritten)}");
    Console.WriteLine($"  Deduplicados (Apple)  : {report.DeduplicatedFiles:N0} archivos con marcador");
    Console.WriteLine($"      reconstruidos     : {report.DeduplicatedResolved:N0}");

    if (report.DeduplicatedUnresolved > 0)
    {
        Console.WriteLine($"      SIN reconstruir   : {report.DeduplicatedUnresolved:N0}");
        foreach (string unresolved in report.UnresolvedFiles.Take(10))
        {
            Console.WriteLine($"          {unresolved}");
        }
    }

    Console.WriteLine($"  Tiempo                : {report.Elapsed.TotalMinutes:F1} min");
    return report.DeduplicatedUnresolved > 0 ? 5 : 0;
}

static int FsSymlinks(string manifest, string root)
{
    if (!File.Exists(manifest))
    {
        Console.Error.WriteLine($"ERROR: no existe el manifiesto '{manifest}'.");
        return 2;
    }

    root = Path.GetFullPath(root);
    if (!Directory.Exists(root))
    {
        Console.Error.WriteLine($"ERROR: no existe la raiz '{root}'.");
        return 2;
    }

    var pending = new List<(string Rel, string Target)>();
    foreach (string line in File.ReadAllLines(manifest))
    {
        int arrow = line.IndexOf("->", StringComparison.Ordinal);
        if (arrow < 0)
        {
            continue;
        }

        pending.Add((line[..arrow].Trim(), line[(arrow + 2)..].Trim()));
    }

    int created = 0;
    var failures = new List<string>();

    // Varias pasadas: un enlace puede apuntar a otro que todavia no existe.
    for (int pass = 0; pass < 4 && pending.Count > 0; pass++)
    {
        var remaining = new List<(string Rel, string Target)>();

        foreach ((string rel, string target) in pending)
        {
            string linkPath = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            string? linkDir = Path.GetDirectoryName(linkPath);
            if (linkDir is null)
            {
                failures.Add($"{rel}: ruta no valida");
                continue;
            }

            Directory.CreateDirectory(linkDir);

            try
            {
                if (File.Exists(linkPath))
                {
                    File.Delete(linkPath);
                }
                else if (Directory.Exists(linkPath))
                {
                    // Solo sustituimos carpetas vacias: son marcadores de posicion,
                    // no contenido real.
                    if (!Directory.EnumerateFileSystemEntries(linkPath).Any())
                    {
                        Directory.Delete(linkPath);
                    }
                    else
                    {
                        failures.Add($"{rel}: ya existe una carpeta con contenido");
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                failures.Add($"{rel}: {ex.Message}");
                continue;
            }

            string normalized = target.Replace('/', Path.DirectorySeparatorChar);
            string resolved = Path.GetFullPath(Path.Combine(linkDir, normalized));
            bool isDirectory = Directory.Exists(resolved)
                || (!File.Exists(resolved) && !LooksLikeFileTarget(normalized));

            try
            {
                if (isDirectory)
                {
                    Directory.CreateSymbolicLink(linkPath, normalized);
                }
                else
                {
                    File.CreateSymbolicLink(linkPath, normalized);
                }

                created++;
            }
            catch (Exception ex)
            {
                remaining.Add((rel, target));
                if (pass == 3)
                {
                    failures.Add($"{rel}: {ex.Message}");
                }
            }
        }

        pending = remaining;
    }

    Console.WriteLine();
    Console.WriteLine($"  Raiz    : {root}");
    Console.WriteLine($"  Enlaces : {created} creados" + (failures.Count > 0 ? $", {failures.Count} fallos" : string.Empty));
    foreach (string failure in failures.Take(10))
    {
        Console.WriteLine($"    [X] {failure}");
    }

    Console.WriteLine();
    return failures.Count == 0 ? 0 : 4;
}

static bool LooksLikeFileTarget(string target)
{
    string extension = Path.GetExtension(target).ToLowerInvariant();
    return extension is ".tbd" or ".dylib" or ".a" or ".h" or ".hpp" or ".plist" or ".swiftmodule" or ".diff";
}

static int XipCat(string path, string fragment, int bytes)
{
    using var xar = XarArchive.Open(path);
    XarEntry? content = xar.Find("Content");
    if (content is null)
    {
        Console.Error.WriteLine("ERROR: el contenedor no tiene una entrada 'Content'.");
        return 3;
    }

    using Stream raw = xar.OpenEntryData(content);
    using var pbzx = PbzxStream.Over(raw);
    var cpio = new CpioReader(pbzx);

    var stopwatch = Stopwatch.StartNew();
    long walked = 0;

    Console.WriteLine();
    Console.WriteLine($"  Buscando \"{fragment}\"...");

    CpioEntry? entry;
    while ((entry = cpio.MoveNext()) is not null)
    {
        walked++;
        if (entry.IsDirectory || entry.IsSymlink)
        {
            continue;
        }

        if (!entry.Name.Contains(fragment, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        Console.WriteLine($"  Entrada    : {entry.Name}");
        Console.WriteLine($"  Modo       : {entry.ModeText}  formato={entry.Format}  tamano={entry.Size:N0}");
        Console.WriteLine($"  Recorridas : {walked:N0} entradas en {stopwatch.Elapsed.TotalSeconds:F0}s");
        Console.WriteLine();

        byte[] data = cpio.ReadCurrentData();
        int take = Math.Min(bytes, data.Length);
        Console.WriteLine($"  Primeros {take} bytes TAL COMO SALEN del descompresor:");
        PrintHex(data, take, 0);
        Console.WriteLine();
        return 0;
    }

    Console.WriteLine($"  (no encontrado; se recorrieron {walked:N0} entradas)");
    return 3;
}
