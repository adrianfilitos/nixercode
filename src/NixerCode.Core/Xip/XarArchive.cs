using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace NixerCode.Core.Xip;

/// <summary>
/// Una entrada (archivo) dentro de un contenedor XAR.
/// Los desplazamientos son relativos al inicio del "heap" (zona de datos),
/// no al inicio del archivo.
/// </summary>
public sealed class XarEntry
{
    public required string Name { get; init; }
    public required string Type { get; init; }
    public long Offset { get; init; }
    public long Length { get; init; }
    public long Size { get; init; }
    public string? Encoding { get; init; }
    public string? ArchivedSha1 { get; init; }
    public string? ExtractedSha1 { get; init; }

    /// <summary>True si los datos almacenados van codificados dentro del contenedor.</summary>
    public bool IsStoredCompressed =>
        !string.IsNullOrEmpty(Encoding) &&
        !Encoding.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase);

    public override string ToString() => $"{Name} ({ByteSize.Format(Length)})";
}

/// <summary>
/// Lector del formato XAR, el contenedor que usa Apple para distribuir Xcode (.xip).
/// Solo lee cabecera e indice; los datos se sirven bajo demanda.
/// </summary>
public sealed class XarArchive : IDisposable
{
    private const uint XarMagic = 0x78617221; // "xar!" leido en big-endian

    private readonly Stream _stream;
    private readonly bool _ownsStream;

    public ushort Version { get; private set; }
    public uint ChecksumAlgorithm { get; private set; }
    public long HeaderSize { get; private set; }
    public long TocCompressedLength { get; private set; }
    public long TocUncompressedLength { get; private set; }
    public long HeapStart { get; private set; }
    public IReadOnlyList<XarEntry> Entries { get; private set; } = [];
    public IReadOnlyList<string> SignatureCertificates { get; private set; } = [];
    public DateTimeOffset? CreatedAt { get; private set; }

    /// <summary>Tamano que deberia tener el archivo segun su propio indice.</summary>
    public long DeclaredTotalSize { get; private set; }

    public bool IsSigned => SignatureCertificates.Count > 0;

    private XarArchive(Stream stream, bool ownsStream)
    {
        _stream = stream;
        _ownsStream = ownsStream;

        Span<byte> header = stackalloc byte[28];
        stream.ReadExactly(header);

        uint magic = BinaryPrimitives.ReadUInt32BigEndian(header[..4]);
        if (magic != XarMagic)
        {
            throw new InvalidDataException(
                $"No parece un contenedor XAR: magic 0x{magic:X8} (esperado 0x{XarMagic:X8}).");
        }

        HeaderSize = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(4, 2));
        Version = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(6, 2));
        TocCompressedLength = checked((long)BinaryPrimitives.ReadUInt64BigEndian(header.Slice(8, 8)));
        TocUncompressedLength = checked((long)BinaryPrimitives.ReadUInt64BigEndian(header.Slice(16, 8)));
        ChecksumAlgorithm = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(24, 4));

        if (HeaderSize < 28)
        {
            throw new InvalidDataException($"Cabecera XAR invalida (tamano {HeaderSize}).");
        }

        if (TocCompressedLength <= 0 || TocCompressedLength > 64L * 1024 * 1024)
        {
            throw new InvalidDataException($"Longitud de indice poco razonable: {TocCompressedLength} bytes.");
        }

        HeapStart = HeaderSize + TocCompressedLength;

        byte[] tocBytes = new byte[TocCompressedLength];
        stream.Position = HeaderSize;
        stream.ReadExactly(tocBytes);

        string tocXml = TocUncompressedLength == TocCompressedLength
            ? Encoding.UTF8.GetString(tocBytes)
            : Inflate(tocBytes);

        ParseToc(tocXml);
    }

    public static XarArchive Open(string path)
    {
        var file = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1 << 20,
            FileOptions.RandomAccess);

        try
        {
            return new XarArchive(file, ownsStream: true);
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    public static XarArchive OpenRead(Stream stream) => new(stream, ownsStream: false);

    public XarEntry? Find(string name) =>
        Entries.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Flujo subyacente. Uso avanzado: permite saltar rapido por el archivo
    /// (por ejemplo, para mapear cabeceras sin descomprimir).
    /// </summary>
    public Stream BaseStream => _stream;

    /// <summary>Coloca la lectura justo al inicio de los datos almacenados de una entrada.</summary>
    public void SeekToData(XarEntry entry) => _stream.Position = HeapStart + entry.Offset;

    /// <summary>Devuelve un flujo de lectura sobre los datos almacenados de la entrada.</summary>
    public Stream OpenEntryData(XarEntry entry)
    {
        if (entry.Length <= 0)
        {
            throw new InvalidOperationException($"La entrada '{entry.Name}' no tiene datos.");
        }

        _stream.Position = HeapStart + entry.Offset;
        return new SubStream(_stream, entry.Length);
    }

    public string ComputeSha1(XarEntry entry)
    {
        using Stream data = OpenEntryData(entry);
        byte[] hash = SHA1.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>Comprueba los datos almacenados contra el SHA1 que declara el indice.</summary>
    public bool Verify(XarEntry entry)
    {
        if (string.IsNullOrEmpty(entry.ArchivedSha1))
        {
            return true;
        }

        string actual = ComputeSha1(entry);
        return string.Equals(actual, entry.ArchivedSha1, StringComparison.OrdinalIgnoreCase);
    }

    private static string Inflate(byte[] data)
    {
        using var memory = new MemoryStream(data, writable: false);
        using var zlib = new ZLibStream(memory, CompressionMode.Decompress);
        using var reader = new StreamReader(zlib, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private void ParseToc(string xml)
    {
        XDocument document = XDocument.Parse(xml);
        XElement toc = document.Root?.Element("toc")
            ?? throw new InvalidDataException("El indice no contiene un elemento <toc>.");

        var entries = new List<XarEntry>();
        foreach (XElement file in toc.Elements("file"))
        {
            XElement? data = file.Element("data");
            if (data is null)
            {
                continue;
            }

            entries.Add(new XarEntry
            {
                Name = file.Element("name")?.Value ?? "(sin nombre)",
                Type = file.Element("type")?.Value ?? "file",
                Length = ParseLong(data.Element("length")),
                Offset = ParseLong(data.Element("offset")),
                Size = ParseLong(data.Element("size")),
                Encoding = data.Element("encoding")?.Attribute("style")?.Value,
                ArchivedSha1 = data.Element("archived-checksum")?.Value?.Trim(),
                ExtractedSha1 = data.Element("extracted-checksum")?.Value?.Trim(),
            });
        }

        Entries = entries;

        long maxEnd = 0;
        foreach (XarEntry entry in entries)
        {
            maxEnd = Math.Max(maxEnd, entry.Offset + entry.Length);
        }

        DeclaredTotalSize = HeapStart + maxEnd;

        string? created = toc.Element("creation-time")?.Value;
        CreatedAt = DateTimeOffset.TryParse(
            created,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : null;

        XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
        SignatureCertificates = toc.Element("signature")
            ?.Element(ds + "KeyInfo")
            ?.Element(ds + "X509Data")
            ?.Elements(ds + "X509Certificate")
            .Select(c => c.Value.Trim())
            .Where(v => v.Length > 0)
            .ToList()
            ?? [];
    }

    private static long ParseLong(XElement? element) =>
        element is null ? 0 : long.Parse(element.Value.Trim(), CultureInfo.InvariantCulture);

    public void Dispose()
    {
        if (_ownsStream)
        {
            _stream.Dispose();
        }
    }
}
