using System.Buffers.Binary;
using SharpCompress.Compressors.Xz;

namespace NixerCode.Core.Xip;

/// <summary>Describe un bloque dentro de un flujo pbzx.</summary>
public sealed record PbzxChunk(int Index, long UncompressedSize, long CompressedSize, bool IsXz);

/// <summary>
/// Flujo de solo lectura que descomprime un contenedor "pbzx", el formato que
/// Apple usa dentro de los .xip.
///
/// Estructura:
///   "pbzx"            (4 bytes)
///   version           (8 bytes, big-endian; Apple escribe aqui 0x1000000 = 16 MB)
///   y despues, repetido hasta el final:
///     tamano sin comprimir (8 bytes, big-endian)
///     tamano comprimido    (8 bytes, big-endian)
///     datos (tamano comprimido bytes, contenedor XZ / LZMA2)
/// </summary>
public sealed class PbzxStream : Stream
{
    private static readonly byte[] PbzxMagic = "pbzx"u8.ToArray();

    private readonly Stream _source;
    private readonly bool _ownsSource;
    private readonly List<PbzxChunk> _chunks = [];
    private readonly byte[] _drainBuffer = new byte[64 * 1024];

    private Stream? _chunkSource;
    private Stream? _chunkData;
    private long _remainingInChunk;
    private bool _finished;

    private PbzxStream(Stream source, bool ownsSource)
    {
        _source = source;
        _ownsSource = ownsSource;

        Span<byte> magic = stackalloc byte[4];
        if (ReadFully(_source, magic) != 4 || !magic.SequenceEqual(PbzxMagic))
        {
            throw new InvalidDataException("El flujo no empieza por la firma 'pbzx'.");
        }

        Span<byte> versionBytes = stackalloc byte[8];
        if (ReadFully(_source, versionBytes) != 8)
        {
            throw new InvalidDataException("Cabecera pbzx truncada.");
        }

        Version = (long)BinaryPrimitives.ReadUInt64BigEndian(versionBytes);
    }

    /// <summary>Crea el descompresor sobre un flujo ya posicionado al inicio del contenido.</summary>
    public static PbzxStream Over(Stream source) => new(source, ownsSource: false);

    /// <summary>Valor del campo "version" tal y como aparece en el archivo.</summary>
    public long Version { get; }

    /// <summary>Bloques encontrados hasta el momento (crece a medida que se lee).</summary>
    public IReadOnlyList<PbzxChunk> Chunks => _chunks;

    /// <summary>Bytes descomprimidos entregados hasta el momento.</summary>
    public long BytesProduced { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => BytesProduced;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            if (!EnsureChunk())
            {
                break;
            }

            int want = (int)Math.Min(count - total, _remainingInChunk);
            if (want <= 0)
            {
                CloseChunk();
                continue;
            }

            int got = _chunkData!.Read(buffer, offset + total, want);
            if (got <= 0)
            {
                CloseChunk();
                continue;
            }

            _remainingInChunk -= got;
            total += got;
            BytesProduced += got;

            if (_remainingInChunk == 0)
            {
                CloseChunk();
            }
        }

        return total;
    }

    public override int Read(Span<byte> buffer)
    {
        byte[] rented = new byte[buffer.Length];
        int read = Read(rented, 0, rented.Length);
        rented.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    private bool EnsureChunk()
    {
        Span<byte> header = stackalloc byte[16];

        while (_chunkData is null)
        {
            if (_finished)
            {
                return false;
            }

            int got = ReadFully(_source, header);
            if (got == 0)
            {
                _finished = true;
                return false;
            }

            if (got < 16)
            {
                throw new InvalidDataException("Cabecera de bloque pbzx truncada.");
            }

            long uncompressed = (long)BinaryPrimitives.ReadUInt64BigEndian(header[..8]);
            long compressed = (long)BinaryPrimitives.ReadUInt64BigEndian(header[8..]);

            if (uncompressed <= 0 || compressed <= 0)
            {
                _finished = true;
                return false;
            }

            // Mirar la firma del bloque: si empieza por "«7zXZ" va comprimido con LZMA2;
            // si no, va almacenado tal cual (Apple lo hace asi con datos incompresibles).
            byte[] peek = new byte[6];
            int peeked = ReadFully(_source, peek.AsSpan(0, 6));
            bool isXz = peeked == 6
                && peek[0] == 0xFD && peek[1] == 0x37 && peek[2] == 0x7A
                && peek[3] == 0x58 && peek[4] == 0x5A && peek[5] == 0x00;

            Stream payload = new SubStream(_source, compressed - peeked);
            if (peeked > 0)
            {
                payload = new PrefixedStream(peek.AsSpan(0, peeked).ToArray(), payload);
            }

            _chunks.Add(new PbzxChunk(_chunks.Count + 1, uncompressed, compressed, isXz));
            _chunkSource = payload;
            _chunkData = isXz ? new XZStream(payload) : payload;
            _remainingInChunk = uncompressed;
        }

        return true;
    }

    /// <summary>
    /// Cierra el bloque actual agotando los bytes no consumidos del origen,
    /// para que la siguiente cabecera quede perfectamente alineada.
    /// </summary>
    private void CloseChunk()
    {
        try
        {
            while (_chunkSource is not null && _chunkSource.Read(_drainBuffer, 0, _drainBuffer.Length) > 0)
            {
                // Descartar el resto del bloque comprimido.
            }
        }
        catch (Exception)
        {
            // Si el bloque esta danado, seguimos: el siguiente intento lo detectara.
        }

        _chunkData?.Dispose();
        _chunkData = null;
        _chunkSource = null;
        _remainingInChunk = 0;
    }

    private static int ReadFully(Stream stream, Span<byte> destination)
    {
        int total = 0;
        while (total < destination.Length)
        {
            int got = stream.Read(destination[total..]);
            if (got <= 0)
            {
                break;
            }

            total += got;
        }

        return total;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CloseChunk();
            if (_ownsSource)
            {
                _source.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
