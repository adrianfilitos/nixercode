using System.Text;

namespace NixerCode.Core.Xip;

/// <summary>Una entrada dentro de un archivo cpio.</summary>
public sealed record CpioEntry(
    string Name,
    long Size,
    int Mode,
    long ModifiedUnixTime,
    string Format,
    long Dev = 0,
    long Ino = 0,
    long NLink = 1)
{
    private const int FileTypeMask = 0xF000;

    public bool IsDirectory => (Mode & FileTypeMask) == 0x4000;
    public bool IsSymlink => (Mode & FileTypeMask) == 0xA000;
    public bool IsRegularFile => (Mode & FileTypeMask) == 0x8000;

    public string ModeText
    {
        get
        {
            Span<char> chars = stackalloc char[10];
            chars[0] = IsDirectory ? 'd' : IsSymlink ? 'l' : IsRegularFile ? '-' : '?';
            ReadOnlySpan<char> rwx = "rwxrwxrwx";
            for (int i = 0; i < 9; i++)
            {
                chars[i + 1] = (Mode & (1 << (8 - i))) != 0 ? rwx[i] : '-';
            }

            return new string(chars);
        }
    }

    public DateTimeOffset? Modified
    {
        get
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(ModifiedUnixTime);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }
    }
}

/// <summary>
/// Lector secuencial del formato cpio. Soporta las dos variantes que usa Apple
/// dentro de un .xip: "odc" (070707) y "newc" (070701 / 070702).
/// </summary>
public sealed class CpioReader
{
    private static readonly byte[] PadBuffer = new byte[8];

    private readonly Stream _stream;
    private readonly byte[] _skipBuffer = new byte[256 * 1024];
    private readonly byte[] _copyBuffer = new byte[1024 * 1024];

    private long _remaining;
    private int _dataPadding;

    public CpioReader(Stream stream) => _stream = stream;

    /// <summary>TRUE si ya se alcanzo la entrada final ("TRAILER!!!").</summary>
    public bool ReachedEnd { get; private set; }

    public long EntriesRead { get; private set; }

    /// <summary>
    /// Avanza a la siguiente entrada. El flujo queda posicionado justo en sus datos.
    /// Devuelve null al llegar al final del archivo.
    /// </summary>
    public CpioEntry? MoveNext()
    {
        if (ReachedEnd)
        {
            return null;
        }

        DrainCurrent();

        Span<byte> magic = stackalloc byte[6];
        int got = ReadFully(_stream, magic);
        if (got == 0)
        {
            ReachedEnd = true;
            return null;
        }

        if (got < 6)
        {
            throw new InvalidDataException("Cabecera cpio truncada.");
        }

        string magicText = Encoding.ASCII.GetString(magic);
        CpioEntry entry = magicText switch
        {
            "070707" => ReadOdcHeader(),
            "070701" or "070702" => ReadNewcHeader(),
            _ => throw new InvalidDataException(
                $"Formato cpio desconocido (firma '{magicText}' en la entrada {EntriesRead + 1})."),
        };

        if (entry.Name is "TRAILER!!!")
        {
            ReachedEnd = true;
            return null;
        }

        _remaining = entry.Size;
        EntriesRead++;
        return entry;
    }

    /// <summary>
    /// Lee como maximo 'count' bytes de los datos de la entrada actual.
    /// Permite inspeccionar el principio de un archivo sin perder el resto.
    /// </summary>
    public int ReadCurrent(byte[] buffer, int offset, int count)
    {
        if (_remaining <= 0)
        {
            return 0;
        }

        int want = (int)Math.Min(count, _remaining);
        int read = _stream.Read(buffer, offset, want);
        _remaining -= read;
        return read;
    }

    /// <summary>Copia los datos de la entrada actual al destino indicado.</summary>
    public long CopyCurrentData(Stream destination)
    {
        long copied = 0;
        while (_remaining > 0)
        {
            int read = _stream.Read(_copyBuffer, 0, (int)Math.Min(_copyBuffer.Length, _remaining));
            if (read <= 0)
            {
                break;
            }

            destination.Write(_copyBuffer, 0, read);
            _remaining -= read;
            copied += read;
        }

        return copied;
    }

    /// <summary>Lee los datos de la entrada actual en memoria (para entradas pequenas).</summary>
    public byte[] ReadCurrentData()
    {
        var result = new byte[_remaining];
        int total = 0;
        while (total < result.Length)
        {
            int read = _stream.Read(result, total, result.Length - total);
            if (read <= 0)
            {
                break;
            }

            total += read;
        }

        _remaining -= total;
        return total == result.Length ? result : result[..total];
    }

    private void DrainCurrent()
    {
        while (_remaining > 0)
        {
            int read = _stream.Read(_skipBuffer, 0, (int)Math.Min(_skipBuffer.Length, _remaining));
            if (read <= 0)
            {
                break;
            }

            _remaining -= read;
        }

        if (_dataPadding > 0)
        {
            ReadFully(_stream, PadBuffer.AsSpan(0, _dataPadding));
            _dataPadding = 0;
        }

        _remaining = 0;
    }

    private CpioEntry ReadOdcHeader()
    {
        byte[] rest = new byte[70];
        _stream.ReadExactly(rest);

        long dev = ParseOctal(rest, 0, 6);
        long ino = ParseOctal(rest, 6, 6);
        int mode = (int)ParseOctal(rest, 12, 6);
        long nlink = ParseOctal(rest, 30, 6);
        long mtime = ParseOctal(rest, 42, 11);
        int nameSize = (int)ParseOctal(rest, 53, 6);
        long size = ParseOctal(rest, 59, 11);

        string name = ReadName(nameSize);
        _dataPadding = 0; // el formato odc no usa relleno
        return new CpioEntry(name, size, mode, mtime, "odc", dev, ino, nlink);
    }

    private CpioEntry ReadNewcHeader()
    {
        byte[] rest = new byte[104];
        _stream.ReadExactly(rest);

        long ino = ParseOctal(rest, 0, 8);
        int mode = (int)ParseOctal(rest, 8, 8);
        long nlink = ParseOctal(rest, 32, 8);
        long mtime = ParseOctal(rest, 40, 8);
        long size = ParseOctal(rest, 48, 8);
        long dev = ParseOctal(rest, 56, 16);
        int nameSize = (int)ParseOctal(rest, 88, 8);

        string name = ReadName(nameSize);

        int namePadding = (4 - ((110 + nameSize) % 4)) % 4;
        if (namePadding > 0)
        {
            ReadFully(_stream, PadBuffer.AsSpan(0, namePadding));
        }

        _dataPadding = (int)((4 - (size % 4)) % 4);
        return new CpioEntry(name, size, mode, mtime, "newc", dev, ino, nlink);
    }

    private string ReadName(int size)
    {
        if (size <= 0)
        {
            return string.Empty;
        }

        byte[] bytes = new byte[size];
        _stream.ReadExactly(bytes);

        int length = Array.IndexOf(bytes, (byte)0);
        if (length < 0)
        {
            length = bytes.Length;
        }

        return Encoding.UTF8.GetString(bytes, 0, length);
    }

    private static long ParseOctal(byte[] buffer, int offset, int length)
    {
        long value = 0;
        for (int i = 0; i < length; i++)
        {
            byte b = buffer[offset + i];
            if (b is < (byte)'0' or > (byte)'7')
            {
                continue;
            }

            value = (value * 8) + (b - '0');
        }

        return value;
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
}
