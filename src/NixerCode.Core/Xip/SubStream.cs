namespace NixerCode.Core.Xip;

/// <summary>
/// Vista de solo lectura sobre una porcion de otro flujo.
/// No admite posicionamiento: avanza secuencialmente desde donde se creo.
/// </summary>
internal sealed class SubStream : Stream
{
    private readonly Stream _inner;
    private readonly long _length;
    private long _position;

    internal SubStream(Stream inner, long length)
    {
        _inner = inner;
        _length = length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        long remaining = _length - _position;
        if (remaining <= 0)
        {
            return 0;
        }

        if (count > remaining)
        {
            count = (int)remaining;
        }

        int read = _inner.Read(buffer, offset, count);
        _position += read;
        return read;
    }

    public override int Read(Span<byte> buffer)
    {
        long remaining = _length - _position;
        if (remaining <= 0)
        {
            return 0;
        }

        if (buffer.Length > remaining)
        {
            buffer = buffer[..(int)remaining];
        }

        int read = _inner.Read(buffer);
        _position += read;
        return read;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
