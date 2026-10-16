namespace NixerCode.Core.Xip;

/// <summary>
/// Antepone unos bytes ya leidos delante de otro flujo. Se usa para "devolver"
/// los bytes que se consumieron al mirar una firma, sin poder rebobinar.
/// </summary>
internal sealed class PrefixedStream : Stream
{
    private readonly byte[] _prefix;
    private readonly Stream _inner;
    private int _prefixPosition;

    internal PrefixedStream(byte[] prefix, Stream inner)
    {
        _prefix = prefix;
        _inner = inner;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _prefixPosition + _inner.Position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int total = 0;
        if (_prefixPosition < _prefix.Length)
        {
            int available = Math.Min(buffer.Length, _prefix.Length - _prefixPosition);
            _prefix.AsSpan(_prefixPosition, available).CopyTo(buffer);
            _prefixPosition += available;
            total += available;
        }

        if (total < buffer.Length)
        {
            total += _inner.Read(buffer[total..]);
        }

        return total;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
