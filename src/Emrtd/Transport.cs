using PCSC;
using PCSC.Exceptions;

namespace Emrtd;

/// <summary>Sends raw APDUs to a contactless chip. Implemented by <see cref="PcscTransport"/> and by test simulators.</summary>
public interface ICardTransport : IDisposable
{
    byte[] Transmit(byte[] apdu);

    /// <summary>Resets the chip (e.g. after a failed PACE attempt, before falling back to BAC).</summary>
    void Reset();
}

/// <summary>
/// PC/SC transport. Works with Windows' built-in NFC smart-card reader and USB CCID readers
/// (ACS ACR1252U, HID Omnikey 5022, Identiv uTrust 3700F, ...). Also runs on macOS/Linux (pcsc-lite).
/// </summary>
public sealed class PcscTransport : ICardTransport
{
    private readonly ISCardContext _context;
    private readonly ICardReader _reader;
    private readonly byte[] _buffer = new byte[65538];

    private PcscTransport(ISCardContext context, ICardReader reader)
    {
        _context = context;
        _reader = reader;
    }

    public string ReaderName => _reader.Name;

    public byte[] Atr => _reader.GetStatus().GetAtr();

    public static string[] ListReaders()
    {
        using var context = ContextFactory.Instance.Establish(SCardScope.System);
        try
        {
            return context.GetReaders() ?? [];
        }
        catch (NoReadersAvailableException)
        {
            return [];
        }
    }

    /// <summary>
    /// Waits until a card is present on a reader and connects to it.
    /// <paramref name="readerName"/> may be a substring of the reader name; null picks the first reader with a card.
    /// </summary>
    public static PcscTransport WaitForCard(string? readerName, TimeSpan timeout, Action<string>? log = null)
    {
        var context = ContextFactory.Instance.Establish(SCardScope.System);
        try
        {
            var deadline = DateTime.UtcNow + timeout;
            bool announced = false;
            while (true)
            {
                string[] readers = GetReaders(context)
                    .Where(r => readerName is null || r.Contains(readerName, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (readers.Length == 0)
                    throw new InvalidOperationException(readerName is null
                        ? "No PC/SC readers found. Check that the NFC reader is enabled / plugged in."
                        : $"No PC/SC reader matching '{readerName}'. Available: {string.Join(", ", GetReaders(context))}");

                foreach (string reader in readers)
                {
                    var state = context.GetReaderStatus(reader);
                    if (!state.EventState.HasFlag(SCRState.Present) || state.EventState.HasFlag(SCRState.Mute)) continue;

                    var cardReader = context.ConnectReader(reader, SCardShareMode.Exclusive, SCardProtocol.Any);
                    log?.Invoke($"Connected to '{reader}' ({cardReader.Protocol}).");
                    return new PcscTransport(context, cardReader);
                }

                if (!announced)
                {
                    log?.Invoke($"Waiting for a document on: {string.Join(", ", readers)}");
                    announced = true;
                }
                if (DateTime.UtcNow > deadline) throw new TimeoutException("No document presented to the reader.");
                Thread.Sleep(250);
            }
        }
        catch
        {
            context.Dispose();
            throw;
        }
    }

    private static string[] GetReaders(ISCardContext context)
    {
        try
        {
            return context.GetReaders() ?? [];
        }
        catch (NoReadersAvailableException)
        {
            return [];
        }
    }

    public byte[] Transmit(byte[] apdu)
    {
        var response = TransmitRaw(apdu);

        // T=0 style continuation: 61xx = more data available, 6Cxx = wrong Le, resend with the right one.
        if (response.Length == 2 && response[0] == 0x6C)
        {
            var retry = (byte[])apdu.Clone();
            retry[^1] = response[1];
            response = TransmitRaw(retry);
        }

        var data = new List<byte>();
        while (response.Length >= 2 && response[^2] == 0x61)
        {
            data.AddRange(response[..^2]);
            response = TransmitRaw([(byte)(apdu[0] & 0x03), 0xC0, 0x00, 0x00, response[^1]]);
        }
        if (data.Count == 0) return response;
        data.AddRange(response);
        return [.. data];
    }

    private byte[] TransmitRaw(byte[] apdu)
    {
        int length = _reader.Transmit(apdu, _buffer);
        return _buffer[..length];
    }

    public void Reset() => _reader.Reconnect(SCardShareMode.Exclusive, SCardProtocol.Any, SCardReaderDisposition.Reset);

    public void Dispose()
    {
        try
        {
            _reader.Disconnect(SCardReaderDisposition.Leave);
        }
        catch (PCSCException)
        {
            // Card already removed.
        }
        _reader.Dispose();
        _context.Dispose();
    }
}
