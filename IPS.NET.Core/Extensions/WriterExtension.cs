using Revrs;
using System.Globalization;

namespace IPS.NET.Core.Extensions;

public static class WriterExtension
{
    public static void WriteHex(this ref RevrsWriter writer, ReadOnlySpan<char> hex)
    {
        for (var i = 0; i < hex.Length; i++) {
            writer.Write(byte.Parse(hex[i..(++i + 1)], NumberStyles.HexNumber));
        }
    }
}
