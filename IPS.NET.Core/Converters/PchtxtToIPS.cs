using IPS.NET.Core.Extensions;
using Revrs;
using System.Globalization;

namespace IPS.NET.Core.Converters;

public class PchtxtToIPS
{
    private const string ENABLED_KEYWORD = "@enabled";
    private const string STOP_KEYWORD = "@stop";

    private static readonly Exception _invalidNsoidException = new InvalidDataException("""
        Could not locate NSOBID in pchtxt header.
        """);

    private static readonly Exception _invalidPchtxtException = new InvalidDataException("""
        Could not identify IPS type from pchtxt entries.
        """);

    private enum Type
    {
        None,
        IPS = 3,
        IPS32 = 4,
    }
    
    private enum State
    {
        None,
        Address,
        Value,
        Comment,
    }

    public static void ConvertPchtxtToIps(string pchtxtPath, string outputDirectory)
    {
        string text = File.ReadAllText(pchtxtPath);
        if (text.Length < 8) {
            throw _invalidNsoidException;
        }

        ReadOnlySpan<char> utf16 = text;
        int endOfLineIndex = utf16.IndexOf('\n');
        ReadOnlySpan<char> nsoid = utf16[8..endOfLineIndex];
        if (nsoid[^1] is '\r') {
            nsoid = utf16[..^1];
        }

        string output = Path.Combine(outputDirectory, $"{nsoid}.ips");

        Directory.CreateDirectory(outputDirectory);
        using FileStream fs = File.Create(output);

        ConvertPchtxtToIps(utf16, fs);
    }

    public static void ConvertPchtxtToIps(ReadOnlySpan<char> text, Stream output)
    {
        int enabledBlockStartIndex = text.IndexOf(ENABLED_KEYWORD) + ENABLED_KEYWORD.Length;
        int enabledBlockEndIndex = enabledBlockStartIndex + text[enabledBlockStartIndex..].IndexOf(STOP_KEYWORD);
        ReadOnlySpan<char> enabledBlock = text[enabledBlockStartIndex..enabledBlockEndIndex];

        RevrsWriter writer = new(output, Endianness.Big);
        writer.Move(5);

        int addressSize = 0;
        Type type = Type.None;

        State state = State.None;
        int valueRangeStart = 0;
        int valueSize = 0;

        int addressBytePos = 0;

        for (int i = 0; i < enabledBlock.Length; i++) {
            char @char = enabledBlock[i];
            switch (@char) {
                case '\r' or '\n':
                    if (valueSize > 0) {
                        writer.Write((ushort)(valueSize / 2));
                        writer.WriteHex(enabledBlock[valueRangeStart..(valueRangeStart + valueSize)]);
                    }

                    valueRangeStart = valueSize = addressSize = 0;
                    state = State.Address;
                    addressBytePos = 0;
                    break;
                case ' ':
                    switch (state) {
                        case State.Address:
                            valueRangeStart = i + 1;
                            state = State.Value;
                            type = (Type)addressSize;
                            break;
                        default:
                            state = State.Comment;
                            break;
                    }
                    break;
                case '@':
                    state = State.Comment;
                    break;
                default:
                    switch (state) {
                        case State.Address:
                            writer.Write((byte)(byte.Parse(enabledBlock[i..(++i + 1)], NumberStyles.HexNumber) + addressBytePos switch {
                                2 => 1,
                                _ => 0
                            }));
                            addressSize++;
                            addressBytePos++;
                            break;
                        case State.Value:
                            valueSize++;
                            break;
                    }
                    break;
            }
        }

        writer.Write(type switch {
            Type.IPS => "EOF"u8,
            Type.IPS32 => "EEOF"u8,
            _ => throw _invalidPchtxtException
        });

        writer.Seek(position: 0);
        writer.Write(type switch {
            Type.IPS => "PATCH"u8,
            Type.IPS32 => "IPS32"u8,
            _ => throw _invalidPchtxtException
        });
    }
}
