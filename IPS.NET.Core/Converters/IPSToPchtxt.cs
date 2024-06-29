namespace IPS.NET.Core.Converters
{
    using System;
    using System.IO;
    using System.Globalization;

    public class IPSToPchtxt
    {
        private const int IPS_ADDRESS_SIZE = 3;
        private const int IPS32_ADDRESS_SIZE = 4;
        private const int NSO_HEADER_LEN = 0x100;
        private static readonly byte[] IPS_HEAD_MAGIC = { 0x50, 0x41, 0x54, 0x43, 0x48 }; // "PATCH"
        private static readonly byte[] IPS32_HEAD_MAGIC = { 0x49, 0x50, 0x53, 0x33, 0x32 }; // "IPS32"
        private static readonly byte[] IPS_FOOT_MAGIC = { 0x45, 0x4F, 0x46 }; // "EOF"
        private static readonly byte[] IPS32_FOOT_MAGIC = { 0x45, 0x45, 0x4F, 0x46 }; // "EEOF"

        public static void ConvertIpsToPchtxt(string ipsPath, string outputDirectory)
        {
            byte[] ipsData = File.ReadAllBytes(ipsPath);
            string outputFileName = Path.GetFileNameWithoutExtension(ipsPath) + ".pchtxt";
            string outputPath = Path.Combine(outputDirectory, outputFileName);

            using (StreamWriter writer = new StreamWriter(outputPath))
            {
                int index = 0;

                // Check the header
                if (MatchMagic(ipsData, ref index, IPS_HEAD_MAGIC))
                {
                    writer.WriteLine("@nsobid-" + Path.GetFileNameWithoutExtension(ipsPath));
                    ProcessIpsData(ipsData, index, IPS_ADDRESS_SIZE, writer);
                }
                else if (MatchMagic(ipsData, ref index, IPS32_HEAD_MAGIC))
                {
                    writer.WriteLine("@nsobid-" + Path.GetFileNameWithoutExtension(ipsPath));
                    ProcessIpsData(ipsData, index, IPS32_ADDRESS_SIZE, writer);
                }
                else
                {
                    throw new InvalidOperationException("Unsupported IPS file format");
                }
            }
        }

        private static void ProcessIpsData(byte[] ipsData, int startIndex, int addressSize, StreamWriter writer)
        {
            int index = startIndex;

            while (index < ipsData.Length)
            {
                if (MatchMagic(ipsData, ref index, addressSize == IPS_ADDRESS_SIZE ? IPS_FOOT_MAGIC : IPS32_FOOT_MAGIC))
                {
                    break;
                }

                // Read the address
                byte[] addressBytes = new byte[addressSize];
                Array.Copy(ipsData, index, addressBytes, 0, addressSize);
                Array.Reverse(addressBytes);
                int address = BitConverter.ToInt32(new byte[] { addressBytes[0], addressBytes[1], addressBytes[2], 0 }, 0) - NSO_HEADER_LEN;
                index += addressSize;

                // Read the length
                byte[] lengthBytes = new byte[2];
                Array.Copy(ipsData, index, lengthBytes, 0, 2);
                Array.Reverse(lengthBytes);
                ushort length = BitConverter.ToUInt16(lengthBytes, 0);
                index += 2;

                // Read the patch value
                byte[] value = new byte[length];
                Array.Copy(ipsData, index, value, 0, length);
                index += length;

                // Write the patch data to the pchtxt file
                writer.WriteLine($"{address.ToString("X6")} {BitConverter.ToString(value).Replace("-", "")}");
            }
        }

        private static bool MatchMagic(byte[] data, ref int index, byte[] magic)
        {
            if (index + magic.Length > data.Length)
            {
                return false;
            }

            for (int i = 0; i < magic.Length; i++)
            {
                if (data[index + i] != magic[i])
                {
                    return false;
                }
            }

            index += magic.Length;
            return true;
        }
    }
}
