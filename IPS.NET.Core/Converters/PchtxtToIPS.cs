namespace IPS.NET.Core.Converters
{
    using System;
    using System.IO;
    using System.Globalization;

    public class PchtxtToIPS
    {
        private const int IPS_ADDRESS_SIZE = 3;
        private const int IPS32_ADDRESS_SIZE = 4;
        private const int NSO_HEADER_LEN = 0x100;
        private static readonly byte[] IPS_HEAD_MAGIC = { 0x50, 0x41, 0x54, 0x43, 0x48 }; // "PATCH"
        private static readonly byte[] IPS32_HEAD_MAGIC = { 0x49, 0x50, 0x53, 0x33, 0x32 }; // "IPS32"
        private static readonly byte[] IPS_FOOT_MAGIC = { 0x45, 0x4F, 0x46 }; // "EOF"
        private static readonly byte[] IPS32_FOOT_MAGIC = { 0x45, 0x45, 0x4F, 0x46 }; // "EEOF"

        public static void ConvertPchtxtToIps(string pchtxtPath, string outputDirectory)
        {
            string[] lines = File.ReadAllLines(pchtxtPath);
            byte[] headMagic = null;
            byte[] footMagic = null;
            int addressSize = 0;
            string outputFileName = null;

            // Extract the NSO bid from the first line and set the output file name
            if (lines.Length > 0 && lines[0].StartsWith("@nsobid-"))
            {
                outputFileName = lines[0].Substring(8).Trim() + ".ips";
            }
            else
            {
                throw new InvalidOperationException("NSO bid not found in the pchtxt file");
            }

            // Find the first line with actual patch data to determine address size
            foreach (string line in lines)
            {
                if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("@") && !line.StartsWith("//"))
                {
                    string[] parts = line.Trim().Split();
                    int addressLength = parts[0].Length / 2;

                    if (addressLength == IPS_ADDRESS_SIZE)
                    {
                        headMagic = IPS_HEAD_MAGIC;
                        footMagic = IPS_FOOT_MAGIC;
                        addressSize = IPS_ADDRESS_SIZE;
                        break;
                    }
                    else if (addressLength == IPS32_ADDRESS_SIZE)
                    {
                        headMagic = IPS32_HEAD_MAGIC;
                        footMagic = IPS32_FOOT_MAGIC;
                        addressSize = IPS32_ADDRESS_SIZE;
                        break;
                    }
                    else
                    {
                        throw new InvalidOperationException("Unsupported address size in pchtxt file");
                    }
                }
            }

            if (headMagic == null || footMagic == null)
            {
                throw new InvalidOperationException("No valid patch data found in pchtxt file");
            }

            string outputPath = Path.Combine(outputDirectory, outputFileName);
            using (FileStream ipsFile = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                ipsFile.Write(headMagic, 0, headMagic.Length);

                foreach (string line in lines)
                {
                    if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("@") && !line.StartsWith("//"))
                    {
                        string[] parts = line.Trim().Split();
                        int address = int.Parse(parts[0], NumberStyles.HexNumber) + NSO_HEADER_LEN;
                        byte[] value = HexStringToByteArray(parts[1]);

                        // Write address
                        byte[] addressBytes = BitConverter.GetBytes(address);
                        Array.Reverse(addressBytes); // Convert to big-endian
                        ipsFile.Write(addressBytes, addressBytes.Length - addressSize, addressSize);

                        // Write length of the patch
                        ushort length = (ushort)value.Length;
                        byte[] lengthBytes = BitConverter.GetBytes(length);
                        Array.Reverse(lengthBytes); // Convert to big-endian
                        ipsFile.Write(lengthBytes, lengthBytes.Length - 2, 2);

                        // Write the patch value
                        ipsFile.Write(value, 0, value.Length);
                    }
                }

                ipsFile.Write(footMagic, 0, footMagic.Length);
            }
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}