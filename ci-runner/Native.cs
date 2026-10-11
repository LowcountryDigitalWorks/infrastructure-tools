using System;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace LDW.CiRunner {
    public sealed class GuestDiagnostics : IDisposable {
        private readonly NamedPipeClientStream pipe;
        private readonly byte[] buffer = new byte[4096];
        private Task<int> read;
        private string pending = "";
        private bool ended;
        public GuestDiagnostics(string name) { pipe = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous); }
        public static string Classify(string line) {
            foreach (string stage in new[] { "BOOTSTRAP", "NETWORK", "DEPENDENCIES", "FIREWALL", "IDENTITY", "DOWNLOAD", "HASH", "SERVICE", "FAILED",
                "DOWNLOAD_DNS_FAILED", "DOWNLOAD_CONNECT_FAILED", "DOWNLOAD_HTTP_FAILED", "DOWNLOAD_WRITE_FAILED", "DOWNLOAD_TLS_FAILED", "DOWNLOAD_OTHER_FAILED" })
                if (line.TrimEnd('\r') == "CI7_BOOT_PHASE=" + stage) return stage;
            return null;
        }
        public string[] Poll() {
            var result = new List<string>();
            if (ended) return result.ToArray();
            try {
                if (!pipe.IsConnected) { pipe.Connect(200); read = pipe.ReadAsync(buffer, 0, buffer.Length); }
                if (read != null && read.IsCompleted) {
                    int count = read.GetAwaiter().GetResult();
                    if (count == 0) { ended = true; return result.ToArray(); }
                    foreach (byte value in buffer.AsSpan(0, count)) {
                        if (value == 10) { string stage = Classify(pending); if (stage != null) result.Add(stage); pending = ""; }
                        else { pending += value < 128 ? (char)value : '?'; if (pending.Length > 1024) pending = ""; }
                    }
                    Array.Clear(buffer, 0, buffer.Length);
                    read = pipe.ReadAsync(buffer, 0, buffer.Length);
                }
            } catch (TimeoutException) { }
              catch (IOException) { ended = true; }
            return result.ToArray();
        }
        public void Dispose() { pipe.Dispose(); pending = ""; Array.Clear(buffer, 0, buffer.Length); }
    }
    public static class Native {
        // IMAPI supplies IStream; copying in bounded chunks keeps seed contents off stdout.
        public static void SaveIso(object source, string destination) {
            var stream = (IStream)source;
            var count = Marshal.AllocCoTaskMem(sizeof(int));
            try {
                var buffer = new byte[65536];
                using (var file = new FileStream(destination, FileMode.CreateNew, FileAccess.Write)) {
                    while (true) {
                        stream.Read(buffer, buffer.Length, count);
                        int read = Marshal.ReadInt32(count);
                        if (read == 0) break;
                        file.Write(buffer, 0, read);
                    }
                    file.Flush(true);
                }
            } finally { Marshal.FreeCoTaskMem(count); }
        }

        private static ulong U64(byte[] bytes, int offset) {
            ulong value = 0; for (int i = 0; i < 8; i++) value = (value << 8) | bytes[offset + i]; return value;
        }
        private static uint U32(byte[] bytes, int offset) {
            uint value = 0; for (int i = 0; i < 4; i++) value = (value << 8) | bytes[offset + i]; return value;
        }
        private static void ReadExact(FileStream stream, byte[] bytes, long offset) {
            if (offset < 0 || offset > stream.Length - bytes.Length) throw new InvalidDataException("QCOW_OFFSET_INVALID");
            stream.Position = offset; int total = 0;
            while (total < bytes.Length) { int n = stream.Read(bytes, total, bytes.Length - total); if (n == 0) throw new EndOfStreamException(); total += n; }
        }
        // Read-only conversion of the pinned generic Ubuntu QCOW2 disk. Unsupported
        // features are refused; this is deliberately not a general QCOW editor.
        public static void QcowToRaw(string source, string destination) {
            using (var input = File.OpenRead(source)) {
                var header = new byte[104]; ReadExact(input, header, 0);
                uint version = U32(header, 4), bits = U32(header, 20);
                if (U32(header, 0) != 0x514649fb || (version != 2 && version != 3) || bits < 12 || bits > 21 ||
                    U64(header, 8) != 0 || U32(header, 32) != 0 || (version == 3 && U64(header, 72) != 0))
                    throw new InvalidDataException("QCOW_FEATURE_UNSUPPORTED");
                ulong size = U64(header, 24), tableOffset = U64(header, 40);
                uint entries = U32(header, 36);
                int cluster = 1 << (int)bits, l2Entries = cluster / 8;
                if (size < 1024 * 1024 || size > 64UL * 1024 * 1024 * 1024 || size % 512 != 0 || entries > 1024 * 1024)
                    throw new InvalidDataException("QCOW_SIZE_INVALID");
                if (entries < (size + (ulong)cluster * (ulong)l2Entries - 1) / ((ulong)cluster * (ulong)l2Entries))
                    throw new InvalidDataException("QCOW_L1_INVALID");
                var l1 = new byte[checked((int)entries * 8)]; ReadExact(input, l1, checked((long)tableOffset));
                var l2 = new byte[cluster]; var data = new byte[cluster]; long cached = -1;
                const ulong mask = 0x00fffffffffffe00UL;
                using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write)) {
                    output.SetLength((long)size);
                    for (ulong logical = 0; logical < size; logical += (ulong)cluster) {
                        ulong index = logical / (ulong)cluster;
                        ulong l1Value = U64(l1, checked((int)(index / (ulong)l2Entries) * 8));
                        if ((l1Value & ~(mask | (1UL << 63))) != 0) throw new InvalidDataException("QCOW_L1_FLAGS_INVALID");
                        ulong l2Offset = l1Value & mask; if (l2Offset == 0) continue;
                        if (l2Offset % (ulong)cluster != 0) throw new InvalidDataException("QCOW_L2_ALIGNMENT_INVALID");
                        if (cached != (long)l2Offset) { ReadExact(input, l2, checked((long)l2Offset)); cached = (long)l2Offset; }
                        ulong value = U64(l2, checked((int)(index % (ulong)l2Entries) * 8));
                        if ((value & (1UL << 62)) != 0) {
                            if ((value & (1UL << 63)) != 0) throw new InvalidDataException("QCOW_COMPRESSED_FLAGS_INVALID");
                            int shift = 62 - ((int)bits - 8);
                            ulong offset = value & ((1UL << shift) - 1);
                            int sectorsCount = (int)((value >> shift) & ((1UL << ((int)bits - 8)) - 1)) + 1;
                            var packed = new byte[sectorsCount * 512 - (int)(offset % 512)];
                            ReadExact(input, packed, checked((long)offset));
                            using (var compressed = new MemoryStream(packed))
                            using (var inflate = new DeflateStream(compressed, CompressionMode.Decompress)) {
                                int total = 0;
                                while (total < cluster) { int n = inflate.Read(data, total, cluster - total); if (n == 0) throw new InvalidDataException("QCOW_COMPRESSED_SIZE_INVALID"); total += n; }
                                if (inflate.ReadByte() != -1) throw new InvalidDataException("QCOW_COMPRESSED_SIZE_INVALID");
                            }
                            output.Position = (long)logical;
                            output.Write(data, 0, (int)Math.Min((ulong)cluster, size - logical));
                            continue;
                        }
                        if ((value & ~(mask | (1UL << 63) | 1UL)) != 0) throw new InvalidDataException("QCOW_CLUSTER_UNSUPPORTED");
                        if ((value & 1) != 0 || (value & mask) == 0) continue;
                        ulong dataOffset = value & mask;
                        if (dataOffset % (ulong)cluster != 0) throw new InvalidDataException("QCOW_DATA_ALIGNMENT_INVALID");
                        ReadExact(input, data, checked((long)dataOffset)); output.Position = (long)logical;
                        output.Write(data, 0, (int)Math.Min((ulong)cluster, size - logical));
                    }
                    output.Flush(true);
                }
            }
        }

        // A fixed VHD footer allows the built-in Hyper-V converter to import a
        // partitioned raw disk without installing a third-party disk utility.
        public static void RawToFixedVhd(string source, string destination) {
            long size = new FileInfo(source).Length;
            if (size < 1024 * 1024 || size % 512 != 0) throw new InvalidDataException("BASE_RAW_SIZE_INVALID");
            var footer = new byte[512];
            Action<int, byte[]> put = (offset, value) => Array.Copy(value, 0, footer, offset, value.Length);
            Action<int, uint> put32 = (offset, value) => { var b = BitConverter.GetBytes(value); Array.Reverse(b); put(offset, b); };
            Action<int, ulong> put64 = (offset, value) => { var b = BitConverter.GetBytes(value); Array.Reverse(b); put(offset, b); };
            put(0, Encoding.ASCII.GetBytes("conectix"));
            put32(8, 2); put32(12, 0x10000); put64(16, ulong.MaxValue);
            put32(24, 0); put(28, Encoding.ASCII.GetBytes("LDW7")); put32(32, 0x10000);
            put(36, Encoding.ASCII.GetBytes("Wi2k"));
            put64(40, (ulong)size); put64(48, (ulong)size);
            long sectors = Math.Min(size / 512, 65535L * 16 * 255);
            int sectorsPerTrack, heads; long cylinderTimesHeads;
            if (sectors >= 65535L * 16 * 63) { sectorsPerTrack = 255; heads = 16; cylinderTimesHeads = sectors / 255; }
            else {
                sectorsPerTrack = 17; cylinderTimesHeads = sectors / 17;
                heads = (int)((cylinderTimesHeads + 1023) / 1024); heads = Math.Max(heads, 4);
                if (cylinderTimesHeads >= heads * 1024 || heads > 16) { sectorsPerTrack = 31; heads = 16; cylinderTimesHeads = sectors / 31; }
                if (cylinderTimesHeads >= heads * 1024) { sectorsPerTrack = 63; heads = 16; cylinderTimesHeads = sectors / 63; }
            }
            int cylinders = (int)(cylinderTimesHeads / heads);
            footer[56] = (byte)(cylinders >> 8); footer[57] = (byte)cylinders;
            footer[58] = (byte)heads; footer[59] = (byte)sectorsPerTrack;
            put32(60, 2);
            put(68, Guid.NewGuid().ToByteArray());
            uint checksum = 0; foreach (byte value in footer) checksum += value;
            put32(64, ~checksum);
            using (var input = File.OpenRead(source))
            using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write)) {
                input.CopyTo(output); output.Write(footer, 0, footer.Length); output.Flush(true);
            }
        }
    }
}
