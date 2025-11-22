using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace BeaconKiller
{
    internal class EtwTraceCtx
    {
        internal const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 6;

        readonly Dictionary<int, ProcessCtx> processes = new Dictionary<int, ProcessCtx>();
        readonly Dictionary<string, ImageSymbol> symbols = new Dictionary<string, ImageSymbol>();
        readonly FieldInfo _eventRecordField;


        public EtwTraceCtx()
        {
            _eventRecordField = typeof(TraceEvent).GetField("eventRecord", BindingFlags.NonPublic | BindingFlags.Instance);
        }
        public bool TryGetProcess(int pid,out ProcessCtx processCtx)
        {
            return processes.TryGetValue(pid, out processCtx);
        }
        unsafe internal StackData GetKernelCallStack(int pid, long TimeStampQPC, StackWalkStackTraceData s)
        {
            // 先找到进程，没有进程无法获取堆栈对应的Image名称
            if (!processes.TryGetValue(pid, out var p))
            {
                return null;
            }

            // 判断最后一次的堆栈是否是当前事件
            if (s != null && s.EventTimeStampQPC == TimeStampQPC)
            {
                var sd = new StackData(s);
                if (sd.Addresses.Length == 0)
                {
                    return null;
                }
                processes.TryGetValue(0, out ProcessCtx kp);
                sd.FixAddressNames(p, kp, symbols);
                return sd;
            }
            return null;

        }
        unsafe internal StackData GetCallStack(TraceEvent e)
        {
            // 先找到进程，没有进程无法获取堆栈对应的Image名称
            if (!processes.TryGetValue(e.ProcessID, out var p))
            {
                return null;
            }

            // 用户模式事件
            // 根据eventRecord->ExtendedDataCount循环eventRecord->ExtendedData
            // 获取ExtType是TraceEventNativeMethods.EVENT_HEADER_EXT_TYPE_STACK_TRACE64(6)
            var eventRecord = (EVENT_RECORD*)Pointer.Unbox(_eventRecordField.GetValue(e));

            if (eventRecord->ExtendedDataCount == 0)
            {
                return null;
            }
            for (int i = 0; i < eventRecord->ExtendedDataCount; i++)
            {
                var extendedData = &eventRecord->ExtendedData[i];
                if (extendedData->ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
                {
                    continue;
                }
                var length = (extendedData->DataSize - 8) / 8;
                var addrs = new ulong[length];
                for (int j = 0; j < length; j++)
                {
                    var addr = extendedData->DataPtr->Address[j];
                    addrs[j] = addr;
                }
                var sd = new StackData(addrs);
                if (sd.Addresses.Length == 0)
                {
                    return null;
                }
                processes.TryGetValue(0, out ProcessCtx kp);
                sd.FixAddressNames(p, kp, symbols);
                return sd;
            }

            return null;
        }
        internal string GetProcessName(TraceEvent e)
        {
            if (processes.TryGetValue(e.ProcessID, out var p))
            {
                return p.Name;
            }
            return e.ProcessName;
        }
        internal void OnProcessStart(ProcessTraceData obj)
        {
            processes[obj.ProcessID] = new ProcessCtx(obj.ProcessID, obj.ImageFileName, obj.CommandLine);
        }
        internal void OnProcessStop(ProcessTraceData obj)
        {
            processes.Remove(obj.ProcessID);
        }
        internal void OnImageLoad(ImageLoadTraceData data)
        {
            var image = new Image(data);
            if (processes.TryGetValue(data.ProcessID, out var p))
            {
                p.AddImage(image);
            }
            var filepath = data.FileName.ToLower();
            if (!symbols.ContainsKey(filepath))
            {
                try
                {
                    symbols[filepath] = new ImageSymbol(data.FileName);
                }
                catch
                {

                }
            }



        }
        internal void OnImageUnload(ImageLoadTraceData data)
        {
            if (!processes.TryGetValue(data.ProcessID, out var p))
            {
                return;
            }
            p.RemoveImage(data.ImageBase);
        }

    }
#pragma warning disable 0649
    internal struct EVENT_HEADER
    {
        public ushort Size;

        public ushort HeaderType;

        public ushort Flags;

        public ushort EventProperty;

        public int ThreadId;

        public int ProcessId;

        public long TimeStamp;

        public Guid ProviderId;

        public ushort Id;

        public byte Version;

        public byte Channel;

        public byte Level;

        public byte Opcode;

        public ushort Task;

        public ulong Keyword;

        public uint KernelTime;

        public uint UserTime;

        public Guid ActivityId;
    }
    internal struct ETW_BUFFER_CONTEXT
    {
        public byte ProcessorNumber;

        public byte Alignment;

        public ushort LoggerId;
    }
    internal unsafe struct EVENT_HEADER_EXTENDED_DATA_ITEM
    {
        public ushort Reserved1;

        public ushort ExtType;

        public ushort Reserved2;

        public ushort DataSize;

        public EventExtendedItemStackTrace64* DataPtr;
    }
    internal struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;

        public ETW_BUFFER_CONTEXT BufferContext;

        public ushort ExtendedDataCount;

        public ushort UserDataLength;

        public unsafe EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData;

        public IntPtr UserData;

        public IntPtr UserContext;
    }
    internal unsafe struct EventExtendedItemStackTrace64
    {
        // MatchID represents the unique identifier that you use to match
        // the kernel-mode calls to the user-mode calls; the kernel-mode
        // calls and user-mode calls are captured in separate events if
        // the environment prevents both from being captured in the same event.
        // If the kernel-mode and user-mode calls were captured in the same event,
        // the value is zero.
        public ulong MatchID;
        // Address is an array of call addresses on the stack.
        public fixed ulong Address[1];
    }
#pragma warning restore 0649
    internal class StackData
    {
        private readonly ulong[] _addrs;
        private bool _unbacked = false;
        private string[] _names = null;
        public StackData(ulong[] addrs_, long eventTimeStampQPC = -1)
        {
            EventTimeStampQPC = eventTimeStampQPC;
            var addrs = new List<ulong>();
            foreach (ulong addr in addrs_)
            {
                // 过滤掉内核地址
                //if (addr >= 0x800000000000 || (addr < 0x100000000 && addr >= 0x80000000))
                //{
                //    continue;
                //}
                addrs.Add(addr);

            }
            _addrs = addrs.ToArray();
        }
        public StackData(StackWalkStackTraceData e)
        {
            EventTimeStampQPC = e.EventTimeStampQPC;
            var addrs = new List<ulong>();
            for (int i = 0; i < e.FrameCount; i++)
            {
                var addr = e.InstructionPointer(i);
                // 过滤掉内核地址

                addrs.Add(addr);
            }
            _addrs = addrs.ToArray();
        }
        public ulong[] Addresses => _addrs;
        public string[] AddressNames => _names;
        internal string[] FixAddressNames(ProcessCtx p, ProcessCtx kp, Dictionary<string, ImageSymbol> symbols)
        {

            var names = new string[Addresses.Length];
            for (int i = 0; i < Addresses.Length; i++)
            {
                var addr = Addresses[i];
                if (addr >= 0x800000000000 || (addr < 0x100000000 && addr >= 0x80000000))
                {
                    if (kp != null)
                    {
                        // 内核地址，使用内核的ImageSymbol
                        names[i] = kp.Images.Addr2ImageString(addr, symbols, out var _);
                    }
                    else
                    {
                        names[i] = $"UnknowKernel!0x{addr:X8}";
                    }
                }
                else
                {
                    names[i] = p.Images.Addr2ImageString(addr, symbols, out var hasImage);
                    if (!hasImage)
                    {
                        _unbacked = true;
                    }
                }

            }
            _names = names;
            return names;

        }
        public bool Unbacked => _unbacked;
        public long EventTimeStampQPC { get; private set; }

    }
    internal class ImageSymbol
    {
        readonly SortedList<ulong, string> symbols;
        readonly ulong[] keys;
        public ImageSymbol(string filePath)
        {
            symbols = new SortedList<ulong, string>();
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (var reader = new BinaryReader(fs))
            {
                // 读取DOS头
                var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(reader);
                if (dosHeader.e_magic != 0x5A4D) // "MZ"
                    return;

                // 定位到NT头
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                if (reader.ReadUInt32() != 0x00004550) // "PE\0\0"
                    return;

                // 读取文件头
                var fileHeader = ReadStruct<IMAGE_FILE_HEADER>(reader);

                bool is32Bit = true;
                ushort optionalHeaderMagic = reader.ReadUInt16();
                fs.Seek(-2, SeekOrigin.Current); // 回退以便读取整个可选头

                if (optionalHeaderMagic == 0x20B) // PE32+
                {
                    is32Bit = false;
                }
                // 读取可选头
                IMAGE_DATA_DIRECTORY exportDir;
                if (is32Bit)
                {
                    IMAGE_OPTIONAL_HEADER32 optionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER32>(reader);
                    if (optionalHeader.AddressOfEntryPoint != 0)
                    {
                        symbols[optionalHeader.AddressOfEntryPoint] = "EntryPoint";
                    }
                    exportDir = optionalHeader.DataDirectory[0]; // 导出表是第一个数据目录
                }
                else
                {
                    IMAGE_OPTIONAL_HEADER64 optionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER64>(reader);
                    if (optionalHeader.AddressOfEntryPoint != 0)
                    {
                        symbols[optionalHeader.AddressOfEntryPoint] = "EntryPoint";
                    }
                    exportDir = optionalHeader.DataDirectory[0]; // 导出表是第一个数据目录
                }
                // 读取可选头


                if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
                    return;

                // 读取节区头
                var sections = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int i = 0; i < sections.Length; i++)
                    sections[i] = ReadStruct<IMAGE_SECTION_HEADER>(reader);

                // 定位导出表
                var exportSection = FindSection(sections, exportDir.VirtualAddress);
                if (exportSection == null)
                    return;

                fs.Seek(exportSection.Value.PointerToRawData + (exportDir.VirtualAddress - exportSection.Value.VirtualAddress), SeekOrigin.Begin);
                var exportDirectory = ReadStruct<IMAGE_EXPORT_DIRECTORY>(reader);

                // 读取函数地址表
                var functionsSection = FindSection(sections, exportDirectory.AddressOfFunctions);
                if (functionsSection == null)
                    return;

                fs.Seek(functionsSection.Value.PointerToRawData + (exportDirectory.AddressOfFunctions - functionsSection.Value.VirtualAddress), SeekOrigin.Begin);
                var functionAddresses = new uint[exportDirectory.NumberOfFunctions];
                for (int i = 0; i < functionAddresses.Length; i++)
                    functionAddresses[i] = reader.ReadUInt32();

                // 读取名称表（如果有）
                if (exportDirectory.NumberOfNames > 0)
                {
                    var namesSection = FindSection(sections, exportDirectory.AddressOfNames);
                    var ordinalsSection = FindSection(sections, exportDirectory.AddressOfNameOrdinals);

                    if (namesSection != null && ordinalsSection != null)
                    {
                        var namePointers = new uint[exportDirectory.NumberOfNames];
                        var nameOrdinals = new ushort[exportDirectory.NumberOfNames];

                        // 读取名称指针
                        fs.Seek(namesSection.Value.PointerToRawData + (exportDirectory.AddressOfNames - namesSection.Value.VirtualAddress), SeekOrigin.Begin);
                        for (int i = 0; i < namePointers.Length; i++)
                            namePointers[i] = reader.ReadUInt32();

                        // 读取序号
                        fs.Seek(ordinalsSection.Value.PointerToRawData + (exportDirectory.AddressOfNameOrdinals - ordinalsSection.Value.VirtualAddress), SeekOrigin.Begin);
                        for (int i = 0; i < nameOrdinals.Length; i++)
                            nameOrdinals[i] = reader.ReadUInt16();

                        // 读取名称并关联到函数
                        for (int i = 0; i < namePointers.Length; i++)
                        {
                            var nameSection = FindSection(sections, namePointers[i]);
                            if (nameSection != null)
                            {
                                fs.Seek(nameSection.Value.PointerToRawData + (namePointers[i] - nameSection.Value.VirtualAddress), SeekOrigin.Begin);
                                var name = ReadNullTerminatedString(reader);
                                var ordinal = nameOrdinals[i];
                                if (ordinal < functionAddresses.Length)
                                {
                                    var rva = functionAddresses[ordinal];
                                    if (rva != 0) // 跳过空项
                                        symbols[rva] = name;
                                }
                            }
                        }
                    }
                }

                // 添加没有名称的函数（仅序号）
                for (int i = 0; i < functionAddresses.Length; i++)
                {
                    var rva = functionAddresses[i];
                    if (rva != 0 && !symbols.ContainsKey(rva))
                        symbols[rva] = $"#{i + exportDirectory.Base}";
                }
                keys = symbols.Keys.ToArray();
            }
        }
        public string ToSymbol(ulong RVA)
        {
            if (keys != null)
            {
                var index = Array.BinarySearch(keys, RVA);

                if (index < 0)
                {
                    index = ~index;
                    if (index > 0)
                        index--;
                }
                if (index >= 0)
                {
                    var addr = keys[index];
                    if (RVA >= addr)
                    {
                        var name = symbols.Values[index];
                        var offset = RVA - addr;
                        return $"{name}+0x{offset:X}";
                    }

                }

            }

            return $"0x{RVA:X}";

        }
        private static IMAGE_SECTION_HEADER? FindSection(IMAGE_SECTION_HEADER[] sections, uint rva)
        {
            foreach (var section in sections)
            {
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                    return section;
            }
            return null;
        }

        private static string ReadNullTerminatedString(BinaryReader reader)
        {
            var bytes = new List<byte>();
            byte b;
            while ((b = reader.ReadByte()) != 0)
                bytes.Add(b);
            return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
        }

        private static T ReadStruct<T>(BinaryReader reader) where T : struct
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T structure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return structure;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;    // Magic number
            public ushort e_cblp;    // Bytes on last page of file
            public ushort e_cp;      // Pages in file
            public ushort e_crlc;    // Relocations
            public ushort e_cparhdr; // Size of header in paragraphs
            public ushort e_minalloc; // Minimum extra paragraphs needed
            public ushort e_maxalloc; // Maximum extra paragraphs needed
            public ushort e_ss;      // Initial (relative) SS value
            public ushort e_sp;      // Initial SP value
            public ushort e_csum;    // Checksum
            public ushort e_ip;      // Initial IP value
            public ushort e_cs;      // Initial (relative) CS value
            public ushort e_lfarlc;  // File address of relocation table
            public ushort e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;  // Reserved words
            public ushort e_oemid;   // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo; // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;  // Reserved words
            public int e_lfanew;     // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }
    }

    internal class Image
    {
        private readonly string _imageName;
        private readonly ulong _imageBase;
        private readonly int _imageSize;
        public Image(string imageName, ulong imageBase, int imageSize)
        {
            _imageName = imageName;
            _imageBase = imageBase;
            _imageSize = imageSize;
        }

        public Image(ImageLoadTraceData d)
        {
            _imageBase = d.ImageBase;
            _imageName = d.FileName;
            _imageSize = d.ImageSize;
        }
        public string ImageName => _imageName;
        public ulong ImageBase => _imageBase;
        public int ImageSize => _imageSize;
    }
    internal class Images : SortedList<ulong, Image>
    {
        public void Add(Image image)
        {
            this[image.ImageBase] = image;
        }
        public void Delete(Image image)
        {
            Remove(image.ImageBase);
        }
        public void Delete(ulong imageBase)
        {
            Remove(imageBase);
        }
        public Image FindImage(ulong address)
        {
            var keys = Keys;
            int left = 0;
            int right = keys.Count - 1;
            int result = -1; // 初始化为无效索引

            while (left <= right)
            {
                int mid = left + (right - left) / 2;

                if (keys[mid] == address)
                {
                    result = mid;
                    break;
                }
                else if (keys[mid] < address)
                {
                    result = mid;
                    left = mid + 1;
                }
                else
                {
                    right = mid - 1;
                }
            }
            if (result == -1)
            {
                return null;
            }
            var image = Values[result];
            if (address > image.ImageBase + (ulong)image.ImageSize)
            {
                return null;
            }
            return image;
        }
        public string Addr2ImageString(ulong address, Dictionary<string, ImageSymbol> symbols, out bool hasImage)
        {
            var image = FindImage(address);
            if (image == null)
            {
                hasImage = false;
                return $"0x{address:X8}";
            }
            hasImage = true;
            string sym;
            if (symbols.TryGetValue(image.ImageName.ToLower(), out var symbol))
            {
                sym = symbol.ToSymbol(address - image.ImageBase);
            }
            else
            {
                sym = $"0x{address - image.ImageBase:X}";
            }

            return $"{Path.GetFileName(image.ImageName)}!{sym}";

        }

    }
    internal class ProcessCtx
    {
        public int PID { get; private set; }
        public string CommandLine { get; set; }
        public string Name { get; private set; }
        public Images Images { get; private set; }
        public SortedSet<string> ImagesNames { get; private set; }
        public ProcessCtx(int pid, string name, string commandLine)
        {
            PID = pid;
            Name = name;
            Images = new Images();
            ImagesNames = new SortedSet<string>();
            CommandLine = commandLine;
        }
        public void AddImage(Image image)
        {
            Images.Add(image);
            ImagesNames.Add(Path.GetFileName(image.ImageName.ToLower()));
        }
        public void RemoveImage(ulong imageBase)
        {
            Images.Delete(imageBase);
        }
        public bool HasAnyImage(string[] imageNames)
        {
            foreach (string imageName in imageNames) {
                if (ImagesNames.Contains(imageName.ToLower()))
                {
                    return true;
                }
            }
            return false;
            
        }
    }
}
