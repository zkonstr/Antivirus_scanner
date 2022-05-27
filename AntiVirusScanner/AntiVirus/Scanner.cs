using System.Collections.Generic;
using System.IO;
using System.Text;
using System;
using System.Diagnostics;
using System.ComponentModel;
using PeNet;
using PeNet.FileParser;
using System.Security.Permissions;
using System.Security.Principal;
using System.Reflection;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace AntiVirusScanner.AntiVirus
{
    public class Scanner
    {

        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;  // MZ
        const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00
        static IMAGE_DOS_HEADER GetDosHeader(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_DOS_HEADER>(stream);
        }

        static IMAGE_NT_HEADERS_COMMON GetCommonNtHeader(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS_COMMON>(stream);
        }

        private readonly Logger _logger = new Logger("log.txt");
        
        public void ScanPE(string folderPath)
        {
            _logger.ClearLog();
            if (Directory.Exists(folderPath))
            { 
                foreach (string file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        if (!PEExecutable(file)) { continue; }
                        _logger.WriteSingle(file);
                        GC.Collect();
                        GC.WaitForPendingFinalizers();

                }
                    catch (UnauthorizedAccessException e)
                    {
                        Console.WriteLine(e);
                        continue;
                    }
                }
            }
        }

        public void ScanHex(string folderPath,string[] vs)
        {
            if (string.IsNullOrEmpty(folderPath))
            {
                throw new ArgumentException($"\"{nameof(folderPath)}\" не может быть неопределенным или пустым.", nameof(folderPath));
            }

            _logger.ClearLog();
            if (Directory.Exists(folderPath))
            {
                
                
                foreach (string file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
                {
                    if (new FileInfo(file).Length != 0)
                    {
                        try
                        {
                            const int MAX_BUFFER = 20971520;
                            byte[] Buffer = new byte[MAX_BUFFER];
                            int BytesRead;
                            using (FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read))
                                while ((BytesRead = fileStream.Read(Buffer, 0, MAX_BUFFER)) != 0)
                                {
                                    var hexString = BitConverter.ToString(Buffer);
                                    hexString = hexString.Replace("-", "");


                                    if (HasSequence(hexString,vs))
                                    {
                                        _logger.WriteSingle(file);
                                        break;
                                    }
                                    GC.Collect();
                                    GC.WaitForPendingFinalizers();
                                }
                        }
                        catch (UnauthorizedAccessException e)
                        {
                            Console.WriteLine(e);
                            continue;
                        }
                        catch(IOException e)
                        {
                            Console.WriteLine(e);
                            continue;
                        }
                    }
                }
            }
        }
        private bool HasSequence(string buf,string[] vs)
        {
            
            var hasSeq = false;
            foreach(var virSeq in vs)
            {
                if (buf.Contains(virSeq))
                {
                    if(virSeq == "")continue;
                    hasSeq = true;
                    break;
                }
            }           
            return hasSeq;
        }

        

        private bool PEExecutable(string file) {
            bool isPe = false;
            if (!File.Exists(file))
                return false;

            try
            {
                using (var stream = File.OpenRead(file))
                {
                    IMAGE_DOS_HEADER dosHeader = GetDosHeader(stream);
                    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                        return false;
                    IMAGE_NT_HEADERS_COMMON ntHeader = GetCommonNtHeader(stream, dosHeader);
                    if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
                        return false;

                    isPe = true;

                }
            }
            catch (IOException e)
            {
                System.Console.WriteLine(e);
                return isPe;
                
            }
            return isPe;

        }
        static T ReadStructFromStream<T>(Stream stream)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            IntPtr memory = IntPtr.Zero;

            try
            {
                memory = Marshal.AllocCoTaskMem(structSize);
                if (memory == IntPtr.Zero)
                    throw new InvalidOperationException();

                byte[] buffer = new byte[structSize];
                int bytesRead = stream.Read(buffer, 0, structSize);
                //if (bytesRead != structSize)
                //    throw new InvalidOperationException();

                Marshal.Copy(buffer, 0, memory, structSize);

                return (T)Marshal.PtrToStructure(memory, typeof(T));
            }
            finally
            {
                if (memory != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(memory);
            }
        }
    }
}
