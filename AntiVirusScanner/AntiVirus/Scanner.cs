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

namespace AntiVirusScanner.AntiVirus
{
    public class Scanner
    {
        
        private const string EXE_PREFIX = "MZ";
        private readonly Logger _logger = new Logger("log.txt");
        public void ScanMZ(string folderPath)
        {
            
            

            _logger.ClearLog();               
            foreach (string file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                    try
                    {

                    string contentsPrefix = ReadPrefix(file, EXE_PREFIX.Length);
                    if (!MZExecutable(contentsPrefix)) { continue; }

                    _logger.WriteSingle(Path.GetFileName(file));

                    }
                    catch (System.UnauthorizedAccessException e)
                    {
                    System.Console.WriteLine(e);
                    continue;
                    
                    }
            }
            
        }
        
        public void ScanPE(string folderPath)
        {
            _logger.ClearLog();
            foreach (string file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                try
                {

                    if (!PEExecutable(file)) { continue; }

                    _logger.WriteSingle(Path.GetFileName(file));

                }
                catch (System.UnauthorizedAccessException e)
                {
                    System.Console.WriteLine(e);
                    continue;

                }
            }

        }

        private bool MZExecutable(string contentsPrefix)
        {
            return !(contentsPrefix is null) && contentsPrefix == EXE_PREFIX;
        }//old one, only check MZ prefix

        private bool PEExecutable(string file) {
            //StreamReader reader = new StreamReader(file);
            //var isPe = PeFile.IsPeFile(file);
            var isPe = false;
            var buff = File.ReadAllBytes(file);
            isPe = PeFile.TryParse(buff, out var peFile);
            if (isPe) isPe = peFile.IsExe;
            return isPe;
        }//new one, check PE signature

        private string ReadPrefix(string filename, int n)
        {
            byte[] bytes = new byte[n];
            
                using (BinaryReader reader = new BinaryReader(new FileStream(filename, FileMode.Open)))
                {
                    reader.Read(bytes, 0x00, n);
                }
            
            
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
