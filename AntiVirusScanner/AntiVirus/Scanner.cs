using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AntiVirusScanner.AntiVirus
{
    public class Scanner
    {
        private const string EXE_PREFIX = "MZ";


        public IEnumerable<string> Scan(string folderPath)
        {
            foreach (string file in Directory.EnumerateFiles(folderPath))
            {
                string contentsPrefix = ReadPrefix(file, EXE_PREFIX.Length);
                if (!Executable(contentsPrefix))
                {
                    continue;
                }
                yield return Path.GetFileName(file);
            }
        }

        private bool Executable(string contentsPrefix)
        {
            return !(contentsPrefix is null) && contentsPrefix == EXE_PREFIX;
        }

        private string ReadPrefix(string filename, int n)
        {
            byte[] bytes = new byte[n];
            using (BinaryReader reader = new BinaryReader(new FileStream(filename, FileMode.Open)))
            {
                reader.Read(bytes, 0, n);
            }
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
