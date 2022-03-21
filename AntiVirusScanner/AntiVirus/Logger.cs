using System.Collections.Generic;
using System.IO;

namespace AntiVirusScanner.AntiVirus
{
    public class Logger
    {
        private static string _logPath;

        public Logger(string loggerPath)
        {
            _logPath = loggerPath;
        }

        public void Write(IEnumerable<string> strings)
        {
            File.WriteAllLines(_logPath, strings);
        }
    }
}
