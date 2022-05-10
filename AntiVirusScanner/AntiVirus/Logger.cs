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

        public void WriteAll(IEnumerable<string> strings)
        {
            File.WriteAllLines(_logPath, strings);
        }
        public void ClearLog()
        {
            File.WriteAllText(_logPath,"");
        }
        public void WriteSingle(string contents)
        {
            File.AppendAllText(_logPath, contents+"\n");
        }

    }
}
