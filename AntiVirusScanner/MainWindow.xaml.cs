using AntiVirusScanner;
using AntiVirusScanner.AntiVirus;
using System.Windows;
using System.Data;
using System.IO;
using System.Windows.Documents;
using System.Windows.Controls;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;


namespace AntiVirusScanner
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    
    public partial class MainWindow : Window
    {
        public static void RelaunchIfNotAdmin()
        {
            if (!RunningAsAdmin())
            {
                Console.WriteLine("Running as admin required!");
                ProcessStartInfo proc = new ProcessStartInfo();
                proc.UseShellExecute = true;
                proc.WorkingDirectory = Environment.CurrentDirectory;
                proc.FileName = Assembly.GetEntryAssembly().CodeBase;
                proc.Verb = "runas";
                try
                {
                    Process.Start(proc);
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("This program must be run as an administrator! \n\n" + ex.ToString());
                    Environment.Exit(0);
                }
            }
        }

        private static bool RunningAsAdmin()
        {
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(id);

            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private readonly Scanner _scanner = new Scanner();
        public DBManager _DBManager = new DBManager();
        public MainWindow()
        {
            InitializeComponent();
            _DBManager.ConnectDB();

        }

        private void FolderButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();
            SearchBox.Text = dialog.SelectedPath.ToString();
        }
        bool isRunning = false;
        private void ScanButton_Click(object sender, RoutedEventArgs e)
        {

            if (!isRunning)
            {
                isRunning = true;
                string searchString = SearchBox.Text;
                if (!string.IsNullOrEmpty(searchString))
                {
                    LogLB.Items.Clear();
                    if (PEButton.IsChecked == true)
                    {
                        _scanner.ScanPE(@searchString);
                        var _logText = File.ReadAllText("log.txt").Split('\n');
                        foreach (string line in _logText)
                        {
                            LogLB.Items.Add(line);
                        }
                        int exes = _logText.Length - 1;
                        MessageBox.Show("Scan is done " + exes + " executable file(s) found");
                    }
                    if (HexButton.IsChecked == true)
                    {

                        string[] vs = _DBManager.GetVs().Split('\n');
                        _scanner.ScanHex(@searchString,vs);
                        var _logText = File.ReadAllText("log.txt").Split('\n');
                        foreach (string line in _logText)
                        {
                            LogLB.Items.Add(line);
                        }
                        int hasVS = _logText.Length - 1;
                        MessageBox.Show("Scan is done " + hasVS + " file(s) has virus sequences");
                    }
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                isRunning = false;
            }
            else
            {
                ScanButton.IsEnabled = false;
            }
            
        }
        private void DBButton_Click(object sender, RoutedEventArgs e)
        {
            string s = _DBManager.GetVs();
            MessageBox.Show(s);
        }
    }
}

