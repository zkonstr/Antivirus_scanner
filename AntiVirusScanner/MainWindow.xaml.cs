using AntiVirusScanner;
using AntiVirusScanner.AntiVirus;
using System.Windows.Forms;
using System.Windows;
using System.Data;
using System.IO;
using System.Windows.Documents;

namespace AntiVirusScanner
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly Logger _logger = new Logger("log.txt");
        private readonly Scanner _scanner = new Scanner();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            var searchString = SearchBox.Text;
            if (searchString != null)
            {
                _logger.Write(_scanner.Scan(@"" + searchString));
                var _logText = File.ReadAllText("log.txt");
                LogRTB.Document = new FlowDocument(new Paragraph(new Run(_logText)));
            }
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();
            SearchBox.Text = dialog.SelectedPath.ToString();

        }
        
        
    }  
}
