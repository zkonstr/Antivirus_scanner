using AntiVirusScanner;
using AntiVirusScanner.AntiVirus;
using System.Windows;


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

        private void Button_Click(object sender, RoutedEventArgs e)
        {

            var searchString = SearchBox.Text;
            if (searchString != null) _logger.Write(_scanner.Scan(@"" + searchString));
            
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();
            SearchBox.Text = dialog.SelectedPath.ToString();
          
        }
    }
}
