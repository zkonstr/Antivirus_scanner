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
            _logger.Write(_scanner.Scan(@"C:\Users\zkons\Downloads"));  
        }

        private void TitleTB_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            
        }
    }
}
