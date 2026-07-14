using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard.Views;

public partial class ScanView : UserControl
{
    public ScanView(ScanViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
