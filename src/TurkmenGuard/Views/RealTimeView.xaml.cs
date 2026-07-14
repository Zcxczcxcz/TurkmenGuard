using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard.Views;

public partial class RealTimeView : UserControl
{
    public RealTimeView(RealTimeViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
