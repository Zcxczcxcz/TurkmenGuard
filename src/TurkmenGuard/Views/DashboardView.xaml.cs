using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard.Views;

public partial class DashboardView : UserControl
{
    public DashboardView(DashboardViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
