using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard.Views;

public partial class SettingsView : UserControl
{
    public SettingsView(SettingsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
