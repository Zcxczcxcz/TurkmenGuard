using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard.Views;

public partial class QuarantineView : UserControl
{
    public QuarantineView(QuarantineViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
