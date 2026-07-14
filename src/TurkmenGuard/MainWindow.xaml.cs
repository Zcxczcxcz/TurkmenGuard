using System.Windows;
using System.Windows.Controls;
using TurkmenGuard.ViewModels;

namespace TurkmenGuard;

public partial class MainWindow : Window
{
    private readonly ApplicationServices _services;
    private readonly MainViewModel _viewModel;

    public MainWindow(ApplicationServices services)
    {
        _services = services;
        _viewModel = new MainViewModel(services);

        InitializeComponent();
        DataContext = _viewModel;
        Title = Services.LocalizationService.AppTitle;

        _viewModel.ExitRequested += Close;
        _services.ShowMainWindowRequested += () =>
            Dispatcher.Invoke(() => { Show(); WindowState = WindowState.Normal; Activate(); });
        _services.ExitRequested += () => Dispatcher.Invoke(Close);

        // Navigation is driven entirely by the ViewModel's SelectedNav binding +
        // SelectedItem two-way sync, so keyboard navigation (arrows/Enter) works
        // without any mouse-event hacks.
        Closing += OnClosing;
    }

    private void NavList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is System.Windows.Controls.ListBox { SelectedItem: NavigationItem item })
            _viewModel.NavigateCommand.Execute(item);
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Soft, opt-in exit confirmation only (defaults to off). The app otherwise
        // closes like any ordinary desktop program.
        if (!_services.SelfProtection.CanClose(this))
            e.Cancel = true;
    }
}
