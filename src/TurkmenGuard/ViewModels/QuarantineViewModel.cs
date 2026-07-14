using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TurkmenGuard.Quarantine;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class QuarantineViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;

    [ObservableProperty] private List<QuarantineEntry> _entries = [];
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _refreshLabel = "";
    [ObservableProperty] private string _restoreLabel = "";
    [ObservableProperty] private string _deleteLabel = "";
    [ObservableProperty] private string _colFile = "";
    [ObservableProperty] private string _colThreat = "";
    [ObservableProperty] private string _colMethod = "";
    [ObservableProperty] private string _colDate = "";

    public QuarantineViewModel(ApplicationServices services)
    {
        _services = services;
        RefreshLabels();
        Refresh();
        _services.Quarantine.QuarantineChanged += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(Refresh));
        LocalizationService.LanguageChanged += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(RefreshLabels));
    }

    private void RefreshLabels()
    {
        Title = LocalizationService.Get("NavQuarantine");
        RefreshLabel = LocalizationService.Get("Refresh");
        RestoreLabel = LocalizationService.Get("Restore");
        DeleteLabel = LocalizationService.Get("Delete");
        ColFile = LocalizationService.Get("ColFile");
        ColThreat = LocalizationService.Get("ColThreat");
        ColMethod = LocalizationService.Get("ColMethod");
        ColDate = LocalizationService.Get("ColDate");
    }

    [RelayCommand]
    private void Refresh() => Entries = _services.Quarantine.Entries.ToList();

    [RelayCommand]
    private void Restore(QuarantineEntry? entry)
    {
        if (entry == null) return;
        if (System.Windows.MessageBox.Show(
                LocalizationService.Get("ConfirmRestore"),
                LocalizationService.AppTitle,
                System.Windows.MessageBoxButton.YesNo) != System.Windows.MessageBoxResult.Yes)
            return;

        if (!_services.Quarantine.Restore(entry.Id))
            System.Windows.MessageBox.Show(
                LocalizationService.Get("RestoreFailed"),
                LocalizationService.AppTitle,
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
        Refresh();
    }

    [RelayCommand]
    private void Delete(QuarantineEntry? entry)
    {
        if (entry == null) return;
        if (System.Windows.MessageBox.Show(
                LocalizationService.Get("ConfirmDelete"),
                LocalizationService.AppTitle,
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            return;

        if (!_services.Quarantine.DeletePermanently(entry.Id))
            System.Windows.MessageBox.Show(
                LocalizationService.Get("DeleteFailed"),
                LocalizationService.AppTitle,
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
        Refresh();
    }
}
