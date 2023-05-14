using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace FileClientUI
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected ApplicationView? app;
        ApplicationViewModel? context;
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            app = new ApplicationView();
            context = new ApplicationViewModel();
            app.DataContext = context;
            app.Show();
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            if (context?.CurrentPageViewModel is FileBrowserViewModel fbvModel)
            {
                await Task.WhenAny(Task.Run(() => fbvModel.GetFileClient()?.CloseConnection(out string? answer)), Task.Delay(1000));
                fbvModel.GetFileClient()?.Dispose();
            }

            base.OnExit(e);
        }
    }
}
