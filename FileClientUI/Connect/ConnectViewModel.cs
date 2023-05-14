using Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace FileClientUI
{
    internal class ConnectViewModel : ObservableObject, IPageViewModel
    {
        public string Name => "Connect";

        private string? serverIp;
        private ICommand? connect;
        private string? serverPort;
        private readonly FileClient fileClient;

        public ConnectViewModel()
        {
            this.fileClient = new FileClient();
        }

        public string? ServerIp
        {
            get => serverIp;
            set
            {
                serverIp = value;
                OnPropertyChanged("ServerIp");
            }
        }

        public string? ServerPort
        {
            get => serverPort;
            set
            {
                serverPort = value;
                OnPropertyChanged("ServerPort");
            }
        }


        public ICommand Connect
        {
            get
            {
                return connect ??= new RelayCommand(param =>
                {
                    try
                    {
                        fileClient.Connect(serverIp ?? "", int.Parse(serverPort ?? ""));
                        Messenger.Default.Send(fileClient);
                    }
                    catch
                    {
                        MessageBox.Show("Can not connect to server");
                    }
                }, param => !string.IsNullOrEmpty(serverIp) && !string.IsNullOrEmpty(serverPort));
            }
        }
    }
}