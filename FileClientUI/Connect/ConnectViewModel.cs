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

        public string? serverIp;
        private ICommand? _connect;
        public string? serverPort;
        FileClient fileClient;

        public ConnectViewModel()
        {
            this.fileClient= new FileClient();
        }

        public string? ServerIp
        {
            get { return serverIp; }
            set { serverIp = value; OnPropertyChanged("ServerIp"); }
        }

        public string? ServerPort
        {
            get { return serverPort; }
            set { serverPort = value; OnPropertyChanged("ServerPort"); }
        }


        public ICommand Connect
        {
            get
            {
                if (_connect == null)
                {
                    _connect = new RelayCommand(param =>
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

                    }, param =>
                    {
                        return serverIp != "" && serverPort != "";
                    });
                }
                return _connect;
            }
  
        }




    }

}
