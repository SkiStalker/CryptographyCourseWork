using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Client;
using Microsoft.VisualBasic.CompilerServices;
using Microsoft.Win32;

namespace FileClientUI
{
    internal class FileBrowserViewModel : ObservableObject, IPageViewModel
    {
        private string? selectedFile;
        private FileClient? fileClient;
        private RelayCommand? refreshCommand;
        private RelayCommand? updateCommand;
        private RelayCommand? downloadCommand;
        private RelayCommand? uploadCommand;
        private RelayCommand? deleteCommand;
        private string[] files;
        private Visibility cryptoActive;
        private int curCryptoProgress;
        private int maxCryptoProgress;

        public Visibility CryptoActive
        {
            get => cryptoActive;
            set
            {
                cryptoActive = value;
                OnPropertyChanged("CryptoActive");
                OnPropertyChanged("NotCryptoActive");
                OnPropertyChanged("IsFileSelected");
            }
        }

        public bool NotCryptoActive => CryptoActive != Visibility.Visible;

        public int CurrentCryptoProgress
        {
            get => curCryptoProgress;
            set
            {
                curCryptoProgress = value;
                OnPropertyChanged("CurrentCryptoProgress");
            }
        }

        public int MaxCryptoProgress
        {
            get => maxCryptoProgress;
            set
            {
                maxCryptoProgress = value;
                OnPropertyChanged("MaxCryptoProgress");
            }
        }

        public string? SelectedFile
        {
            get => selectedFile;
            set
            {
                selectedFile = value;

                OnPropertyChanged("SelectedFile");
                OnPropertyChanged("IsFileSelected");
            }
        }

        public string Name => "File Browser";
        public bool IsFileSelected => !string.IsNullOrEmpty(selectedFile) && NotCryptoActive;


        public string[] Files
        {
            get => files;
            set
            {
                files = value;
                OnPropertyChanged("Files");
            }
        }


        public RelayCommand RefreshCommand
        {
            get { return refreshCommand ??= new RelayCommand(obj => { RefreshFilesList(); }); }
        }

        public RelayCommand UpdateCommand
        {
            get { return updateCommand ??= new RelayCommand(obj => { UpdateFile(); }); }
        }

        public RelayCommand DownloadCommand
        {
            get { return downloadCommand ??= new RelayCommand(obj => { DownloadFile(); }); }
        }

        public RelayCommand UploadCommand
        {
            get { return uploadCommand ??= new RelayCommand(obj => { UploadFile(); }); }
        }

        public RelayCommand DeleteCommand
        {
            get { return deleteCommand ??= new RelayCommand(obj => { DeleteFile(); }); }
        }

        public FileBrowserViewModel()
        {
            Files = Array.Empty<string>();
            CryptoActive = Visibility.Collapsed;
            CurrentCryptoProgress = 0;
            MaxCryptoProgress = 100;
        }

        ~FileBrowserViewModel()
        {
            fileClient?.Dispose();
        }

        private bool CheckConnection()
        {
            if (fileClient == null)
            {
                MessageBox.Show("Internal error: broken server connection");
                return false;
            }

            return true;
        }

        private void UpdateFile()
        {
            if (CheckConnection())
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.FileName = Path.GetFileNameWithoutExtension(selectedFile ?? "");
                openFileDialog.DefaultExt = Path.GetExtension(selectedFile ?? "txt");
                openFileDialog.Filter = "All files |*";
                if (openFileDialog.ShowDialog() ?? false)
                {
                    byte[] fileBytes = File.ReadAllBytes(openFileDialog.FileName);

                    CryptoActive = Visibility.Visible;
                    CurrentCryptoProgress = 0;
                    bool res = fileClient.UpdateFile(SelectedFile ?? "", fileBytes, out string? answer);

                    CryptoActive = Visibility.Collapsed;

                    if (res)
                    {
                        MessageBox.Show(answer ?? "Success");
                    }
                    else
                    {
                        MessageBox.Show(answer ?? "Error");
                    }
                }
            }
        }

        private void RefreshFilesList()
        {
            if (CheckConnection())
            {
                CryptoActive = Visibility.Visible;
                CurrentCryptoProgress = 0;
                bool res = this.fileClient.GetFilesList(out string[]? filesList, out string? answer);
                CryptoActive = Visibility.Collapsed;
                if (res)
                {
                    if (filesList == null)
                    {
                        MessageBox.Show("Null received files list");
                    }
                    else
                    {
                        Files = filesList;
                    }
                }
                else
                {
                    MessageBox.Show(answer ?? "Error");
                }
            }
        }

        private void DownloadFile()
        {
            if (CheckConnection())
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog();
                saveFileDialog.FileName = Path.GetFileNameWithoutExtension(selectedFile ?? "");
                saveFileDialog.DefaultExt = Path.GetExtension(selectedFile ?? "txt");
                saveFileDialog.Filter = "All files |*";
                if (saveFileDialog.ShowDialog() ?? false)
                {
                    CryptoActive = Visibility.Visible;
                    CurrentCryptoProgress = 0;
                    bool res = fileClient.DownloadFile(selectedFile ?? "", out byte[]? data, out string? answer);
                    CryptoActive = Visibility.Collapsed;
                    if (res)
                    {
                        File.WriteAllBytes(saveFileDialog.FileName, data ?? Array.Empty<byte>());
                        MessageBox.Show(answer ?? "Success");
                    }
                    else
                    {
                        MessageBox.Show(answer ?? "Error");
                    }
                }
            }
        }

        private void DeleteFile()
        {
            if (CheckConnection())
            {
                CryptoActive = Visibility.Visible;
                CurrentCryptoProgress = 0;
                bool res = fileClient.DeleteFile(selectedFile ?? "", out string? answer);
                CryptoActive = Visibility.Collapsed;
                if (res)
                {
                    RefreshFilesList();
                    MessageBox.Show(answer ?? "Success");
                }
                else
                {
                    MessageBox.Show(answer ?? "Error");
                }
            }
        }

        private void UploadFile()
        {
            if (CheckConnection())
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Filter = "All files |*";
                if (openFileDialog.ShowDialog() ?? false)
                {
                    byte[] data = File.ReadAllBytes(openFileDialog.FileName);

                    CryptoActive = Visibility.Visible;
                    CurrentCryptoProgress = 0;

                    bool res = fileClient.UploadFile(Path.GetFileName(openFileDialog.FileName), data,
                        out string? answer);

                    CryptoActive = Visibility.Collapsed;
                    if (res)
                    {
                        RefreshFilesList();
                        MessageBox.Show(answer ?? "Success");
                    }
                    else
                    {
                        MessageBox.Show(answer ?? "Error");
                    }
                }
            }
        }

        public void SetFileClient(FileClient newFileClient)
        {
            this.fileClient = newFileClient;
            fileClient.AddCryptCallback((cur, max) =>
            {
                CurrentCryptoProgress = cur;
                MaxCryptoProgress = max;
            });
            RefreshFilesList();
        }

        public FileClient? GetFileClient()
        {
            return this.fileClient;
        }
    }
}