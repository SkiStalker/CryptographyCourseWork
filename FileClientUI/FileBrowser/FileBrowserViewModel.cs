using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Client;

namespace FileClientUI
{
    internal class FileBrowserViewModel : ObservableObject, IPageViewModel
    {
        private FileClient? fileClient;

        public string Name => "File Browser";


        public void SetFileClient(FileClient fileClient)
        {
            this.fileClient = fileClient;
        }

    }
}
