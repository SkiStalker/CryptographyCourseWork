using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Input;
using Client;

namespace FileClientUI
{
    public class ApplicationViewModel : ObservableObject
    {
        private ICommand? _changePageCommand;

        private IPageViewModel? _currentPageViewModel;
        private List<IPageViewModel>? _pageViewModels;

        public ApplicationViewModel()
        {
            PageViewModels.Add(new ConnectViewModel());

            FileBrowserViewModel fbvm = new FileBrowserViewModel();
            Messenger.Default.Register<FileClient>(fbvm, (obj) => { ChangeViewModel(fbvm); fbvm.SetFileClient(obj); });
            PageViewModels.Add(fbvm);
            CurrentPageViewModel = PageViewModels[0];
        }


        public ICommand ChangePageCommand
        {
            get
            {
                if (_changePageCommand == null)
                {
                    _changePageCommand = new RelayCommand(
                        p => ChangeViewModel((IPageViewModel)p),
                        p => p is IPageViewModel);
                }

                return _changePageCommand;
            }
        }

        public List<IPageViewModel> PageViewModels
        {
            get
            {
                if (_pageViewModels == null)
                    _pageViewModels = new List<IPageViewModel>();

                return _pageViewModels;
            }
        }

        public IPageViewModel? CurrentPageViewModel
        {
            get
            {
                return _currentPageViewModel;
            }
            set
            {
                if (_currentPageViewModel != value)
                {
                    _currentPageViewModel = value;
                    OnPropertyChanged("CurrentPageViewModel");
                }
            }
        }

        private void ChangeViewModel(IPageViewModel viewModel)
        {
            if (!PageViewModels.Contains(viewModel))
                PageViewModels.Add(viewModel);



            CurrentPageViewModel = PageViewModels
                .FirstOrDefault(vm => vm == viewModel);
        }
    }
}
