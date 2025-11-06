using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using NativeProcesses.Core;

namespace ProcessDemo
{
    public partial class MainForm : Form
    {
        private ProcessService _service;
        private BindingList<ProcessInfoViewModel> _allProcessItems;
        private ContextMenuStrip _menu;
        private ContextMenuStrip _menuThread;
        private bool isInitialLoad = true;
        private List<ProcessInfoViewModel> initialLoadBatch = new List<ProcessInfoViewModel>();

        public MainForm()
        {
            InitializeComponent();
            this.DoubleBuffered = true;
            DarkTitleBarHelper.Apply(this);

            SetupFilterBar();

            SetupGrid();
            SetupThreadGrid();

            SetupMenu();
            LoadProcesses();
        }

        private void SetupFilterBar()
        {
            lblFilter.Text = "Filter:";
            lblFilter.ForeColor = Color.AliceBlue;
            lblFilter.Padding = new Padding(5, 4, 5, 0);
            lblFilter.AutoSize = true;

            edtFilter.ForeColor = Color.White;
            edtFilter.BackColor = Color.FromArgb(45, 45, 48);
            edtFilter.TextChanged += edtFilter_TextChanged;
            edtFilter.BorderStyle = BorderStyle.FixedSingle;
        }

        private void edtFilter_TextChanged(object sender, EventArgs e)
        {
            ApplyFilter();
        }

        private void Binding_ListChanged(object sender, ListChangedEventArgs e)
        {
            if (e.ListChangedType == ListChangedType.ItemAdded ||
                e.ListChangedType == ListChangedType.ItemDeleted ||
                e.ListChangedType == ListChangedType.Reset)
            {
                if (grid.DataSource == _allProcessItems)
                {
                    this.Text = $"Processes: {_allProcessItems.Count}";
                }
            }
        }

        private void SetupGrid()
        {
            EnableGridDoubleBuffering(grid);
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AutoGenerateColumns = true;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.EnableHeadersVisualStyles = false;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(45, 45, 48);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            grid.ColumnHeadersDefaultCellStyle.Font = new Font(this.Font, FontStyle.Bold);
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(240, 240, 240);

            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0, 120, 215);
            grid.DefaultCellStyle.SelectionForeColor = Color.White;

            grid.RowHeadersVisible = false;
            grid.BorderStyle = BorderStyle.None;
            grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.GridColor = Color.Gainsboro;

            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;

            grid.SelectionChanged += Grid_SelectionChanged;
        }

        private void SetupThreadGrid()
        {
            EnableGridDoubleBuffering(gridThreads);
            gridThreads.Dock = DockStyle.Fill;
            gridThreads.ReadOnly = true;
            gridThreads.AutoGenerateColumns = true;
            gridThreads.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            gridThreads.AllowUserToAddRows = false;
            gridThreads.AllowUserToDeleteRows = false;
            gridThreads.EnableHeadersVisualStyles = false;
            gridThreads.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(60, 60, 60);
            gridThreads.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            gridThreads.ColumnHeadersDefaultCellStyle.Font = new Font(this.Font, FontStyle.Regular);
            gridThreads.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(245, 245, 245);

            gridThreads.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0, 120, 215);
            gridThreads.DefaultCellStyle.SelectionForeColor = Color.White;

            gridThreads.RowHeadersVisible = false;
            gridThreads.BorderStyle = BorderStyle.None;
            gridThreads.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            gridThreads.GridColor = Color.Gainsboro;

            gridThreads.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        }


        private void Grid_SelectionChanged(object sender, EventArgs e)
        {
            var p = SelectedProcess;
            if (p != null)
            {
                gridThreads.DataSource = p.Threads;
            }
            else
            {
                gridThreads.DataSource = null;
            }
        }

        private void SetupMenu()
        {
            _menu = new ContextMenuStrip();
            _menu.Items.Add("Kill", null, (s, e) => KillSelected());
            _menu.Items.Add("Suspend", null, (s, e) => SuspendSelected());
            _menu.Items.Add("Resume", null, (s, e) => ResumeSelected());
            grid.ContextMenuStrip = _menu;

            _menuThread = new ContextMenuStrip();
            _menuThread.Items.Add("Suspend Thread", null, (s, e) => SuspendSelectedThread());
            _menuThread.Items.Add("Resume Thread", null, (s, e) => ResumeSelectedThread());
            gridThreads.ContextMenuStrip = _menuThread;
        }

        private void InitialLoadTimer_Tick(object sender, EventArgs e)
        {
            (sender as Timer).Stop();
            try
            {
                grid.SuspendLayout();
                foreach (var item in initialLoadBatch)
                {
                    _allProcessItems.Add(item);
                }

                _allProcessItems.RaiseListChangedEvents = true;
                _allProcessItems.ResetBindings();
            }
            finally
            {
                grid.ResumeLayout();
                initialLoadBatch = null;
                isInitialLoad = false;
            }
        }

        //private void LoadProcesses()
        //{
        //    var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
        //    var logger = new ConsoleLogger(richTextBox1);

        //    var detailOptions = new NativeProcesses.ProcessDetailOptions
        //    {
        //        LoadSignatureInfo = true,
        //        LoadMitigationInfo = true,
        //        LoadExePathAndCommandLine = true,
        //        LoadFileVersionInfo = true,
        //        LoadIoCounters = true,
        //        LoadSecurityInfo = true
        //    };

        //    // Hier kannst du jetzt steuern, was geladen wird:
        //    // detailOptions.LoadSignatureInfo = false; // <-- Z.B. Zertifikate deaktivieren

        //    _service = new ProcessService(provider, detailOptions, logger);

        //    _allProcessItems = new BindingList<ProcessInfoViewModel>();
        //    _allProcessItems.ListChanged += Binding_ListChanged;

        //    _allProcessItems.RaiseListChangedEvents = false;
        //    grid.DataSource = _allProcessItems;

        //    _service.ProcessAdded += Service_ProcessAdded;
        //    _service.ProcessRemoved += Service_ProcessRemoved;
        //    _service.ProcessUpdated += Service_ProcessUpdated;

        //    _service.Start();

        //    Timer initialLoadTimer = new Timer();
        //    initialLoadTimer.Interval = 1000;
        //    initialLoadTimer.Tick += InitialLoadTimer_Tick;
        //    initialLoadTimer.Start();
        //}
        private void LoadProcesses()
        {
            var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
            var logger = new ConsoleLogger(richTextBox1);

            var detailOptions = new NativeProcesses.ProcessDetailOptions
            {
                LoadSignatureInfo = true,
                LoadMitigationInfo = true,
                LoadExePathAndCommandLine = true,
                LoadFileVersionInfo = true,
                LoadIoCounters = true,
                LoadSecurityInfo = true
            };

            _service = new ProcessService(provider, logger);
            _service.DetailOptions = detailOptions;

            _allProcessItems = new BindingList<ProcessInfoViewModel>();
            _allProcessItems.ListChanged += Binding_ListChanged;

            _allProcessItems.RaiseListChangedEvents = false;
            grid.DataSource = _allProcessItems;

            _service.ProcessAdded += Service_ProcessAdded;
            _service.ProcessRemoved += Service_ProcessRemoved;
            _service.ProcessUpdated += Service_ProcessUpdated;

            _service.Start();

            Timer initialLoadTimer = new Timer();
            initialLoadTimer.Interval = 1000;
            initialLoadTimer.Tick += InitialLoadTimer_Tick;
            initialLoadTimer.Start();
        }
        private void EnableGridDoubleBuffering(DataGridView dgv)
        {
            typeof(DataGridView)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(dgv, true, null);
        }

        private void ApplyFilter()
        {
            string filterText = edtFilter.Text.ToLowerInvariant().Trim();
            grid.SuspendLayout();
            gridThreads.DataSource = null;

            if (string.IsNullOrEmpty(filterText))
            {
                grid.DataSource = null;
                grid.DataSource = _allProcessItems;
                this.Text = $"Processes: {_allProcessItems.Count}";
                lblFilter.Text = "Filter:";
            }
            else
            {
                var filteredList = _allProcessItems.Where(p =>
                        (p.Name != null && p.Name.ToLowerInvariant().Contains(filterText)) ||
                        (p.ExePath != null && p.ExePath.ToLowerInvariant().Contains(filterText)) ||
                        p.Pid.ToString().Contains(filterText)
                    ).ToList();
                grid.DataSource = null;
                grid.DataSource = filteredList;

                lblFilter.Text = $"Filter: ({filteredList.Count})";
                this.Text = $"Processes: {filteredList.Count}";
            }

            grid.ResumeLayout();

            if (grid.Rows.Count > 0)
            {
                grid.Rows[0].Selected = true;
            }
            Grid_SelectionChanged(this, EventArgs.Empty);
        }

        private void Service_ProcessAdded(FullProcessInfo info)
        {
            var newItem = new ProcessInfoViewModel(info);

            if (isInitialLoad)
            {
                if (initialLoadBatch != null)
                {
                    lock (initialLoadBatch)
                    {
                        initialLoadBatch.Add(newItem);
                    }
                }
                return;
            }

            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Service_ProcessAdded(info)));
                return;
            }

            if (!_allProcessItems.Any(p => p.Pid == newItem.Pid))
            {
                _allProcessItems.Add(newItem);
            }
        }

        private void Service_ProcessRemoved(int pid)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Service_ProcessRemoved(pid)));
                return;
            }

            var processToRemove = _allProcessItems.FirstOrDefault(p => p.Pid == pid);
            if (processToRemove != null)
            {
                _allProcessItems.Remove(processToRemove);
            }
        }

        private void Service_ProcessUpdated(FullProcessInfo info)
        {
            if (isInitialLoad)
            {
                return;
            }

            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Service_ProcessUpdated(info)));
                return;
            }

            var itemToUpdate = _allProcessItems.FirstOrDefault(p => p.Pid == info.Pid);
            if (itemToUpdate != null)
            {
                itemToUpdate.ApplyUpdate(info);
            }
        }

        private ProcessInfoViewModel SelectedProcess
        {
            get
            {
                if (grid.SelectedRows.Count == 0)
                    return null;
                return grid.SelectedRows[0].DataBoundItem as ProcessInfoViewModel;
            }
        }

        private ThreadInfoViewModel SelectedThread
        {
            get
            {
                if (gridThreads.SelectedRows.Count == 0)
                    return null;
                return gridThreads.SelectedRows[0].DataBoundItem as ThreadInfoViewModel;
            }
        }

        private void KillSelected()
        {
            var p = SelectedProcess;
            if (p == null) return;
            if (ProcessManager.Kill(p.Pid))
                MessageBox.Show($"{p.Name} beendet");
            else
                MessageBox.Show($"Fehler beim Beenden von {p.Name}");
        }

        private void SuspendSelected()
        {
            var p = SelectedProcess;
            if (p == null) return;
            if (ProcessManager.Suspend(p.Pid))
                MessageBox.Show($"{p.Name} angehalten");
            else
                MessageBox.Show($"Fehler beim Anhalten von {p.Name}");
        }

        private void ResumeSelected()
        {
            var p = SelectedProcess;
            if (p == null) return;
            if (ProcessManager.Resume(p.Pid))
                MessageBox.Show($"{p.Name} fortgesetzt");
            else
                MessageBox.Show($"Fehler beim Fortsetzen von {p.Name}");
        }

        private void SuspendSelectedThread()
        {
            var t = SelectedThread;
            if (t == null) return;
            try
            {
                using (var thread = new ManagedThread(t.ThreadId, ManagedThread.ThreadAccessFlags.SuspendResume))
                {
                    thread.Suspend();
                    MessageBox.Show($"Thread {t.ThreadId} angehalten.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fehler beim Anhalten von Thread {t.ThreadId}: {ex.Message}");
            }
        }

        private void ResumeSelectedThread()
        {
            var t = SelectedThread;
            if (t == null) return;
            try
            {
                using (var thread = new ManagedThread(t.ThreadId, ManagedThread.ThreadAccessFlags.SuspendResume))
                {
                    thread.Resume();
                    MessageBox.Show($"Thread {t.ThreadId} fortgesetzt.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fehler beim Fortsetzen von Thread {t.ThreadId}: {ex.Message}");
            }
        }


        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _service?.Stop();
            _service?.Dispose();
            base.OnFormClosing(e);
        }

        private void MainForm_Shown(object sender, EventArgs e)
        {
            DarkTitleBarHelper.Apply(this);
            Application.DoEvents();
        }
    }

    public class ConsoleLogger : IEngineLogger
    {
        private RichTextBox _richTextBox;
        public ConsoleLogger(RichTextBox richTextBox)
        {
            _richTextBox = richTextBox;
        }

        public void Log(LogLevel level, string message, Exception ex = null)
        {
            return;
        }
    }
}