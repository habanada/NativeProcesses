using NativeProcesses.Core;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Native;
using NativeProcesses.Core;
using NativeProcesses.Core.Providers;
using processlist;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using NativeProcesses.Core.Models;
using System.Threading.Tasks;

namespace ProcessDemo
{
    public partial class MainForm : Form
    {
        private ProcessService _service;
        private BindingList<ProcessInfoViewModel> _allProcessItems;
        private ContextMenuStrip _menu;
        private ContextMenuStrip _menuThread;
        //private bool isInitialLoad = true;
        //private List<ProcessInfoViewModel> initialLoadBatch = new List<ProcessInfoViewModel>();
        private IEngineLogger _logger;
        private ProcessMonitorEngine _monitorEngine;

        private Button btnNetwork;

        public MainForm()
        {
            InitializeComponent();
            this.DoubleBuffered = true;
            DarkTitleBarHelper.Apply(this);
            this.KeyPreview = true;
            this.KeyDown += new KeyEventHandler(this.MainForm_KeyDown);
            SetupFilterBar();

            SetupGrid();
            SetupThreadGrid();

            SetupMenu();
            LoadProcesses();
        }
        private void MainForm_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F3)
            {
                e.SuppressKeyPress = true;
                ShowUwpPackageInfo_Click();
            }
            if (e.KeyCode == Keys.F4)
            {
                e.SuppressKeyPress = true;
                ShowWindowsForSelectedProcess();
            }
            if (e.KeyCode == Keys.F5)
            {
                e.SuppressKeyPress = true;
                ShowModulesForSelectedProcess();
            }
            else if (e.KeyCode == Keys.F6)
            {
                e.SuppressKeyPress = true;
                ShowHandlesForSelectedProcess();
            }
            else if (e.KeyCode == Keys.F7)
            {
                e.SuppressKeyPress = true;
                ShowPrioritiesForSelectedThread();
            }
            else if (e.KeyCode == Keys.F8)
            {
                e.SuppressKeyPress = true;
                ResolveSelectedThreadAddress();
            }
            else if (e.KeyCode == Keys.F9)
            {
                e.SuppressKeyPress = true;
                ShowMemoryRegionsForSelectedProcess();
            }
            else if (e.KeyCode == Keys.F10)
            {
                e.SuppressKeyPress = true;
                ShowDotNetHeapForSelectedProcess();
            }
            else if (e.KeyCode == Keys.F11)
            {
                e.SuppressKeyPress = true;
                ShowDotNetExceptionsForSelectedProcess();
            }
            else if (e.KeyCode == Keys.F12)
            {
                e.SuppressKeyPress = true;
                ShowDotNetGcRootsForSelectedProcess();
            }
        }
        private async void ShowDotNetHeapForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var heapStats = await ProcessManager.GetDotNetHeapStatsAsync(p.Pid, _logger);
                long totalObjects = heapStats.Sum(s => s.Count);

                using (var detailForm = new DetailForm($".NET Heap Stats: {p.Name} ({p.Pid}) ({totalObjects} Objects)", heapStats, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET heap for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetExceptionsForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var exceptions = await ProcessManager.GetDotNetHeapExceptionsAsync(p.Pid, _logger);

                using (var detailForm = new DetailForm($".NET Exceptions on Heap: {p.Name} ({p.Pid}) ({exceptions.Count()} found)", exceptions, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET heap for exceptions (PID {p.Pid}):\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
            private async void ShowWindowsForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var windows = await ProcessManager.GetWindowsAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($"Windows for {p.Name} ({p.Pid})", windows, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load windows for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetGcRootsForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var roots = await ProcessManager.GetDotNetGcRootsAsync(p.Pid, _logger);

                using (var detailForm = new DetailForm($".NET GC Roots: {p.Name} ({p.Pid}) ({roots.Count()} roots found)", roots, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET GC roots for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetFinalizerQueueForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var finalizerQueue = await ProcessManager.GetDotNetFinalizerQueueAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($".NET Finalizer Queue: {p.Name} ({p.Pid}) ({finalizerQueue.Count()} objects)", finalizerQueue, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET Finalizer Queue for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetAppDomains_Click()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var domains = await ProcessManager.GetDotNetAppDomainsAsync(p.Pid, _logger);

                var displayData = domains.Select(d => new
                {
                    d.Id,
                    d.Name,
                    d.Address,
                    d.ConfigFile,
                    d.ApplicationBase,
                    LoadedAssemblies = string.Join(", ", d.LoadedAssemblies.ToArray())
                }).ToList();

                using (var detailForm = new DetailForm($".NET AppDomains: {p.Name} ({p.Pid})", displayData, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET AppDomains for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetAllHeapStrings_Click()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var stats = await ProcessManager.GetDotNetAllHeapStringsAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($".NET Heap Strings: {p.Name} ({p.Pid})", stats, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET heap strings for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetStringDuplicates_Click()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var stats = await ProcessManager.GetDotNetStringDuplicatesAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($".NET String Duplicates: {p.Name} ({p.Pid})", stats, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET string duplicates for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetThreadPoolForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var tpInfo = await ProcessManager.GetDotNetThreadPoolAsync(p.Pid, _logger);

                var list = new List<DotNetThreadPoolInfo> { tpInfo };

                using (var detailForm = new DetailForm($".NET ThreadPool: {p.Name} ({p.Pid})", list, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET ThreadPool for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private void ShowUwpPackageInfo_Click()
        {
            var p = SelectedProcess;
            if (p == null) return;

            if (!p.IsPackagedApp)
            {
                MessageBox.Show(this, "This is not a packaged (UWP/MSIX) application.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var uwpInfo = UwpManager.GetPackageInfo(p.PackageFullName);

                var list = new System.Collections.Generic.List<UwpPackageInfo> { uwpInfo };

                using (var detailForm = new DetailForm($"UWP Package Info: {p.Name}", list, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load UWP package info for {p.PackageFullName}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowPrioritiesForSelectedThread()
        {
            var t = SelectedThread;
            if (t == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var info = await ProcessManager.GetExtendedThreadInfoAsync(t.ThreadId, _logger);

                string message = $"Thread: {info.ThreadId}\n\n";
                message += $"I/O Priority: {info.IoPriority}\n";
                message += $"Memory Priority: {info.MemoryPriority}";

                MessageBox.Show(this, message, "Thread Priorities", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load priorities for TID {t.ThreadId}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowModulesForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var modules = await ProcessManager.GetModulesAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($"Modules for {p.Name} ({p.Pid})", modules, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load modules for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }

        private async void ShowHandlesForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var handles = await ProcessManager.GetHandlesAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($"Handles for {p.Name} ({p.Pid})", handles, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load handles for PID {p.Pid}:\n{ex.Message}\n\n(This often requires administrative privileges.)", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
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

            btnNetwork = new Button();
            btnNetwork.Text = "Network";
            btnNetwork.Dock = DockStyle.Right;
            btnNetwork.Width = 80;
            btnNetwork.ForeColor = Color.White;
            btnNetwork.BackColor = Color.FromArgb(60, 60, 60);
            btnNetwork.FlatStyle = FlatStyle.Flat;
            btnNetwork.Click += ShowNetworkConnections_Click;
            panel1.Controls.Add(btnNetwork);
        }
        private async void ShowNetworkConnections_Click(object sender, EventArgs e)
        {
            this.Cursor = Cursors.WaitCursor;
            try
            {
                var connections = await ProcessManager.GetNetworkConnectionsAsync(_logger);
                using (var detailForm = new DetailForm("System Network Connections", connections, -1))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load network connections:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
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


        private async void Grid_SelectionChanged(object sender, EventArgs e)
        {
            var p = SelectedProcess;
            if (p != null)
            {
                gridThreads.DataSource = p.Threads;
                if (!p.AreModulesLoadingOrLoaded)
                {
                    await LoadModulesForProcess(p);
                }
                else
                {
                    ResolveThreadAddresses(p);
                }
            }
            else
            {
                gridThreads.DataSource = null;
            }
            if (p != null)
            {
                _monitorEngine.Subscribe(p.Pid, ProcessMetric.CpuUsage);
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
            _menuThread.Items.Add("-");
            _menu.Items.Add("Show Windows (F4)", null, (s, e) => ShowWindowsForSelectedProcess());
            _menu.Items.Add("Show Modules (F5)", null, (s, e) => ShowModulesForSelectedProcess());
            _menu.Items.Add("Show Handles (F6)", null, (s, e) => ShowHandlesForSelectedProcess());

            _menu.Items.Add("Show Memory Regions (F9)", null, (s, e) => ShowMemoryRegionsForSelectedProcess());
            _menu.Items.Add("-");
            _menu.Items.Add("Show .NET Heap Stats (F10)", null, (s, e) => ShowDotNetHeapForSelectedProcess());
            _menu.Items.Add("Show .NET Exceptions (F11)", null, (s, e) => ShowDotNetExceptionsForSelectedProcess());
            _menu.Items.Add("Show .NET GC Roots (F12)", null, (s, e) => ShowDotNetGcRootsForSelectedProcess());
            _menu.Items.Add("Show .NET Locks & Blocks", null, (s, e) => ShowDotNetLockingInfoForSelectedProcess());
            _menu.Items.Add("Show .NET Finalizer Queue", null, (s, e) => ShowDotNetFinalizerQueueForSelectedProcess());
            _menu.Items.Add("Show .NET ThreadPool", null, (s, e) => ShowDotNetThreadPoolForSelectedProcess());
            _menu.Items.Add("Show .NET String Duplicates", null, (s, e) => ShowDotNetStringDuplicates_Click());
            _menu.Items.Add("Show All Heap Strings", null, (s, e) => ShowDotNetAllHeapStrings_Click());
            _menu.Items.Add("Show .NET AppDomains/Assemblies", null, (s, e) => ShowDotNetAppDomains_Click());
            _menu.Items.Add("Show UWP Package Info (F3)", null, (s, e) => ShowUwpPackageInfo_Click());

            _menuThread.Items.Add("Show Priorities (F7)", null, (s, e) => ShowPrioritiesForSelectedThread());
            _menuThread.Items.Add("Resolve Start Address (F8)", null, (s, e) => ResolveSelectedThreadAddress());
            _menuThread.Items.Add("Show Managed Stack", null, (s, e) => ShowManagedStackForSelectedThread());
            gridThreads.ContextMenuStrip = _menuThread;
        }

        //private void InitialLoadTimer_Tick(object sender, EventArgs e)
        //{
        //    (sender as Timer).Stop();
        //    try
        //    {
        //        grid.SuspendLayout();
        //        foreach (var item in initialLoadBatch)
        //        {
        //            _allProcessItems.Add(item);
        //        }

        //        _allProcessItems.RaiseListChangedEvents = true;
        //        _allProcessItems.ResetBindings();
        //    }
        //    finally
        //    {
        //        grid.ResumeLayout();
        //        initialLoadBatch = null;
        //        isInitialLoad = false;
        //    }
        //}
        private async Task LoadModulesForProcess(ProcessInfoViewModel p)
        {
            p.SetModules(new List<NativeProcesses.Core.Models.ProcessModuleInfo>());

            try
            {
                var modules = await ProcessManager.GetModulesAsync(p.Pid, _logger);
                p.SetModules(modules);
                ResolveThreadAddresses(p);
            }
            catch (Exception ex)
            {
            }
        }

        private void ResolveThreadAddresses(ProcessInfoViewModel p)
        {
            if (p.Modules == null || p.Modules.Count == 0)
                return;

            foreach (var t in p.Threads)
            {
                if (t.StartAddress == IntPtr.Zero)
                {
                    t.StartAddressSymbol = "N/A";
                    continue;
                }

                string resolvedName = "0x" + t.StartAddress.ToString("X");
                bool found = false;

                foreach (var mod in p.Modules)
                {
                    if (mod.SizeOfImage == 0)
                        continue;

                    IntPtr start = mod.DllBase;
                    IntPtr end = IntPtr.Add(start, (int)mod.SizeOfImage);

                    if (t.StartAddress.ToInt64() >= start.ToInt64() && t.StartAddress.ToInt64() < end.ToInt64())
                    {
                        long offset = t.StartAddress.ToInt64() - start.ToInt64();
                        resolvedName = $"{mod.BaseDllName}+0x{offset:X}";
                        found = true;
                        break;
                    }
                }

                t.StartAddressSymbol = resolvedName;
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
        private async void ShowMemoryRegionsForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var regions = await ProcessManager.GetVirtualMemoryRegionsAsync(p.Pid, _logger);
                using (var detailForm = new DetailForm($"Memory Regions for {p.Name} ({p.Pid})", regions, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not load memory regions for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowDotNetLockingInfoForSelectedProcess()
        {
            var p = SelectedProcess;
            if (p == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var locks = await ProcessManager.GetDotNetLockingInfoAsync(p.Pid, _logger);

                using (var detailForm = new DetailForm($".NET Locks: {p.Name} ({p.Pid}) ({locks.Count} contended locks)", locks, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not analyze .NET locks for PID {p.Pid}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ShowManagedStackForSelectedThread()
        {
            var p = SelectedProcess;
            var t = SelectedThread;
            if (p == null || t == null) return;

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var stack = await ProcessManager.GetDotNetThreadStackAsync(p.Pid, t.ThreadId, _logger);

                using (var detailForm = new DetailForm($".NET Stack: {p.Name} (TID {t.ThreadId})", stack, p.Pid))
                {
                    detailForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not get managed stack for TID {t.ThreadId}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private async void ResolveSelectedThreadAddress()
        {
            var p = SelectedProcess;
            var t = SelectedThread;
            if (p == null || t == null)
            {
                return;
            }

            if (t.StartAddress == IntPtr.Zero)
            {
                MessageBox.Show(this, $"Thread {t.ThreadId} has no valid start address (0x0).", "Resolve Address", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var modules = await ProcessManager.GetModulesAsync(p.Pid, _logger);
                string resolvedName = "0x" + t.StartAddress.ToString("X");
                bool found = false;

                foreach (var mod in modules)
                {
                    if (mod.SizeOfImage == 0)
                    {
                        continue;
                    }

                    IntPtr start = mod.DllBase;
                    IntPtr end = IntPtr.Add(start, (int)mod.SizeOfImage);

                    if (t.StartAddress.ToInt64() >= start.ToInt64() && t.StartAddress.ToInt64() < end.ToInt64())
                    {
                        long offset = t.StartAddress.ToInt64() - start.ToInt64();
                        resolvedName = $"{mod.BaseDllName}+0x{offset:X}";
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    resolvedName += " (No module found for this address range)";
                }

                MessageBox.Show(this, $"Thread: {t.ThreadId}\nStart Address: {resolvedName}", "Resolve Address", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not resolve address for TID {t.ThreadId}:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private void LoadProcesses()
        {
            // Schritt 1: Provider auf Hybrid umstellen (Polling für CPU/Mem, ETW für I/O, Start/Stop)
            var provider = new HybridProcessProvider(
                new PollingProcessProvider(TimeSpan.FromSeconds(1)), // Liefert CPU/Speicher
                new EtwProcessProvider() // Liefert Echtzeit-Events (Start/Stop, I/O, Netzwerk, PageFaults)
            );

            // Schritt 2: Logger instanziieren (wie im Original)
            _logger = new ConsoleLogger(richTextBox1);

            // Schritt 3: DetailOptions (wie im Original)
            var detailOptions = new ProcessDetailOptions
            {
                LoadSignatureInfo = true,
                LoadMitigationInfo = true,
                LoadExePathAndCommandLine = true,
                LoadFileVersionInfo = true,
                LoadIoCounters = true,
                LoadSecurityInfo = true,
                LoadModules = false,
                LoadHandles = false
            };

            // Schritt 4: ProcessService instanziieren (wie im Original)
            _service = new ProcessService(provider, _logger, detailOptions);

            // Schritt 5: ProcessMonitorEngine instanziieren (NEU, aus Schritt 3.3)
            _monitorEngine = new ProcessMonitorEngine(_service, _logger);
            _monitorEngine.MetricChanged += MonitorEngine_MetricChanged;
            _monitorEngine.Start();

            // Schritt 6: UI-Binding (Bereinigt von 'isInitialLoad'-Bug, aus Schritt 5.5)
            _allProcessItems = new BindingList<ProcessInfoViewModel>();
            _allProcessItems.ListChanged += Binding_ListChanged;
            grid.DataSource = _allProcessItems;

            // Schritt 7: Alle Events abonnieren (Volatile-Event NEU, aus Schritt 5.4)
            _service.ProcessAdded += Service_ProcessAdded;
           _service.ProcessRemoved += Service_ProcessRemoved;
            _service.ProcessUpdated += Service_ProcessUpdated; // Für statische Daten (ExePath, Signer...)
            _service.ProcessVolatileUpdated += Service_ProcessVolatileUpdated; // Für CPU, RAM, I/O...

            // Schritt 8: Service starten (Veraltete Timer-Logik entfernt, aus Schritt 5.5)
            _service.Start();
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
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Service_ProcessAdded(info)));
                return;
            }

            try
            {
                if (!_allProcessItems.Any(p => p.Pid == info.Pid))
                {
                    var newItem = new ProcessInfoViewModel(info);
                    _allProcessItems.Add(newItem);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, "Service_ProcessAdded failed.", ex);
            }
        }
        //private void Service_ProcessAdded(FullProcessInfo info)
        //{
        //    var newItem = new ProcessInfoViewModel(info);

        //    if (isInitialLoad)
        //    {
        //        if (initialLoadBatch != null)
        //        {
        //            lock (initialLoadBatch)
        //            {
        //                initialLoadBatch.Add(newItem);
        //            }
        //        }
        //        return;
        //    }

        //    if (InvokeRequired)
        //    {
        //        BeginInvoke(new Action(() => Service_ProcessAdded(info)));
        //        return;
        //    }

        //    if (!_allProcessItems.Any(p => p.Pid == newItem.Pid))
        //    {
        //        _allProcessItems.Add(newItem);
        //    }
        //}

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
            //if (isInitialLoad)
            //{
            //    return;
            //}

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
        private void Service_ProcessVolatileUpdated(ProcessVolatileUpdate update)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => Service_ProcessVolatileUpdated(update)));
                return;
            }

            var itemToUpdate = _allProcessItems.FirstOrDefault(p => p.Pid == update.Pid);
            if (itemToUpdate != null)
            {
                itemToUpdate.ApplyVolatileUpdate(update);
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
            _monitorEngine?.Stop();
            _service?.Stop();
            _service?.Dispose();
            base.OnFormClosing(e);

        }

        private void MainForm_Shown(object sender, EventArgs e)
        {
            DarkTitleBarHelper.Apply(this);
            Application.DoEvents();
        }
        private void MonitorEngine_MetricChanged(object sender, ProcessMetricChangeEventArgs e)
        {
            if (richTextBox1.InvokeRequired)
            {
                richTextBox1.BeginInvoke(new Action(() => MonitorEngine_MetricChanged(sender, e)));
                return;
            }

            try
            {
                string text = $"[MonitorEngine] PID {e.Pid} - {e.Metric}: {e.NewValue}\n";
                richTextBox1.AppendText(text);
                richTextBox1.ScrollToCaret();
            }
            catch (Exception)
            {
            }
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