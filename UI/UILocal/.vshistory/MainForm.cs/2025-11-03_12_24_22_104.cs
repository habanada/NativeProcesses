using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using NativeProcesses;

namespace ProcessDemo
{
    public partial class MainForm : Form
    {
        private ProcessService _service;
        private BindingList<FullProcessInfo> _allProcessItems;
        private BindingSource _filteredBindingSource;
        private ContextMenuStrip _menu;
        private bool isInitialLoad = true;
        private List<FullProcessInfo> initialLoadBatch = new List<FullProcessInfo>();
        // +++ NEUE VIEW-KLASSE +++
        // Diese Klasse enthält nur die sicheren Daten für das Grid.
        private class ProcessInfoView
        {
            public int Pid { get; set; }
            public string Name { get; set; }
            public string ExePath { get; set; }
            // Fügen Sie hier weitere "sichere" Eigenschaften hinzu,
            // die Sie im Grid anzeigen möchten (z.B. CpuUsage).
        }

        public MainForm()
        {
            InitializeComponent();
            DarkTitleBarHelper.Apply(this);
            this.DoubleBuffered = true; // HIER HINZUFÜGEN
            SetupFilterBar();
            SetupGrid();
            SetupMenu();
            LoadProcesses();
        }

        private void SetupFilterBar()
        {
            lblFilter.Text = "Filter:";
            lblFilter.ForeColor = Color.AliceBlue;
            lblFilter.Padding = new Padding(5, 4, 5, 0);
            lblFilter.AutoSize = true;

            edtFilter.ForeColor = Color.Black;
            edtFilter.TextChanged += edtFilter_TextChanged;
            edtFilter.BorderStyle = BorderStyle.FixedSingle;
           // edtFilter.BackColor = Color.DimGray;
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
                this.Text = $"Processes: {_allProcessItems.Count}";
            }
        }

        private void SetupGrid()
        {
            EnableGridDoubleBuffering();
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

            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells;
        }

        private void SetupMenu()
        {
            _menu = new ContextMenuStrip();
            _menu.Items.Add("Kill", null, (s, e) => KillSelected());
            _menu.Items.Add("Suspend", null, (s, e) => SuspendSelected());
            _menu.Items.Add("Resume", null, (s, e) => ResumeSelected());
            grid.ContextMenuStrip = _menu;
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
        private void LoadProcesses()
        {
            var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
            var logger = new ConsoleLogger(richTextBox1);
            _service = new ProcessService(provider, logger);

            _allProcessItems = new BindingList<FullProcessInfo>();
            _allProcessItems.ListChanged += Binding_ListChanged;

            _allProcessItems.RaiseListChangedEvents = false; // UPDATES DEAKTIVIEREN

            grid.DataSource = _allProcessItems;

            _service.ProcessAdded += Service_ProcessAdded;
            _service.ProcessRemoved += Service_ProcessRemoved;

            _service.Start();

            Timer initialLoadTimer = new Timer();
            initialLoadTimer.Interval = 1000;
            initialLoadTimer.Tick += InitialLoadTimer_Tick;
            initialLoadTimer.Start();
        }
        private void EnableGridDoubleBuffering()
        {
            typeof(DataGridView)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(grid, true, null);
        }

        private void ApplyFilter()
        {
            
            if (InvokeRequired)
            {
                Invoke(new Action(ApplyFilter));
                return;
            }

            string filterText = edtFilter.Text.ToLowerInvariant().Trim();

            // Temporäre Sicht-Liste erzeugen, aber DataSource NICHT austauschen
            var filtered = _allProcessItems
                .Where(p =>
                    string.IsNullOrEmpty(filterText) ||
                    (p.Name != null && p.Name.ToLowerInvariant().Contains(filterText)) ||
                    (p.ExePath != null && p.ExePath.ToLowerInvariant().Contains(filterText)) ||
                    p.Pid.ToString().Contains(filterText))
                .OrderBy(p => p.Name)
                .ToList();

            // Grid-Inhalt aktualisieren ohne Binding-Reset
            grid.SuspendLayout();
            grid.DataSource = null;
            grid.DataSource = filtered;
            grid.ResumeLayout();

            lblFilter.Text = $"Filter: ({filtered.Count})";
            this.Text = $"Processes: {filtered.Count}";
        }


        private void Service_ProcessAdded(FullProcessInfo info)
        {
            if (isInitialLoad)
            {
                lock (initialLoadBatch)
                {
                    initialLoadBatch.Add(info);
                }
                return;
            }

            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Service_ProcessAdded(info)));
                return;
            }

            if (!_allProcessItems.Any(p => p.Pid == info.Pid))
            {
                _allProcessItems.Add(info);
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
                ApplyFilter();
            }
        }


        // --- ÄNDERUNG HIER ---
        private FullProcessInfo SelectedProcess
        {
            get
            {
                if (grid.SelectedRows.Count == 0)
                    return null;

                // 1. Hole das "sichere" View-Objekt aus dem Grid
                var selectedViewItem = grid.SelectedRows[0].DataBoundItem as ProcessInfoView;
                if (selectedViewItem == null)
                    return null;

                // 2. Suche das "echte" Objekt mit der PID in der Master-Liste
                return _allProcessItems.FirstOrDefault(p => p.Pid == selectedViewItem.Pid);
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

    // Die ConsoleLogger-Klasse bleibt unverändert
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
            string fullMessage = (message ?? "") + (ex?.Message ?? "");
            string lowerMessage = fullMessage.ToLowerInvariant();

            // LOGISCHE FILTERUNG:
            // Ignoriere harmlose Fehler, die wir erwarten
            if (level >= LogLevel.Warning) // Annahme: 0=Debug, 1=Info, 2=Warn, 3=Error
            {
                if (lowerMessage.Contains("access") && lowerMessage.Contains("denied"))
                {
                    return; // Ignorieren
                }
                if (lowerMessage.Contains("failed to open") ||
                    lowerMessage.Contains("kann prozess nicht öffnen") ||
                    lowerMessage.Contains("fehler beim lesen"))
                {
                    return; // Ignorieren
                }
            }

            var line = $"[{level}] {message} {ex?.Message}";
          //  Console.WriteLine(line);

            if (_richTextBox.InvokeRequired)
                _richTextBox.Invoke(new Action(() => _richTextBox.AppendText(line + Environment.NewLine)));
            else
                _richTextBox.AppendText(line + Environment.NewLine);
        }
    }

}