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


        public MainForm()
        {
            InitializeComponent();



            SetupFilterBar();
            SetupGrid();
            SetupMenu();
            LoadProcesses();
        }

        private void SetupFilterBar()
        {

            lblFilter.Text = "Filter:";
            lblFilter.ForeColor = Color.White;
            lblFilter.Dock = DockStyle.Left;
            lblFilter.Padding = new Padding(5, 4, 5, 0);
            lblFilter.AutoSize = true;

            edtFilter.Dock = DockStyle.Fill;
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
                this.Text = $"Processes: {_allProcessItems.Count}";
            }
        }

        private void SetupGrid()
        {
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

        private void LoadProcesses()
        {
            var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
            var logger = new ConsoleLogger(richTextBox1);
            _service = new ProcessService(provider, logger);

            _allProcessItems = new BindingList<FullProcessInfo>();
            _allProcessItems.ListChanged += Binding_ListChanged;

            _filteredBindingSource = new BindingSource();
            _filteredBindingSource.DataSource = new List<FullProcessInfo>(_allProcessItems);

            grid.DataSource = _filteredBindingSource;

            _service.ProcessAdded += Service_ProcessAdded;
            _service.ProcessRemoved += Service_ProcessRemoved;

            _service.Start();
        }

        private void ApplyFilter()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(ApplyFilter));
                return;
            }

            string filterText = edtFilter.Text.ToLowerInvariant().Trim();

            List<FullProcessInfo> filteredList;

            if (string.IsNullOrEmpty(filterText))
            {
                filteredList = new List<FullProcessInfo>(_allProcessItems);
            }
            else
            {
                filteredList = _allProcessItems.Where(p =>
                    (p.Name != null && p.Name.ToLowerInvariant().Contains(filterText)) ||
                    (p.ExePath != null && p.ExePath.ToLowerInvariant().Contains(filterText)) ||
                    p.Pid.ToString().Contains(filterText)
                ).ToList();
            }

            _filteredBindingSource.DataSource = filteredList;
            _filteredBindingSource.ResetBindings(false);
        }

        private void Service_ProcessAdded(FullProcessInfo info)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Service_ProcessAdded(info)));
                return;
            }
            _allProcessItems.Add(info);
            ApplyFilter();
        }

        private void Service_ProcessRemoved(int pid)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Service_ProcessRemoved(pid)));
                return;
            }

            var processToRemove = _allProcessItems.FirstOrDefault(p => p.Pid == pid);
            if (processToRemove != null)
            {
                _allProcessItems.Remove(processToRemove);
                ApplyFilter();
            }
        }

        private FullProcessInfo SelectedProcess =>
            grid.SelectedRows.Count > 0 ? grid.SelectedRows[0].DataBoundItem as FullProcessInfo : null;

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
            var line = $"[{level}] {message} {ex?.Message}";
            Console.WriteLine(line);

            if (_richTextBox.InvokeRequired)
                _richTextBox.Invoke(new Action(() => _richTextBox.AppendText(line + Environment.NewLine)));
            else
                _richTextBox.AppendText(line + Environment.NewLine);
        }
    }
}