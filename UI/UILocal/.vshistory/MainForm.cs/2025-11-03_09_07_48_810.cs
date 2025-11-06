using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Forms;
using NativeProcesses;

namespace ProcessDemo
{
    public partial class MainForm : Form
    {
        private ProcessService _service;
        private BindingList<FullProcessInfo> _binding;
        private ContextMenuStrip _menu;


        public MainForm()
        {
            InitializeComponent();


            SetupGrid();
            SetupMenu();
            LoadProcesses();
        }
        private void grid_BindingContextChanged(object sender, EventArgs e)
        {
            this.Text = $"Processes: {grid.RowCount}";
        }

        private void SetupGrid()
        {
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AutoGenerateColumns = true;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            Controls.Add(grid);
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
            var logger = new ConsoleLogger();
            _service = new ProcessService(provider, logger);

            _binding = new BindingList<FullProcessInfo>();
            grid.DataSource = _binding;

            _service.ProcessAdded += Service_ProcessAdded;
            _service.ProcessRemoved += Service_ProcessRemoved;

            _service.Start();
        }

        private void Service_ProcessAdded(FullProcessInfo info)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Service_ProcessAdded(info)));
                return;
            }
            _binding.Add(info);
        }

        private void Service_ProcessRemoved(int pid)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Service_ProcessRemoved(pid)));
                return;
            }

            var processToRemove = _binding.FirstOrDefault(p => p.Pid == pid);
            if (processToRemove != null)
            {
                _binding.Remove(processToRemove);
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
        public void Log(LogLevel level, string message, Exception ex = null)
        {
            Console.WriteLine($"[{level}] {message} {ex?.Message}");
        }
    }
}