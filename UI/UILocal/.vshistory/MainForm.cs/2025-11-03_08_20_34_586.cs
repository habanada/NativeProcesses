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

        private void SetupGrid()
        {
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AutoGenerateColumns = true;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
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
            _service.Start();

            var list = _service.GetCurrentProcesses();
            _binding = new BindingList<FullProcessInfo>(list);
            grid.DataSource = _binding;

            var refreshTimer = new Timer();
            refreshTimer.Interval = 3000;
            refreshTimer.Tick += (s, e) =>
            {
                var updated = _service.GetCurrentProcesses();
                _binding.Clear();
                foreach (var p in updated) _binding.Add(p);
            };
            refreshTimer.Start();
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
    }

    public class ConsoleLogger : IEngineLogger
    {
        public void Log(LogLevel level, string message, Exception ex = null)
        {
            Console.WriteLine($"[{level}] {message} {ex?.Message}");
        }
    }
}

