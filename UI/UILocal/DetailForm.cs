using ProcessDemo;
using System;
using System.Collections;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace processlist
{
    public partial class DetailForm : Form
    {
        private int _pid = -1;
        private Type _itemType = null;

        public DetailForm(string title, IEnumerable data, int pid = -1)
        {
            InitializeComponent();
            this.Text = title;
            gridDetails.DataSource = data;
            _pid = pid;
            StyleForm(data);
        }

        private void StyleForm(IEnumerable data)
        {
            this.DoubleBuffered = true;
            DarkTitleBarHelper.Apply(this);
            this.BackColor = Color.FromArgb(45, 45, 48);

            EnableGridDoubleBuffering(gridDetails);
            gridDetails.Dock = DockStyle.Fill;
            gridDetails.ReadOnly = true;
            gridDetails.AutoGenerateColumns = true;
            gridDetails.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            gridDetails.AllowUserToAddRows = false;
            gridDetails.AllowUserToDeleteRows = false;
            gridDetails.EnableHeadersVisualStyles = false;
            gridDetails.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(45, 45, 48);
            gridDetails.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            gridDetails.ColumnHeadersDefaultCellStyle.Font = new Font(this.Font, FontStyle.Bold);
            gridDetails.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(240, 240, 240);
            gridDetails.DefaultCellStyle.BackColor = Color.White;
            gridDetails.DefaultCellStyle.ForeColor = Color.Black;
            gridDetails.BackgroundColor = Color.FromArgb(45, 45, 48);
            gridDetails.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0, 120, 215);
            gridDetails.DefaultCellStyle.SelectionForeColor = Color.White;
            gridDetails.RowHeadersVisible = false;
            gridDetails.BorderStyle = BorderStyle.None;
            gridDetails.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            gridDetails.GridColor = Color.Gainsboro;
            gridDetails.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;

            gridDetails.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;

            SetupContextMenu(data);
        }
        private async void FindGcRoot_Click(object sender, EventArgs e)
        {
            if (gridDetails.SelectedRows.Count == 0 || _pid == -1 || _itemType == null)
                return;

            dynamic item = gridDetails.SelectedRows[0].DataBoundItem;
            ulong targetAddress = 0;

            if (_itemType == typeof(NativeProcesses.Core.Models.DotNetExceptionInfo))
                targetAddress = item.Address;
            else if (_itemType == typeof(NativeProcesses.Core.Models.DotNetFinalizerInfo))
                targetAddress = item.ObjectAddress;
            else if (_itemType == typeof(NativeProcesses.Core.Models.DotNetLockInfo))
                targetAddress = item.LockAddress;

            if (targetAddress == 0)
            {
                MessageBox.Show(this, "Could not determine a valid object address for this item.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            this.Cursor = Cursors.WaitCursor;
            try
            {
                var path = await NativeProcesses.Core.Native.ProcessManager.GetDotNetGcRootPathAsync(_pid, targetAddress);
                using (var pathForm = new DetailForm($"GC Root Path for {targetAddress:X}", path, _pid))
                {
                    pathForm.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not find GC Root path:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }
        private void SetupContextMenu(IEnumerable data)
        {
            if (_pid == -1 && _itemType == null)
            {
                var first = data.Cast<object>().FirstOrDefault();
                if (first == null)
                    return;
                _itemType = first.GetType();
            }

            if (_itemType == typeof(NativeProcesses.Core.Models.DotNetExceptionInfo) ||
                _itemType == typeof(NativeProcesses.Core.Models.DotNetFinalizerInfo) ||
                _itemType == typeof(NativeProcesses.Core.Models.DotNetLockInfo))
            {
                ContextMenuStrip menu = new ContextMenuStrip();
                menu.Items.Add("Find GC Root Path", null, FindGcRoot_Click);
                gridDetails.ContextMenuStrip = menu;
            }

            // --- NEU: Menü für Suspicious Memory Dumps ---
            if (_itemType == typeof(NativeProcesses.Core.Inspection.SecurityInspector.SuspiciousMemoryRegionInfo) ||
                _itemType == typeof(NativeProcesses.Core.Inspection.SecurityInspector.SuspiciousThreadInfo)||
                _itemType == typeof(NativeProcesses.Core.Inspection.FoundPeHeaderInfo))
            {
                ContextMenuStrip menu = new ContextMenuStrip();
                menu.Items.Add("Dump this memory region...", null, DumpSuspiciousMemory_Click);
                gridDetails.ContextMenuStrip = menu;
            }
        }
        private async void DumpSuspiciousMemory_Click(object sender, EventArgs e)
        {
            if (gridDetails.SelectedRows.Count == 0 || _pid == -1 || _itemType == null) return;
            dynamic item = gridDetails.SelectedRows[0].DataBoundItem;

            IntPtr baseAddress = IntPtr.Zero;
            long regionSize = 0;
            bool isPeHeader = false;

            try
            {
                if (_itemType == typeof(NativeProcesses.Core.Inspection.SecurityInspector.SuspiciousMemoryRegionInfo))
                {
                    baseAddress = item.BaseAddress;
                    regionSize = item.RegionSize;
                }
                else if (_itemType == typeof(NativeProcesses.Core.Inspection.FoundPeHeaderInfo))
                {
                    baseAddress = item.BaseAddress;
                    regionSize = item.RegionSize;
                    isPeHeader = true;
                }
                // ... (SuspiciousThreadInfo Logik bleibt gleich)
            }
            catch { return; }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.FileName = $"PID_{_pid}_DUMP_{baseAddress.ToString("X")}.bin";
                sfd.Filter = "Binary Dump (*.bin)|*.bin";

                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    this.Cursor = Cursors.WaitCursor;
                    try
                    {
                        // 1. Raw Dump ziehen (über NTAPI, stealthy)
                        // Dazu nutzen wir ProcessManager Helper, aber wir brauchen die Bytes hier im RAM für den Reconstructor
                        // Da DumpProcessMemoryRegionAsync direkt in Datei schreibt, lesen wir es hier manuell kurz ein.

                        byte[] rawDump = null;
                        var access = NativeProcesses.Core.Native.ProcessAccessFlags.VmRead | NativeProcesses.Core.Native.ProcessAccessFlags.QueryInformation;

                        // Wir nutzen temporär einen ManagedProcess Helper direkt hier, oder erweitern ProcessManager um "ReadBytes"
                        // Um Code-Duplizierung zu vermeiden, nutzen wir einfach ManagedProcess direkt:
                        using (var proc = new NativeProcesses.Core.Native.ManagedProcess(_pid, access))
                        {
                            rawDump = proc.ReadMemory(baseAddress, (int)regionSize);

                            // --- SMART FIXING (ImpRec + Header Repair) ---
                            // Wir fragen den User oder machen es automatisch bei PE-Headern
                            if (isPeHeader || (rawDump.Length > 2 && rawDump[0] == 0x4D && rawDump[1] == 0x5A))
                            {
                                var reconstructor = new NativeProcesses.Core.Inspection.PeReconstructor(null);
                                var modules = proc.GetLoadedModules(null);
                                bool is64 = proc.GetIsWow64() == false;

                                // Versuche Import Table zu rekonstruieren & Header zu fixen
                                rawDump = reconstructor.ReconstructPe(rawDump, modules, proc, is64);
                            }

                            // Falls der AnomalyScanner einen "SuggestedHeaderFix" hatte (z.B. IcedID),
                            // müssten wir den hier theoretisch anwenden. Da wir das Objekt 'item' haben:
                            if (_itemType == typeof(NativeProcesses.Core.Inspection.FoundPeHeaderInfo))
                            {
                                var peInfo = (NativeProcesses.Core.Inspection.FoundPeHeaderInfo)item;
                                if (peInfo.RequiresHeaderReconstruction && peInfo.SuggestedHeaderFix != null)
                                {
                                    // Header patchen (MZ...)
                                    Array.Copy(peInfo.SuggestedHeaderFix, 0, rawDump, 0, Math.Min(rawDump.Length, peInfo.SuggestedHeaderFix.Length));
                                }
                            }
                        }

                        // 2. Schreiben
                        System.IO.File.WriteAllBytes(sfd.FileName, rawDump);

                        this.Cursor = Cursors.Default;
                        MessageBox.Show($"Dump & Repair successful!\nSaved to: {sfd.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        this.Cursor = Cursors.Default;
                        MessageBox.Show($"Dump failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }
        private void EnableGridDoubleBuffering(DataGridView dgv)
        {
            typeof(DataGridView)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(dgv, true, null);
        }

        private void DetailForm_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Escape)
            {
                this.Close();
            }
        }
    }
}