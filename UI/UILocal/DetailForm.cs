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
            // 1. Validierung der Auswahl
            if (gridDetails.SelectedRows.Count == 0 || _pid == -1 || _itemType == null) return;
            dynamic item = gridDetails.SelectedRows[0].DataBoundItem;

            IntPtr baseAddress = IntPtr.Zero;
            long regionSize = 0;
            bool isPeHeader = false;
            bool forceRecalculateSize = false;
            string suggestedFileName = $"PID_{_pid}_DUMP.bin";
            byte[] suggestedHeaderFix = null;

            try
            {
                // 2. Typ-Erkennung und Datenextraktion (Erweitert für Phantom Module)

                // A. Suspicious Memory (RWX Regionen)
                if (_itemType == typeof(NativeProcesses.Core.Inspection.SecurityInspector.SuspiciousMemoryRegionInfo))
                {
                    baseAddress = item.BaseAddress;
                    regionSize = item.RegionSize;
                    suggestedFileName = $"PID_{_pid}_MemRegion_{baseAddress.ToString("X")}.bin";
                }
                // B. Found PE Headers (Hidden PE / Header Stomping)
                else if (_itemType == typeof(NativeProcesses.Core.Inspection.FoundPeHeaderInfo))
                {
                    baseAddress = item.BaseAddress;
                    regionSize = item.RegionSize;
                    isPeHeader = true;
                    suggestedHeaderFix = item.SuggestedHeaderFix;
                    suggestedFileName = $"PID_{_pid}_HiddenPE_{baseAddress.ToString("X")}.bin";
                }
                // C. Suspicious Threads (Wir kennen nur die Startadresse)
                else if (_itemType == typeof(NativeProcesses.Core.Inspection.SecurityInspector.SuspiciousThreadInfo))
                {
                    baseAddress = item.StartAddress;
                    regionSize = 0x1000; // Dummy-Größe, wir berechnen gleich die echte
                    forceRecalculateSize = true;
                    suggestedFileName = $"PID_{_pid}_ThreadStart_{baseAddress.ToString("X")}.bin";
                }
                // D. Phantom Module (VAD Scanner Results) -> NEU!
                // Wir prüfen den Typ-Namen dynamisch oder per typeof, falls du den Namespace importiert hast
                else if (item.GetType().Name == "PhantomModuleInfo")
                {
                    baseAddress = item.BaseAddress;
                    regionSize = item.Size;
                    isPeHeader = true; // Phantom Module sind fast immer PEs

                    string name = item.NtPath;
                    // Pfad bereinigen für Dateinamen (\Device\Harddisk... -> datei.dll)
                    try { name = System.IO.Path.GetFileName(name.Replace("\\", "/")); } catch { }

                    if (string.IsNullOrEmpty(name)) name = "Phantom";
                    suggestedFileName = $"PID_{_pid}_{name}_{baseAddress.ToString("X")}.dll";
                }
                // Fallback für unbekannte Typen
                else
                {
                    try { baseAddress = item.BaseAddress; } catch { return; }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error resolving item type: {ex.Message}");
                return;
            }

            // 3. Speichern-Dialog
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.FileName = suggestedFileName;
                sfd.Filter = "Binary Dump (*.bin)|*.bin|Executable (*.exe)|*.exe|Dynamic Library (*.dll)|*.dll";

                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    this.Cursor = Cursors.WaitCursor;
                    try
                    {
                        byte[] rawDump = null;

                        // Wir benötigen Lesezugriff und Query-Rechte (Query für Memory Info)
                        var access = NativeProcesses.Core.Native.ProcessAccessFlags.VmRead |
                                     NativeProcesses.Core.Native.ProcessAccessFlags.QueryInformation;

                        // 4. Zugriff auf den Prozess (Live oder Snapshot - je nachdem was _pid referenziert)
                        using (var proc = new NativeProcesses.Core.Native.ManagedProcess(_pid, access))
                        {
                            // 4a. Smarte Größen-Erkennung
                            // Wenn wir nur einen Thread-Start haben oder die Größe unsicher ist, fragen wir den Kernel (VAD).
                            if (regionSize <= 0x1000 || forceRecalculateSize)
                            {
                                // Wir holen alle Regionen (nutzt jetzt den schnellen WorkingSetEnumerator im Backend!)
                                var regions = proc.GetVirtualMemoryRegions();

                                // Finde die Region, die unsere Adresse beinhaltet
                                var region = regions.FirstOrDefault(r => r.BaseAddress.ToInt64() <= baseAddress.ToInt64() &&
                                                                         (r.BaseAddress.ToInt64() + r.RegionSize) > baseAddress.ToInt64());
                                if (region != null)
                                {
                                    // Lese ab Startadresse bis Ende der Allocation
                                    long offset = baseAddress.ToInt64() - region.BaseAddress.ToInt64();
                                    regionSize = region.RegionSize - offset;
                                }
                                else
                                {
                                    // Fallback, falls VAD fehlschlägt (sehr selten)
                                    regionSize = 0x20000; // 128KB
                                }
                            }

                            // 5. Speicher lesen (Raw Dump)
                            rawDump = proc.ReadMemory(baseAddress, (int)regionSize);

                            // 6. Advanced Reconstruction Pipeline (ImpRec + Fixes)
                            // Wir versuchen zu rekonstruieren, wenn wir MZ sehen oder wissen, dass es ein PE sein sollte (Phantom/HiddenPE)
                            bool hasMz = (rawDump.Length > 2 && rawDump[0] == 0x4D && rawDump[1] == 0x5A);

                            if (isPeHeader || hasMz)
                            {
                                // A. Header Repair (z.B. bei IcedID "Headerless PE")
                                // Wenn der Scanner (FoundPeHeaderInfo) einen Fix berechnet hat, wenden wir ihn an.
                                if (suggestedHeaderFix != null)
                                {
                                    int copyLen = Math.Min(rawDump.Length, suggestedHeaderFix.Length);
                                    Array.Copy(suggestedHeaderFix, 0, rawDump, 0, copyLen);

                                    // Re-Check MZ nach Fix (jetzt sollte es ein valides PE sein)
                                    hasMz = (rawDump[0] == 0x4D && rawDump[1] == 0x5A);
                                }

                                // B. Import Reconstruction (ImpRec) - Das "PE-sieve Feature"
                                if (hasMz)
                                {
                                    try
                                    {
                                        // Module laden, damit wir wissen, wohin die Imports zeigen
                                        // (Nutzt PSS Snapshot Logic im Backend, wenn verfügbar)
                                        var modules = await NativeProcesses.Core.Native.ProcessManager.GetModulesAsync(proc, null);
                                        bool is64 = proc.GetIsWow64() == false;

                                        // HIER: Wir nutzen deine PeReconstructor Klasse.
                                        // Voraussetzung: Du hast die Klasse mit dem Code aus "PeEmulation/AdvancedPeReconstructor" aktualisiert!
                                        var reconstructor = new NativeProcesses.Core.Inspection.PeReconstructor(null);

                                        // Führt den Rebuild durch (IAT Suche -> Import Table Bau -> Header Patch -> Resize)
                                        byte[] reconstructedDump = reconstructor.ReconstructPe(rawDump, modules, proc, is64);

                                        // Wenn erfolgreich (und größer/anders), übernehmen wir das Ergebnis
                                        if (reconstructedDump != null && reconstructedDump.Length >= rawDump.Length)
                                        {
                                            rawDump = reconstructedDump;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        // ImpRec ist optional. Wenn es fehlschlägt, speichern wir den Raw Dump.
                                        // System.Diagnostics.Debug.WriteLine("ImpRec warning: " + ex.Message);
                                    }
                                }
                            }
                        }

                        // 7. Schreiben auf Festplatte
                        System.IO.File.WriteAllBytes(sfd.FileName, rawDump);

                        this.Cursor = Cursors.Default;

                        string statusMsg = $"Dump saved to:\n{sfd.FileName}\n\n" +
                                           $"Source: 0x{baseAddress.ToString("X")}\n" +
                                           $"Size: {rawDump.Length:N0} bytes";

                        if (rawDump.Length > regionSize)
                            statusMsg += "\n\n[+] Import Table Reconstructed (Executable)";

                        if (suggestedHeaderFix != null)
                            statusMsg += "\n[+] PE Header Repaired";

                        MessageBox.Show(statusMsg, "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
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