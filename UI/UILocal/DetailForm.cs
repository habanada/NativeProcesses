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
            if (_pid == -1)
                return;

            var first = data.Cast<object>().FirstOrDefault();
            if (first == null)
                return;

            _itemType = first.GetType();

            if (_itemType == typeof(NativeProcesses.Core.Models.DotNetExceptionInfo) ||
                _itemType == typeof(NativeProcesses.Core.Models.DotNetFinalizerInfo) ||
                _itemType == typeof(NativeProcesses.Core.Models.DotNetLockInfo))
            {
                ContextMenuStrip menu = new ContextMenuStrip();
                menu.Items.Add("Find GC Root Path", null, FindGcRoot_Click);
                gridDetails.ContextMenuStrip = menu;
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