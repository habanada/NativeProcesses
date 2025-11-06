using Newtonsoft.Json;
using NativeProcesses.Network;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using NativeProcesses.Core;

namespace ProcessDemo
{
    public partial class RemoteClientForm : Form
    {
        private SecureTcpClient _client;
        private BindingList<ProcessInfoViewModel> _allProcessItems;
        private ContextMenuStrip _menu;

        private Panel panelTop;
        private TextBox txtIp;
        private TextBox txtPort;
        private TextBox txtToken;
        private Button btnConnect;
        private Button btnDisconnect;
        private SplitContainer splitContainerMain;
        private DataGridView grid;
        private DataGridView gridThreads;

        public RemoteClientForm()
        {
            InitializeComponent();
            InitializeCustomComponents();

            this.DoubleBuffered = true;
            DarkTitleBarHelper.Apply(this);

            SetupGrid();
            SetupThreadGrid();
            SetupMenu();

            _allProcessItems = new BindingList<ProcessInfoViewModel>();
            grid.DataSource = _allProcessItems;
        }

        private void InitializeCustomComponents()
        {
            this.panelTop = new Panel();
            this.txtIp = new TextBox();
            this.txtPort = new TextBox();
            this.txtToken = new TextBox();
            this.btnConnect = new Button();
            this.btnDisconnect = new Button();
            this.splitContainerMain = new SplitContainer();
            this.grid = new DataGridView();
            this.gridThreads = new DataGridView();

            this.panelTop.SuspendLayout();
            ((ISupportInitialize)(this.splitContainerMain)).BeginInit();
            this.splitContainerMain.Panel1.SuspendLayout();
            this.splitContainerMain.Panel2.SuspendLayout();
            this.splitContainerMain.SuspendLayout();
            ((ISupportInitialize)(this.grid)).BeginInit();
            ((ISupportInitialize)(this.gridThreads)).BeginInit();
            this.SuspendLayout();

            this.BackColor = Color.FromArgb(45, 45, 48);

            this.panelTop.Dock = DockStyle.Top;
            this.panelTop.Height = 40;
            this.panelTop.Padding = new Padding(5);

            this.txtIp.Text = "127.0.0.1";
            this.txtIp.Dock = DockStyle.Left;
            this.txtIp.Width = 120;

            this.txtPort.Text = "8888";
            this.txtPort.Dock = DockStyle.Left;
            this.txtPort.Width = 50;

            this.txtToken.Text = "MySecretToken";
            this.txtToken.PasswordChar = '*';
            this.txtToken.Dock = DockStyle.Left;
            this.txtToken.Width = 150;

            this.btnConnect.Text = "Connect";
            this.btnConnect.Dock = DockStyle.Left;
            this.btnConnect.Click += BtnConnect_Click;

            this.btnDisconnect.Text = "Disconnect";
            this.btnDisconnect.Dock = DockStyle.Left;
            this.btnDisconnect.Enabled = false;
            this.btnDisconnect.Click += BtnDisconnect_Click;

            this.panelTop.Controls.Add(this.btnDisconnect);
            this.panelTop.Controls.Add(this.btnConnect);
            this.panelTop.Controls.Add(this.txtToken);
            this.panelTop.Controls.Add(this.txtPort);
            this.panelTop.Controls.Add(this.txtIp);

            this.splitContainerMain.Dock = DockStyle.Fill;
            this.splitContainerMain.SplitterDistance = 600;
            this.splitContainerMain.Panel1.Controls.Add(this.grid);
            this.splitContainerMain.Panel2.Controls.Add(this.gridThreads);

            this.Controls.Add(this.splitContainerMain);
            this.Controls.Add(this.panelTop);

            this.panelTop.ResumeLayout(false);
            this.panelTop.PerformLayout();
            this.splitContainerMain.Panel1.ResumeLayout(false);
            this.splitContainerMain.Panel2.ResumeLayout(false);
            ((ISupportInitialize)(this.splitContainerMain)).EndInit();
            this.splitContainerMain.ResumeLayout(false);
            ((ISupportInitialize)(this.grid)).EndInit();
            ((ISupportInitialize)(this.gridThreads)).EndInit();
            this.ResumeLayout(false);
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
            grid.DefaultCellStyle.BackColor = Color.White;
            grid.DefaultCellStyle.ForeColor = Color.Black;
            grid.BackgroundColor = Color.FromArgb(45, 45, 48);

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
            gridThreads.DefaultCellStyle.BackColor = Color.White;
            gridThreads.DefaultCellStyle.ForeColor = Color.Black;
            gridThreads.BackgroundColor = Color.FromArgb(60, 60, 60);

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
        }

        private async void BtnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                int port = int.Parse(txtPort.Text);
                _client = new SecureTcpClient(txtIp.Text, port, txtToken.Text);
                _client.MessageReceived += Client_MessageReceived;
                _client.Disconnected += Client_Disconnected;

                bool success = await _client.ConnectAsync();

                if (success)
                {
                    UpdateUI(true);
                    await _client.SendMessageAsync("get_all_processes", null);
                }
                else
                {
                    MessageBox.Show("Connection failed. Check token or server status.");
                    UpdateUI(false);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}");
                UpdateUI(false);
            }
        }

        private void BtnDisconnect_Click(object sender, EventArgs e)
        {
            _client?.Disconnect();
        }

        private void Client_Disconnected()
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(Client_Disconnected));
                return;
            }
            UpdateUI(false);
            _allProcessItems.Clear();
        }

        private void Client_MessageReceived(string type, string data)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Client_MessageReceived(type, data)));
                return;
            }

            try
            {
                switch (type)
                {
                    case "process_list":

                        var list = JsonConvert.DeserializeObject<List<NativeProcesses.Core.FullProcessInfo>>(data);
                        _allProcessItems.Clear();
                        foreach (var info in list)
                        {
                            _allProcessItems.Add(new ProcessInfoViewModel(info));
                        }
                        break;

                    case "process_added":
                        var addedInfo = JsonConvert.DeserializeObject<FullProcessInfo>(data);
                        if (!_allProcessItems.Any(p => p.Pid == addedInfo.Pid))
                        {
                            _allProcessItems.Add(new ProcessInfoViewModel(addedInfo));
                        }
                        break;

                    case "process_updated":
                        var updatedInfo = JsonConvert.DeserializeObject<FullProcessInfo>(data);
                        var itemToUpdate = _allProcessItems.FirstOrDefault(p => p.Pid == updatedInfo.Pid);
                        itemToUpdate?.ApplyUpdate(updatedInfo);
                        break;

                    case "process_removed":
                        int pid = JsonConvert.DeserializeObject<int>(data);
                        var itemToRemove = _allProcessItems.FirstOrDefault(p => p.Pid == pid);
                        if (itemToRemove != null)
                        {
                            _allProcessItems.Remove(itemToRemove);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to process message: {type}, {ex.Message}");
            }
        }

        private void UpdateUI(bool isConnected)
        {
            btnConnect.Enabled = !isConnected;
            txtIp.Enabled = !isConnected;
            txtPort.Enabled = !isConnected;
            txtToken.Enabled = !isConnected;
            btnDisconnect.Enabled = isConnected;
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

        private void KillSelected()
        {
            var p = SelectedProcess;
            if (p == null || _client == null || !_client.IsConnected) return;
            _client.SendMessageAsync("kill", p.Pid);
        }

        private void SuspendSelected()
        {
            var p = SelectedProcess;
            if (p == null || _client == null || !_client.IsConnected) return;
            _client.SendMessageAsync("suspend", p.Pid);
        }

        private void ResumeSelected()
        {
            var p = SelectedProcess;
            if (p == null || _client == null || !_client.IsConnected) return;
            _client.SendMessageAsync("resume", p.Pid);
        }

        private void EnableGridDoubleBuffering(DataGridView dgv)
        {
            typeof(DataGridView)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(dgv, true, null);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _client?.Disconnect();
            base.OnFormClosing(e);
        }

        private void InitializeComponent2()
        {
            this.SuspendLayout();
            this.ClientSize = new System.Drawing.Size(1000, 600);
            this.Name = "RemoteClientForm";
            this.Text = "Remote Process Viewer";
            this.ResumeLayout(false);
        }
    }
}