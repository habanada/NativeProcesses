using ProcessDemo;

namespace processlist
{
    partial class DetailForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

            private System.Windows.Forms.DataGridView gridDetails;

            protected override void Dispose(bool disposing)
            {
                if (disposing && (components != null))
                {
                    components.Dispose();
                }
                base.Dispose(disposing);
            }

            private void InitializeComponent()
            {
                System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
                this.gridDetails = new System.Windows.Forms.DataGridView();
                ((System.ComponentModel.ISupportInitialize)(this.gridDetails)).BeginInit();
                this.SuspendLayout();

                this.gridDetails.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
                this.gridDetails.Dock = System.Windows.Forms.DockStyle.Fill;
                this.gridDetails.Location = new System.Drawing.Point(0, 0);
                this.gridDetails.Name = "gridDetails";
                this.gridDetails.Size = new System.Drawing.Size(784, 561);
                this.gridDetails.TabIndex = 0;

                this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
                this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
                this.ClientSize = new System.Drawing.Size(784, 561);
                this.Controls.Add(this.gridDetails);
                this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
                this.Name = "DetailForm";
                this.Text = "Details";
                this.KeyPreview = true;
                this.KeyDown += new System.Windows.Forms.KeyEventHandler(this.DetailForm_KeyDown);
                ((System.ComponentModel.ISupportInitialize)(this.gridDetails)).EndInit();
                this.ResumeLayout(false);
            }
        }
}