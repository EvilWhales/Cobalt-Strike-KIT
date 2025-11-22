namespace BeaconKiller
{
    partial class MainForm
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.dataGridViewProcess = new System.Windows.Forms.DataGridView();
            this.contextMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.结束进程ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.帮助ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.ToolStripMenuItemProcess = new System.Windows.Forms.ToolStripMenuItem();
            this.ToolStripMenuItemHow = new System.Windows.Forms.ToolStripMenuItem();
            this.ToolStripMenuItemSource = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripComboBoxLoading = new System.Windows.Forms.ToolStripTextBox();
            this.dataGridViewEvent = new System.Windows.Forms.DataGridView();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewProcess)).BeginInit();
            this.contextMenuStrip.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewEvent)).BeginInit();
            this.SuspendLayout();
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(0, 0);
            this.splitContainer1.Name = "splitContainer1";
            this.splitContainer1.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.dataGridViewProcess);
            this.splitContainer1.Panel1.Controls.Add(this.menuStrip1);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.dataGridViewEvent);
            this.splitContainer1.Size = new System.Drawing.Size(762, 494);
            this.splitContainer1.SplitterDistance = 256;
            this.splitContainer1.TabIndex = 0;
            // 
            // dataGridViewProcess
            // 
            this.dataGridViewProcess.AllowUserToAddRows = false;
            this.dataGridViewProcess.AllowUserToDeleteRows = false;
            this.dataGridViewProcess.AllowUserToOrderColumns = true;
            this.dataGridViewProcess.BackgroundColor = System.Drawing.SystemColors.ControlLightLight;
            this.dataGridViewProcess.ContextMenuStrip = this.contextMenuStrip;
            this.dataGridViewProcess.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dataGridViewProcess.EditMode = System.Windows.Forms.DataGridViewEditMode.EditProgrammatically;
            this.dataGridViewProcess.Location = new System.Drawing.Point(0, 27);
            this.dataGridViewProcess.MultiSelect = false;
            this.dataGridViewProcess.Name = "dataGridViewProcess";
            this.dataGridViewProcess.ReadOnly = true;
            this.dataGridViewProcess.RowHeadersVisible = false;
            this.dataGridViewProcess.RowTemplate.Height = 23;
            this.dataGridViewProcess.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dataGridViewProcess.Size = new System.Drawing.Size(762, 229);
            this.dataGridViewProcess.TabIndex = 0;
            this.dataGridViewProcess.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dataGridViewProcess_CellDoubleClick);
            this.dataGridViewProcess.DataBindingComplete += new System.Windows.Forms.DataGridViewBindingCompleteEventHandler(this.dataGridViewProcess_DataBindingComplete);
            // 
            // contextMenuStrip
            // 
            this.contextMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.结束进程ToolStripMenuItem});
            this.contextMenuStrip.Name = "contextMenuStrip";
            this.contextMenuStrip.Size = new System.Drawing.Size(125, 26);
            // 
            // 结束进程ToolStripMenuItem
            // 
            this.结束进程ToolStripMenuItem.Name = "结束进程ToolStripMenuItem";
            this.结束进程ToolStripMenuItem.Size = new System.Drawing.Size(124, 22);
            this.结束进程ToolStripMenuItem.Text = "结束进程";
            this.结束进程ToolStripMenuItem.Click += new System.EventHandler(this.KillProcessToolStripMenuItem_Click);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.帮助ToolStripMenuItem,
            this.toolStripComboBoxLoading});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(762, 27);
            this.menuStrip1.TabIndex = 2;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // 帮助ToolStripMenuItem
            // 
            this.帮助ToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.ToolStripMenuItemProcess,
            this.ToolStripMenuItemHow,
            this.ToolStripMenuItemSource});
            this.帮助ToolStripMenuItem.Name = "帮助ToolStripMenuItem";
            this.帮助ToolStripMenuItem.Size = new System.Drawing.Size(44, 23);
            this.帮助ToolStripMenuItem.Text = "帮助";
            // 
            // ToolStripMenuItemProcess
            // 
            this.ToolStripMenuItemProcess.Name = "ToolStripMenuItemProcess";
            this.ToolStripMenuItemProcess.Size = new System.Drawing.Size(148, 22);
            this.ToolStripMenuItemProcess.Text = "进程列表说明";
            this.ToolStripMenuItemProcess.Click += new System.EventHandler(this.ToolStripMenuItemProcess_Click);
            // 
            // ToolStripMenuItemHow
            // 
            this.ToolStripMenuItemHow.Name = "ToolStripMenuItemHow";
            this.ToolStripMenuItemHow.Size = new System.Drawing.Size(148, 22);
            this.ToolStripMenuItemHow.Text = "原理说明";
            this.ToolStripMenuItemHow.Click += new System.EventHandler(this.ToolStripMenuItemHow_Click);
            // 
            // ToolStripMenuItemSource
            // 
            this.ToolStripMenuItemSource.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Underline);
            this.ToolStripMenuItemSource.ForeColor = System.Drawing.SystemColors.Highlight;
            this.ToolStripMenuItemSource.Name = "ToolStripMenuItemSource";
            this.ToolStripMenuItemSource.Size = new System.Drawing.Size(148, 22);
            this.ToolStripMenuItemSource.Text = "源码";
            this.ToolStripMenuItemSource.Click += new System.EventHandler(this.ToolStripMenuItemSource_Click);
            // 
            // toolStripComboBoxLoading
            // 
            this.toolStripComboBoxLoading.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F);
            this.toolStripComboBoxLoading.Name = "toolStripComboBoxLoading";
            this.toolStripComboBoxLoading.Size = new System.Drawing.Size(121, 23);
            this.toolStripComboBoxLoading.Text = "加载中...";
            // 
            // dataGridViewEvent
            // 
            this.dataGridViewEvent.AllowUserToAddRows = false;
            this.dataGridViewEvent.AllowUserToDeleteRows = false;
            this.dataGridViewEvent.AllowUserToOrderColumns = true;
            this.dataGridViewEvent.BackgroundColor = System.Drawing.SystemColors.ControlLightLight;
            this.dataGridViewEvent.ContextMenuStrip = this.contextMenuStrip;
            this.dataGridViewEvent.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dataGridViewEvent.EditMode = System.Windows.Forms.DataGridViewEditMode.EditProgrammatically;
            this.dataGridViewEvent.Location = new System.Drawing.Point(0, 0);
            this.dataGridViewEvent.MultiSelect = false;
            this.dataGridViewEvent.Name = "dataGridViewEvent";
            this.dataGridViewEvent.ReadOnly = true;
            this.dataGridViewEvent.RowHeadersVisible = false;
            this.dataGridViewEvent.RowTemplate.Height = 23;
            this.dataGridViewEvent.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dataGridViewEvent.Size = new System.Drawing.Size(762, 234);
            this.dataGridViewEvent.TabIndex = 1;
            this.dataGridViewEvent.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dataGridViewEvent_CellDoubleClick);
            this.dataGridViewEvent.DataBindingComplete += new System.Windows.Forms.DataGridViewBindingCompleteEventHandler(this.dataGridViewEvent_DataBindingComplete);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(762, 494);
            this.Controls.Add(this.splitContainer1);
            this.Enabled = false;
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "MainForm";
            this.Text = "BeaconKiller";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainForm_FormClosed);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel1.PerformLayout();
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewProcess)).EndInit();
            this.contextMenuStrip.ResumeLayout(false);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewEvent)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem 帮助ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem ToolStripMenuItemProcess;
        private System.Windows.Forms.ToolStripMenuItem ToolStripMenuItemHow;
        private System.Windows.Forms.ToolStripMenuItem ToolStripMenuItemSource;
        private System.Windows.Forms.DataGridView dataGridViewProcess;
        private System.Windows.Forms.DataGridView dataGridViewEvent;
        private System.Windows.Forms.ToolStripTextBox toolStripComboBoxLoading;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem 结束进程ToolStripMenuItem;
    }
}

