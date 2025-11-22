using System;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace BeaconKiller
{
    public partial class MainForm : Form
    {
        private readonly DataTable ProcessDT = new DataTable("Process")
        {
            Columns =
            {
                new DataColumn("Time", typeof(long)),
                new DataColumn("PID", typeof(int)),
                new DataColumn("Process", typeof(string)),
                new DataColumn("Type", typeof(string)),
                new DataColumn("Exited",typeof(bool)),
                new DataColumn("CommandLine", typeof(string)),
            },
            DefaultView =
            {
                Sort = "Type DESC, Exited ASC, Time DESC"
            }
        };
        private readonly BindingSource bindingSourceProcess;
        private readonly DataTable EventDT = new DataTable("Event")
        {
            Columns =
            {
                new DataColumn("Time", typeof(long)),
                new DataColumn("PID", typeof(int)),
                new DataColumn("Process", typeof(string)),
                new DataColumn("EventName", typeof(string)),
                new DataColumn("Detail", typeof(string)),
                new DataColumn("Exited",typeof(bool)),
            },
            DefaultView =
            {
                Sort = "Exited ASC,Time DESC"
            }
        };
        private readonly BindingSource bindingSourceEvent;
        private readonly EtwTrace etw;
        public MainForm()
        {
            InitializeComponent();
            ProcessDT.PrimaryKey = new DataColumn[] { ProcessDT.Columns["PID"] };
            dataGridViewEvent.AutoGenerateColumns = false;
            SetDoubleBuffered(dataGridViewEvent);
            dataGridViewEvent.Columns.AddRange(
                new DataGridViewTextBoxColumn { DataPropertyName = "Time", HeaderText = "Time", Width = 120 },
                new DataGridViewTextBoxColumn { DataPropertyName = "EventName", HeaderText = "EventName", Width = 150 },
                new DataGridViewTextBoxColumn { DataPropertyName = "PID", HeaderText = "PID", Width = 80 },
                new DataGridViewTextBoxColumn { DataPropertyName = "Process", HeaderText = "Process", Width = 250 },
                new DataGridViewCheckBoxColumn { DataPropertyName = "Exited", HeaderText = "Exited", Width = 80 }
            );


            dataGridViewProcess.AutoGenerateColumns = false;
            SetDoubleBuffered(dataGridViewProcess);
            dataGridViewProcess.Columns.AddRange(
                new DataGridViewTextBoxColumn { DataPropertyName = "Time", HeaderText = "Time", Width = 120 },
                new DataGridViewTextBoxColumn { DataPropertyName = "PID", HeaderText = "PID", Width = 80 },
                new DataGridViewTextBoxColumn { DataPropertyName = "Process", HeaderText = "Process", Width = 250 },
                new DataGridViewTextBoxColumn { DataPropertyName = "Type", HeaderText = "Type", Width = 120 },
                new DataGridViewCheckBoxColumn { DataPropertyName = "Exited", HeaderText = "Exited", Width = 80 }

            );

            bindingSourceProcess = new BindingSource
            {
                DataSource = ProcessDT,
                RaiseListChangedEvents = false,
            };
            bindingSourceEvent = new BindingSource
            {
                DataSource = EventDT,
                RaiseListChangedEvents = false,
            };

            etw = new EtwTrace();
            etw.All += HandleEtwEvent;
            etw.StartTracing();

        }
        private static string[] imageNames = new string[] { "wininet.dll", "winhttp.dll" };
        private void SetDoubleBuffered(DataGridView dgv)
        {
            var prop = dgv.GetType().GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (prop != null)
            {
                prop.SetValue(dgv, true, null);
            }
        }
        private void ResetBindings(BindingSource bindingSource)
        {

            try
            {
                Invoke(new Action(() =>
                {
                    bindingSource.RaiseListChangedEvents = true;
                    bindingSource.ResetBindings(false);
                    bindingSource.RaiseListChangedEvents = false;
                }));

            }
            catch { }
        }

        private void HandleEtwEvent(Event obj)
        {
            lock (ProcessDT)
            {
                lock (EventDT)
                {
                    switch (obj.EventName)
                    {
                        case "EventTrace/RundownComplete":
                            Invoke(new Action(() =>
                            {
                                Enabled = true;
                                toolStripComboBoxLoading.Visible = false;
                                dataGridViewEvent.DataSource = bindingSourceEvent;
                                dataGridViewProcess.DataSource = bindingSourceProcess;
                            }));
                            break;
                        case "Process/Stop":
                            // 进程结束时，在列表中标记为Exited
                            var rowProc = ProcessDT.Rows.Find(obj.PID);
                            if (rowProc != null)
                            {
                                rowProc["Exited"] = true;
                                rowProc.AcceptChanges();
                                ResetBindings(bindingSourceProcess);
                                
                                
                            }
                            var hasUpdated = false;
                            for (int i = EventDT.Rows.Count - 1; i >= 0; i--)
                            {
                                DataRow row = EventDT.Rows[i];
                                if ((int)row["PID"] == obj.PID)
                                {
                                    row["Exited"] = true;
                                    row.AcceptChanges();
                                    hasUpdated = true;
                                }
                            }
                            if (hasUpdated)
                            {
                                EventDT.AcceptChanges();
                                ResetBindings(bindingSourceEvent);
                            }
                            break;
                        case "Image/Load":
                        case "Image/DCStart":
                        case "WinINet/UsageLogRequest":
                        case "WinHttp/Session":
                        case "WinHttp/ApiInit":
                            if (etw.TryGetProcess(obj.PID, out var processCtx))
                            {
                                // 非镜像加载事件 检查是否是目标镜像
                                if (processCtx.HasAnyImage(imageNames))
                                {
                                    // 如果进程加载了目标镜像，则添加到进程和事件列表中
                                    var rowProcess = ProcessDT.NewRow();
                                    rowProcess["Time"] = obj.Time;
                                    rowProcess["PID"] = obj.PID;
                                    rowProcess["Process"] = obj.Process;
                                    rowProcess["CommandLine"] = processCtx.CommandLine;
                                    rowProcess["Type"] = "Loaded";
                                    rowProcess["Exited"] = false;
                                    if (obj.Stack != null && obj.Stack.Unbacked)
                                    {
                                        var rowEvent = EventDT.NewRow();
                                        rowEvent["Time"] = obj.Time;
                                        rowEvent["PID"] = obj.PID;
                                        rowEvent["Process"] = obj.Process;
                                        rowEvent["EventName"] = obj.EventName;
                                        rowEvent["Exited"] = false;
                                        rowEvent["Detail"] = obj.ToString();
                                        if (obj.EventName == "Image/Load")
                                        {
                                            if (obj.Values["FileName"] is string fileName)
                                            {
                                                foreach (var imgName in imageNames)
                                                {
                                                    if (fileName.EndsWith(imgName, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        // 如果加载镜像时堆栈回溯出现unbacked，则标记为Unbacked(Loaded)
                                                        rowProcess["Type"] = "Unbacked(Loaded)";
                                                        EventDT.Rows.Add(rowEvent);
                                                        break;
                                                    }
                                                }

                                            }
                                        }
                                        else
                                        {
                                            // 如果通信时堆栈回溯出现unbacked，则标记为Unbacked(Used)
                                            rowProcess["Type"] = "Unbacked(Used)";
                                            EventDT.Rows.Add(rowEvent);
                                        }
                                        EventDT.AcceptChanges();
                                        ResetBindings(bindingSourceEvent);

                                    }
                                    var rowProcessOld = ProcessDT.Rows.Find(obj.PID);
                                    if (rowProcessOld == null)
                                    {
                                        ProcessDT.Rows.Add(rowProcess);
                                        ProcessDT.AcceptChanges();
                                        ResetBindings(bindingSourceProcess);
                                    }
                                    else
                                    {
                                        // 如果进程已经存在，且没退出则更新类型
                                        if (!(bool)rowProcessOld["Exited"])
                                        {
                                            var oldType = rowProcessOld["Type"].ToString();
                                            var newType = rowProcess["Type"].ToString();
                                            if (oldType !=newType && newType != "Loaded")
                                            {
                                                rowProcessOld["Type"] = newType;
                                                rowProcessOld.AcceptChanges();
                                                ProcessDT.AcceptChanges();
                                                ResetBindings(bindingSourceProcess);
                                            }
                                        }
                                        else
                                        {
                                            rowProcessOld.Delete();
                                            ProcessDT.Rows.Add(rowProcess);
                                            ProcessDT.AcceptChanges();
                                            ResetBindings(bindingSourceProcess);
                                        }
                                        
                                        
                                        
                                    }

                                }
                            }
                            break;
                        case "WinHttp/Connect":
                        case "WinHttp/Request":
                        case "WinHttp/Response":
                        case "WinHttp/Create":
                            //winhttp有些事件无法进行unbacked判断，但仍需要记录

                            var processRow = ProcessDT.Rows.Find(obj.PID); 
                            if (processRow == null) {
                                break;
                            }
                            if (processRow["Type"].ToString() != "Loaded")
                            {
                                //如何进程不是Loaded，则也要展示日志

                                var rowEvent = EventDT.NewRow();
                                rowEvent["Time"] = obj.Time;
                                rowEvent["PID"] = obj.PID;
                                rowEvent["Process"] = obj.Process;
                                rowEvent["EventName"] = obj.EventName;
                                rowEvent["Exited"] = false;
                                rowEvent["Detail"] = obj.ToString();
                                EventDT.Rows.Add(rowEvent);
                                EventDT.AcceptChanges();
                                ResetBindings(bindingSourceEvent);
                            }
                            break;
                    }

                }
            }

        }

        private void MainForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            etw.Dispose();
        }

        private void ToolStripMenuItemProcess_Click(object sender, EventArgs e)
        {
            var msg = @"列表仅展示加载了wininet.dll winhttp.dll的进程
Loaded:表示加载了dll
Unbacked(Loaded):表示加载dll时栈回溯出现unbacked
Unbacked(Used):表示调用dll网络通信时栈回溯出现unbacked";
            MessageBox.Show(msg, "进程列表说明");
        }

        private void ToolStripMenuItemHow_Click(object sender, EventArgs e)
        {
            var msg = @"目标:针对http/https的beacon

数据来源:主要使用etw技术获取数据
  1.进程相关/镜像相关事件:由Windows Kernel Trace提供
  2.WinINet相关事件:由Microsoft-Windows-WinINet提供
  3.WinHTTP相关事件:由Microsoft-Windows-WebIO提供

检测原理:由于beacon使用sRDI等shellcode加载技术
  1.启动时:加载wininet.dll或winhttp.dll时堆栈回溯会出现unbacked
  2.通信时:堆栈回溯会出现unbacked

unbacked: 即栈回溯无法对应镜像地址，而是动态申请的可执行内存地址

绕过:
  1.启动时检测:已有一些绕过方法见: https://xz.aliyun.com/news/18238
  2.通信时检测:修改ntdll!EtwEventWrite,可阻断应用层的etw日志";
            MessageBox.Show(msg, "原理说明");
        }

        private void ToolStripMenuItemSource_Click(object sender, EventArgs e)
        {
            Process.Start("https://github.com/howmp/BeaconKiller");
        }

        private void dataGridViewProcess_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0)
            {
                var row = dataGridViewProcess.Rows[e.RowIndex];
                if (row.DataBoundItem is DataRowView dataRowView)
                {
                    new Detail((string)dataRowView["CommandLine"]).Show();
                }
            }
        }

        private void dataGridViewEvent_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0)
            {
                var row = dataGridViewEvent.Rows[e.RowIndex];
                if (row.DataBoundItem is DataRowView dataRowView)
                {
                    new Detail((string)dataRowView["Detail"]).Show();
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_TERMINATE = 0x0001;

        public static void TerminateProcessById(int processId)
        {
            IntPtr hProcess = OpenProcess(PROCESS_TERMINATE, false, processId);
            try
            {
                if (hProcess == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                // 尝试终止进程
                if (!TerminateProcess(hProcess, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                // 确保关闭句柄
                CloseHandle(hProcess);
            }
        }

        private void KillProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ToolStripMenuItem menuItem = (ToolStripMenuItem)sender;
            ContextMenuStrip menu = (ContextMenuStrip)menuItem.Owner;
            DataGridView dgv = (DataGridView)menu.SourceControl;
            if (dgv.CurrentRow == null)
            {
                MessageBox.Show("未选中", "结束进程失败");
                return;
            }
            if (dgv.CurrentRow.DataBoundItem is DataRowView dataRowView)
            {
                var pid = (int)dataRowView["PID"];
                try
                {

                    TerminateProcessById(pid);
                    MessageBox.Show($"进程({pid})已结束", "结束进程成功");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, $"结束进程({pid})失败");
                }
            }
        }

        private void dataGridViewProcess_DataBindingComplete(object sender, DataGridViewBindingCompleteEventArgs e)
        {
            if (dataGridViewProcess.SelectedRows.Count > 0)
            {
                return;
            }
            if (dataGridViewProcess.Rows.Count > 0)
            {
                dataGridViewProcess.FirstDisplayedScrollingRowIndex = 0;
            }
        }

        private void dataGridViewEvent_DataBindingComplete(object sender, DataGridViewBindingCompleteEventArgs e)
        {
            if(dataGridViewEvent.SelectedRows.Count > 0)
            {
                return;
            }
            if (dataGridViewEvent.Rows.Count > 0)
            {
                dataGridViewEvent.FirstDisplayedScrollingRowIndex = 0;
            }
        }


    }
}
