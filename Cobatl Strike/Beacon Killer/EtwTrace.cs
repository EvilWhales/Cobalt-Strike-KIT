using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.AutomatedAnalysis;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BeaconKiller
{
    internal class EtwTrace : IDisposable
    {
        readonly TraceEventSession session;
        readonly TraceEventSession session2;
        readonly EtwTraceCtx etwTraceCtx = new EtwTraceCtx();
        public event Action<Event> All;
        static readonly string SessionName = "BeaconKiller";
        public EtwTrace()
        {
            session = new TraceEventSession(KernelTraceEventParser.KernelSessionName)
            {
                StopOnDispose = true
            };
            // Windows Kernel Trace
            var flags = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.ImageLoad;
            session.EnableKernelProvider(flags, flags);
            EnableRunDown(session, flags);
            session2 = new TraceEventSession(SessionName)
            {
                StopOnDispose = true
            };
            var options = new TraceEventProviderOptions()
            {
                StacksEnabled = true,
            };
          

            // Microsoft-Windows-WinINet
            session2.EnableProvider(
                WinINetParser.ProviderGuid, TraceEventLevel.Informational,
                matchAnyKeywords: WinINetParser.Keywords, options: options);

            // Microsoft-Windows-WebIO
            session2.EnableProvider(
                WebIOParser.ProviderGuid, TraceEventLevel.Informational,
                matchAnyKeywords: WebIOParser.Keywords, options: options);


            var kernelParser = new KernelTraceEventParser(session.Source, KernelTraceEventParser.ParserTrackingOptions.None);

            var source = session2.Source;

            var wininetParser = new WinINetParser(source);
            var webioParser = new WebIOParser(source);
          


            // 以下AddCallbackForEvents比All先被调用
            // etwTraceCtx 获取上下文，用于堆栈回溯
            kernelParser.AddCallbackForEvents((ProcessTraceData data) =>
            {
                //new ProcessTraceData(null, 65535, 1, "Process", ProcessTaskGuid, 1, "Start", ProviderGuid, ProviderName, null),
                //new ProcessTraceData(null, 65535, 1, "Process", ProcessTaskGuid, 2, "Stop", ProviderGuid, ProviderName, null),
                //new ProcessTraceData(null, 65535, 1, "Process", ProcessTaskGuid, 3, "DCStart", ProviderGuid, ProviderName, null),
                //new ProcessTraceData(null, 65535, 1, "Process", ProcessTaskGuid, 4, "DCStop", ProviderGuid, ProviderName, null),
                //new ProcessTraceData(null, 65535, 1, "Process", ProcessTaskGuid, 39, "Defunct", ProviderGuid, ProviderName, null),
                if ((byte)data.Opcode == 1 || (byte)data.Opcode == 3)
                {

                    etwTraceCtx.OnProcessStart(data);
                }
                else if ((byte)data.Opcode == 2 || (byte)data.Opcode == 4)
                {
                    etwTraceCtx.OnProcessStop(data);
                }
            });

            kernelParser.AddCallbackForEvents((ImageLoadTraceData data) =>
            {
                //new ImageLoadTraceData(null, 65535, 9, "Image", ImageTaskGuid, 10, "Load", ProviderGuid, ProviderName, null),
                //new ImageLoadTraceData(null, 65535, 9, "Image", ImageTaskGuid, 2, "Unload", ProviderGuid, ProviderName, null),
                //new ImageLoadTraceData(null, 65535, 9, "Image", ImageTaskGuid, 3, "DCStart", ProviderGuid, ProviderName, null),
                //new ImageLoadTraceData(null, 65535, 9, "Image", ImageTaskGuid, 4, "DCStop", ProviderGuid, ProviderName, null),
                if ((byte)data.Opcode == 10 || (byte)data.Opcode == 3)
                {

                    etwTraceCtx.OnImageLoad(data);
                }
                else if ((byte)data.Opcode == 2 || (byte)data.Opcode == 4)
                {
                    etwTraceCtx.OnImageUnload(data);
                }
            });
          
            kernelParser.All += OnEvent;
            wininetParser.All += OnEvent;
            webioParser.All += OnEvent;
           
        }


        internal Event _lastKernelEvent;
        public bool TryGetProcess(int pid, out ProcessCtx processCtx)
        {
            return etwTraceCtx.TryGetProcess(pid, out processCtx);
        }
        private void OnEvent(TraceEvent obj)
        {

            if (obj.ProviderGuid == KernelTraceEventParser.ProviderGuid)
            {
                if (_lastKernelEvent != null)
                {
                    // 先有事件，再有事件的堆栈回溯
                    if (obj is StackWalkStackTraceData e)
                    {
                        _lastKernelEvent.Stack = etwTraceCtx.GetKernelCallStack(_lastKernelEvent.PID, _lastKernelEvent.TimeStampQPC, e);
                        All.Invoke(_lastKernelEvent);
                        _lastKernelEvent = null;

                    }
                    else
                    {
                        // 也可能没有对应的堆栈回溯
                        All.Invoke(_lastKernelEvent);
                        _lastKernelEvent = new Event(obj, etwTraceCtx);

                    }
                    return;
                }

                if (!(obj is StackWalkStackTraceData))
                {
                    _lastKernelEvent = new Event(obj, etwTraceCtx);
                }
                return;
            }
            // 其他事件
            var ev = new Event(obj, etwTraceCtx)
            {
                Stack = etwTraceCtx.GetCallStack(obj)
            };
            All.Invoke(ev);

        }

        public void StartTracing()
        {
            new Thread(() =>
            {
                session2.Source.Process();
            }).Start();
            new Thread(() =>
            {
                session.Source.Process();
            }).Start();

        }

        unsafe static void EnableRunDown(TraceEventSession session, KernelTraceEventParser.Keywords flags)
        {
            // from https://github.com/rabbitstack/fibratus/blob/master/internal/etw/trace.go#L209
            // refer https://github.com/microsoft/perfview/issues/928#issuecomment-2798763571
            int GetHRFromWin32(int dwErr)
            {
                return (int)((0 != dwErr) ? (0x80070000 | ((uint)dwErr & 0xffff)) : 0);
            }
            Debug.Assert(session.SessionName == KernelTraceEventParser.KernelSessionName, $"SessionName must be {KernelTraceEventParser.KernelSessionName}");
            const int TraceSystemTraceEnableFlagsInfo = 4;
            var sType = session.GetType();
            var EnsureStarted = sType.GetMethod("EnsureStarted", BindingFlags.NonPublic | BindingFlags.Instance);
            EnsureStarted.Invoke(session, new object[] { null });
            FieldInfo fieldInfo = sType.GetField("m_SessionHandle", BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionHandle = fieldInfo.GetValue(session);
            var method = sessionHandle.GetType().GetMethod("DangerousGetHandle", BindingFlags.Public | BindingFlags.Instance);
            var traceHandle = (ulong)method.Invoke(sessionHandle, null);
            var flagsbuf = new uint[8] { 0, 0, 0, 0, 0, 0, 0, 0 };
            fixed (uint* ptr = &flagsbuf[0])
            {
                var dwErr = TraceSetInformation(traceHandle, TraceSystemTraceEnableFlagsInfo, ptr, 4 * 8);
                Marshal.ThrowExceptionForHR(GetHRFromWin32(dwErr));
                flagsbuf[0] = (uint)flags;
                dwErr = TraceSetInformation(traceHandle, TraceSystemTraceEnableFlagsInfo, ptr, 4 * 8);
                Marshal.ThrowExceptionForHR(GetHRFromWin32(dwErr));
            }
        }
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe static extern int TraceSetInformation([In] ulong traceHandle, [In] int InformationClass, [In] void* TraceInformation, [In] int InformationLength);
        public void Dispose()
        {
            session.Dispose();
            session2.Dispose();
        }


    }

}
