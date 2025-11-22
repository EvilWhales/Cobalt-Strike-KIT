using Microsoft.Diagnostics.Tracing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BeaconKiller
{
    class WinINetParser : TraceEventParser
    {
        public static readonly Guid ProviderGuid = new Guid("43d1a55c-76d6-4f7e-995c-64c711e5cafe");
        public const string ProviderName = "Microsoft-Windows-WinINet";
        // 0x4000000000000000  Microsoft-Windows-WinINet/UsageLog
        public const ulong Keywords = 0x4000000000000000;
        private static volatile TraceEvent[] s_templates;
        public WinINetParser(TraceEventSource source, bool dontRegister = false) : base(source, dontRegister)
        {
        }

        protected override void EnumerateTemplates(Func<string, string, EventFilterResponse> eventsToObserve, Action<TraceEvent> callback)
        {
            if (s_templates == null)
            {
                s_templates = new TraceEvent[]{
                    new WinINetTraceEventData(null, 1057, 575, "WinINet/UsageLogRequest", new Guid("0f09b1ad-2869-4456-a9b7-77a9d89eca64"), 0, "WinINet", ProviderGuid, ProviderName),
                };
            }
            TraceEvent[] array = s_templates;
            foreach (TraceEvent traceEvent in array)
            {
                if (traceEvent != null && (eventsToObserve == null || eventsToObserve(traceEvent.ProviderName, traceEvent.EventName) == EventFilterResponse.AcceptEvent))
                {
                    callback(traceEvent);
                }
            }
        }

        protected override string GetProviderName()
        {
            return ProviderName;
        }
    }
    class WinINetTraceEventData : TraceEvent
    {
        public WinINetTraceEventData(Action<WinINetTraceEventData> action, int eventID, int task, string taskName, Guid taskGuid, int opcode, string opcodeName, Guid providerGuid, string providerName)
            : base(eventID, task, taskName, taskGuid, opcode, opcodeName, providerGuid, providerName)
        {
            Action = action;
        }
        public new string EventName => "WinINet";
        public override string[] PayloadNames
        {
            get
            {
                if (payloadNames == null)
                {
                    payloadNames = new string[]
                    {
                      "URL","Verb","RequestHeaders","ResponseHeaders","Status","UsageLogRequestCache"
                    };
                }

                return payloadNames;
            }
        }
        //<template tid = "Wininet_UsageLogRequestArgs" >
        // < data name="URL" inType="win:AnsiString"/>
        // <data name = "Verb" inType="win:AnsiString"/>
        // <data name = "RequestHeaders" inType="win:AnsiString"/>
        // <data name = "ResponseHeaders" inType="win:AnsiString"/>
        // <data name = "Status" inType="win:UInt32"/>
        // <data name = "UsageLogRequestCache" inType="win:UInt32" map="mapUsageLogRequestCache"/>
        //</template>
        public string URL
        {
            get { return GetUTF8StringAt(0); }
        }
        public string Verb
        {
            get { return GetUTF8StringAt(SkipUTF8String(0)); }
        }
        public string RequestHeaders
        {
            get { return GetUTF8StringAt(SkipUTF8String(0, 2)); }
        }
        public string ResponseHeaders
        {
            get { return GetUTF8StringAt(SkipUTF8String(0, 3)); }
        }

        public int Status
        {
            get { return GetInt32At(SkipUTF8String(0, 4)); }
        }
        public int UsageLogRequestCache
        {
            get { return GetInt32At(SkipUTF8String(0, 4) + 4); }
        }
        int SkipUTF8String(int offset, int stringCount)
        {
            while (stringCount > 0)
            {
                offset = SkipUTF8String(offset);
                stringCount--;
            }

            return offset;
        }
        public override object PayloadValue(int index)
        {
            switch (index)
            {
                case 0:
                    return URL;
                case 1:
                    return Verb;
                case 2:
                    return RequestHeaders;
                case 3:
                    return ResponseHeaders;
                case 4:
                    return Status;
                case 5:
                    return UsageLogRequestCache;
                default:
                    return null;
            }
        }
        protected override Delegate Target
        {
            get
            {
                return Action;
            }
            set
            {
                Action = (Action<WinINetTraceEventData>)value;
            }
        }

        private event Action<WinINetTraceEventData> Action;


        protected override void Dispatch()
        {
            Action?.Invoke(this);
        }
    }
}
