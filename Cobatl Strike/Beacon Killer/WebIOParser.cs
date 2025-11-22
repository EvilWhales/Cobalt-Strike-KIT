using Microsoft.Diagnostics.Tracing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BeaconKiller
{
    class WebIOParser : TraceEventParser
    {
        public static readonly Guid ProviderGuid = new Guid("50b3e73c-9370-461d-bb9f-26f32d68887d");
        public const string ProviderName = "Microsoft-Windows-WebIO";


        //<keyword name = "Keyword.API" message="$(string.keyword_Keyword.API)" mask="0x1" />
        //<keyword name = "Keyword.SEND" message="$(string.keyword_Keyword.SEND)" mask="0x100000000" />
        //<keyword name = "Keyword.RECEIVE" message="$(string.keyword_Keyword.RECEIVE)" mask="0x200000000" />
        //<keyword name = "Keyword.L3_CONNECT" message="$(string.keyword_Keyword.L3_CONNECT)" mask="0x400000000" />
        //<keyword name = "Keyword.CLOSE" message="$(string.keyword_Keyword.CLOSE)" mask="0x1000000000" />
        //<keyword name = "Keyword.SECURITY" message="$(string.keyword_Keyword.SECURITY)" mask="0x2000000000" />
        //<keyword name = "Keyword.CONFIGURATION" message="$(string.keyword_Keyword.CONFIGURATION)" mask="0x4000000000" />
        //<keyword name = "Keyword.GLOBAL" message="$(string.keyword_Keyword.GLOBAL)" mask="0x8000000000" />
        //<keyword name = "keyword_20000000000" message="$(string.keyword_keyword_20000000000)" mask="0x20000000000" />
        //Keyword.RECEIVE | Keyword.SEND | keyword_20000000000"
        public const ulong Keywords = 0x20000000000 | 0x200000000 | 0x100000000 | 0x4000000000 | 0x400000000 | 0x1;

        private static volatile TraceEvent[] s_templates;
        public WebIOParser(TraceEventSource source, bool dontRegister = false) : base(source, dontRegister)
        {
        }

        protected override void EnumerateTemplates(Func<string, string, EventFilterResponse> eventsToObserve, Action<TraceEvent> callback)
        {
            if (s_templates == null)
            {
                s_templates = new TraceEvent[]{
                    new WinHttpEmptyTraceEventData(null,1,111,"WinHttp/ApiInit",Guid.Empty,0,"WinHttp/ApiInit",ProviderGuid,ProviderName),
                    new WinHttpEmptyTraceEventData(null,5,113,"WinHttp/Session",Guid.Empty,0,"WinHttp/Session",ProviderGuid,ProviderName),

                    new WinHttpConnectTraceEventData(null,200,1,"WinHttp/Connect",Guid.Empty,0,"WinHttp/Connect",ProviderGuid,ProviderName),
                    new WinHttpCreateTraceEventData(null,17,0,"WinHttp/Create",Guid.Empty,0,"WinHttp/Create",ProviderGuid,ProviderName),
                    new WinHttpCreateTraceEventData(null,18,0,"WinHttp/Create",Guid.Empty,0,"WinHttp/Create",ProviderGuid,ProviderName),
                    new WinHttpHeaderTraceEventData(null,100,400,"WinHttp/Request",Guid.Empty,0,"WinHttp/Response",ProviderGuid,ProviderName),
                    new WinHttpHeaderTraceEventData(null,101,400,"WinHttp/Response",Guid.Empty,0,"WinHttp/Response",ProviderGuid,ProviderName),
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
    class WinHttpEmptyTraceEventData : TraceEvent
    {
        public WinHttpEmptyTraceEventData(Action<WinHttpEmptyTraceEventData> action, int eventID, int task, string taskName, Guid taskGuid, int opcode, string opcodeName, Guid providerGuid, string providerName)
            : base(eventID, task, taskName, taskGuid, opcode, opcodeName, providerGuid, providerName)
        {
            Action = action;
        }

        public override string[] PayloadNames
        {
            get
            {
                if (payloadNames == null)
                {
                    payloadNames = new string[]
                    {
                      
                    };
                }

                return payloadNames;
            }
        }


        public override object PayloadValue(int index)
        {
            return null;
        }
        protected override Delegate Target
        {
            get
            {
                return Action;
            }
            set
            {
                Action = (Action<WinHttpEmptyTraceEventData>)value;
            }
        }

        private event Action<WinHttpEmptyTraceEventData> Action;


        protected override void Dispatch()
        {
            Action?.Invoke(this);
        }
    }

    class WinHttpConnectTraceEventData : TraceEvent
    {
        public WinHttpConnectTraceEventData(Action<WinHttpConnectTraceEventData> action, int eventID, int task, string taskName, Guid taskGuid, int opcode, string opcodeName, Guid providerGuid, string providerName)
            : base(eventID, task, taskName, taskGuid, opcode, opcodeName, providerGuid, providerName)
        {
            Action = action;
        }

        public override string[] PayloadNames
        {
            get
            {
                if (payloadNames == null)
                {
                    payloadNames = new string[]
                    {
                       "Address"
                    };
                }

                return payloadNames;
            }
        }
        // <template tid="ConnectionSocketConnect始始Args">
        //   <data name="Connection" inType="win:Pointer" />
        //   <data name="SocketHandle" inType="win:UInt64" />
        //   <data name="AddressLength" inType="win:UInt32" />
        //   <data name="Address" inType="win:UnicodeString" length="AddressLength" />
        //   <data name="Context" inType="win:Pointer" />
        //   <data name="RemainingAddressCount" inType="win:UInt64" />
        //   <data name="Error" inType="win:UInt32" />
        // </template>
        public string Address
        {
            get
            {
                var len = GetInt32At(PointerSize+8)*2 -2;
                return Encoding.Unicode.GetString(GetByteArrayAt(PointerSize + 8 + 4, len));
            }
        }

        public override object PayloadValue(int index)
        {
            switch (index)
            {
                case 0:
                    return Address;
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
                Action = (Action<WinHttpConnectTraceEventData>)value;
            }
        }

        private event Action<WinHttpConnectTraceEventData> Action;


        protected override void Dispatch()
        {
            Action?.Invoke(this);
        }
    }

    class WinHttpCreateTraceEventData : TraceEvent
    {
        public WinHttpCreateTraceEventData(Action<WinHttpCreateTraceEventData> action, int eventID, int task, string taskName, Guid taskGuid, int opcode, string opcodeName, Guid providerGuid, string providerName)
            : base(eventID, task, taskName, taskGuid, opcode, opcodeName, providerGuid, providerName)
        {
            Action = action;
        }

        public override string[] PayloadNames
        {
            get
            {
                if (payloadNames == null)
                {
                    payloadNames = new string[]
                    {
                       "Request","Method","URI","VersionMajor","VersionMinor","Error"
                    };
                }

                return payloadNames;
            }
        }
        //<template tid = "RequestCreateArgs" >
        //  < data name="Request" inType="win:Pointer" />
        //  <data name = "RequestHandle" inType="win:UInt64" />
        //  <data name = "Session" inType="win:Pointer" />
        //  <data name = "SessionHandle" inType="win:UInt64" />
        //  <data name = "Method" inType="win:AnsiString" />
        //  <data name = "URI" inType="win:UnicodeString" />
        //  <data name = "VersionMajor" inType="win:UInt16" />
        //  <data name = "VersionMinor" inType="win:UInt16" />
        //  <data name = "Error" inType="win:UInt32" />
        //</template>
        public ulong Request => GetAddressAt(0);
        public string Method => GetUTF8StringAt(PointerSize * 2 + 16);
        public string URI => GetUnicodeStringAt(SkipUTF8String(PointerSize * 2 + 16));
        public int VersionMajor => GetInt16At(SkipUnicodeString(SkipUTF8String(PointerSize * 2 + 16)));
        public int VersionMinor => GetInt16At(SkipUnicodeString(SkipUTF8String(PointerSize * 2 + 16)) + 2);
        public int Error => GetInt32At(SkipUnicodeString(SkipUTF8String(PointerSize * 2 + 16)) + 4);

        public override object PayloadValue(int index)
        {
            switch (index)
            {
                case 0:
                    return Request;
                case 1:
                    return Method;
                case 2:
                    return URI;
                case 3:
                    return VersionMajor;
                case 4:
                    return VersionMinor;
                case 5:
                    return Error;
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
                Action = (Action<WinHttpCreateTraceEventData>)value;
            }
        }

        private event Action<WinHttpCreateTraceEventData> Action;


        protected override void Dispatch()
        {
            Action?.Invoke(this);
        }
    }

    class WinHttpHeaderTraceEventData : TraceEvent
    {
        public WinHttpHeaderTraceEventData(Action<WinHttpHeaderTraceEventData> action, int eventID, int task, string taskName, Guid taskGuid, int opcode, string opcodeName, Guid providerGuid, string providerName)
            : base(eventID, task, taskName, taskGuid, opcode, opcodeName, providerGuid, providerName)
        {
            Action = action;
        }

        public override string[] PayloadNames
        {
            get
            {
                if (payloadNames == null)
                {
                    payloadNames = new string[]
                    {
                       "Request","Headers"
                    };
                }

                return payloadNames;
            }
        }
        //<template tid = "RequestHeaderArgs" >
        // < data name="Request" inType="win:Pointer"/>
        // <data name = "Length" inType="win:UInt16"/>
        // <data name = "Headers" inType="win:AnsiString" length="Length"/>
        //</template>
        public ulong Request => GetAddressAt(0);
        public string Headers
        {
            get { 
                var len = GetInt16At(PointerSize);
                return Encoding.ASCII.GetString(GetByteArrayAt(PointerSize + 2, len)); 
            }
        }
        public override object PayloadValue(int index)
        {
            switch (index)
            {
                case 0:
                    return Request;
                case 1:
                    return Headers;
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
                Action = (Action<WinHttpHeaderTraceEventData>)value;
            }
        }

        private event Action<WinHttpHeaderTraceEventData> Action;


        protected override void Dispatch()
        {
            Action?.Invoke(this);
        }
    }
}
