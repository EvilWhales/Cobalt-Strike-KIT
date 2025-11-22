using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace BeaconKiller
{
    internal class Event
    {
        public long Time { get; private set; }
        public long TimeStampQPC { get; private set; }
        public string EventName { get; private set; }
        public int PID { get; private set; }
        public int TID { get; private set; }
        public string Process { get; private set; }
        public Dictionary<string, object> Values { get; private set; } = new Dictionary<string, object>();
        public StackData Stack { get; set; } = null;


        public Event(TraceEvent e, EtwTraceCtx etwTraceCtx)
        {


            DateTime datetime;
            datetime = e.TimeStamp;
#pragma warning disable 0618
            TimeStampQPC = e.TimeStampQPC;
#pragma warning restore 0618
            
            Time = new DateTimeOffset(datetime).ToUnixTimeMilliseconds();
            EventName = e.EventName;
            if (e.ProcessID != -1)
            {
                PID = e.ProcessID;
                TID = e.ProcessID == -1 ? -1 : e.ThreadID;
                Process = etwTraceCtx.GetProcessName(e);
            }
            foreach (var name in e.PayloadNames)
            {
                var v = e.PayloadByName(name);
                if (v != null)
                {
                    Values[name] = v;
                }
            }

        }
        
        public JsonObject ToJson()
        {
            var json = new JsonObject();
            foreach (var kv in Values)
            {
                var v = kv.Value;
                var k = kv.Key;
                if (!v.GetType().IsPrimitive && !v.GetType().IsArray)
                {
                    if (v is JsonObject jsonobj)
                    {
                        json[k] = jsonobj;

                    }
                    else
                    {
                        json[k] = v.ToString();
                    }
                }
                else
                {
                    json[k] = JsonSerializer.SerializeToNode(v);
                }
            }
            if (Stack != null)
            {
                json["stacks"] = JsonSerializer.SerializeToNode(Stack.AddressNames);
                json["unbacked"] = Stack.Unbacked;
            }
            return json;
        }
        private static readonly JsonSerializerOptions options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,

        };
        public override string ToString()
        {
            return JsonSerializer.Serialize(ToJson(), options);
        }

    }

}
