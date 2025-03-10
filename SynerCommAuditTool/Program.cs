using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using SynerCommAuditTool.Client;

namespace SynerCommAuditTool
{
    internal class Program
    {
        public class Options
        {
            [Option("domain", Required = true, HelpText = "Active Directory domain name. E.g., acme.local")]
            public String Domain {  get; set; }

            [Option('v', "verbose", Default = false)]
            public bool Verbose { get; set; }
        }

        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<Options>( args ).WithParsed<Options>(o =>
            {
                Customer customer = new Customer();

                if (string.IsNullOrEmpty(o.Domain))
                {
                    Console.WriteLine("[!] Domain name required!");
                    return;
                }

                String domain = o.Domain.ToLower();
                customer.EnumerateUsers(domain, o.Verbose);

                Console.WriteLine("[+] Retrieving password policy");
                customer.GetPassPol(domain, o.Verbose);

                //customer.SendData().GetAwaiter().GetResult();
            });
        }
    }
}
