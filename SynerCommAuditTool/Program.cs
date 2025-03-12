using CommandLine;
using SynerCommAuditTool.Client;
using System;
using System.Text.Json;

namespace SynerCommAuditTool
{
    internal class Program
    {
        public class Options
        {
            [Option("domain", Required = true, HelpText = "Active Directory domain name. E.g., acme.local")]
            public String Domain { get; set; }

            [Option('v', "verbose", Default = false)]
            public bool Verbose { get; set; }
        }

        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {

                if (string.IsNullOrEmpty(o.Domain))
                {
                    Console.WriteLine("[!] Domain name required!");
                    return;
                }

                String domain = o.Domain.ToLower();

                Customer customer = new Customer(domain);
                customer.EnumerateUsers(domain, o.Verbose);

                Console.WriteLine("[+] Retrieving password policy");
                customer.GetPassPol(domain, o.Verbose);

                string jsonString = JsonSerializer.Serialize(customer);
                //Console.WriteLine($"{jsonString}");
            });
        }
    }
}
