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

            [Option('d', "dumponly", Default = false, HelpText = "Do not perform collection, only dump hashes")]
            public bool Dump { get; set; }

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

                if (!o.Dump)
                {
                    String domain = o.Domain.ToLower();

                    Customer customer = new Customer(domain);
                    customer.EnumerateDomain(domain, o.Verbose);

                    string jsonString = JsonSerializer.Serialize(customer);
                    if (o.Verbose)
                        Console.WriteLine($"{jsonString}");

                    Console.WriteLine("[+] Generating CSV files");
                    customer.GenerateCSVs();
                }
                else
                {
                    Console.WriteLine("[+] Performing hash collection");
                    Extractor extractor = new Extractor();
                    extractor.Extract();
                }
            });
        }
    }
}
