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
            [Option('d', "dumponly", Default = false, HelpText = "Do not perform collection, only dump hashes")]
            public bool Dump { get; set; }

            [Option('v', "verbose", Default = false)]
            public bool Verbose { get; set; }
        }

        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {

                if (!o.Dump)
                {
                    Customer customer = new Customer();
                    customer.EnumerateDomain(o.Verbose);

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
