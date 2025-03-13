using CommandLine;
using SynerCommAuditTool.Client;
using SynerCommAuditTool.Util;
using System;
using System.IO;
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

                String outputDir = "SynerCommAuditTool_DomainOutput";

                if (!Directory.Exists(outputDir))
                {
                    Directory.CreateDirectory(outputDir);
                }

                if (!o.Dump)
                {
                    Customer customer = new Customer();
                    customer.EnumerateDomain(o.Verbose, outputDir);

                    //string jsonString = JsonSerializer.Serialize(customer);
                    //if (o.Verbose)
                    //    Console.WriteLine($"{jsonString}");

                    Console.WriteLine("[+] Performing hash collection");
                    Extractor extractor = new Extractor();
                    extractor.Extract(o.Verbose, outputDir);

                    Console.WriteLine("[+] Generating zip file");
                    GenerateZip.Create(outputDir);
                }
                else
                {
                    try
                    {
                        Console.WriteLine("[+] Performing hash collection");
                        Extractor extractor = new Extractor();
                        extractor.Extract(o.Verbose, outputDir);
                        Console.WriteLine($"[+] Hashes written to {outputDir}/hashes.pwdump");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Error collecting hashes! {ex.Message}");
                    }
                }
            });
        }
    }
}
