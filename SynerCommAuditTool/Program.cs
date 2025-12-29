using CommandLine;
using ActiveDirectoryDumper.Client;
using ActiveDirectoryDumper.Util;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace ActiveDirectoryDumper
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
                if (!CheckandInstallDeps())
                    return;

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
                    extractor.Extract(o.Verbose, outputDir, customer);


                    customer.GenerateFiles(outputDir);
                    Console.WriteLine("[+] Generating zip file");
                    GenerateZip.Create(outputDir);
                }
                else
                {
                    try
                    {
                        Console.WriteLine("[+] Performing hash collection");
                        Extractor extractor = new Extractor();
                        Customer customer = new Customer();
                        extractor.Extract(o.Verbose, outputDir, customer);
                        Console.WriteLine($"[+] Hashes written to {outputDir}/hashes.pwdump");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Error collecting hashes! {ex.Message}");
                    }
                }
            });
        }

        static bool CheckandInstallDeps()
        {

            if (File.Exists(@"C:\Windows\System32\vcruntime140.dll") && File.Exists(@"C:\Windows\System32\msvcp140.dll"))
                return true;


            string redistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"Redist\vc_redist.x64.exe");
            if (!File.Exists(redistPath))
            {
                Console.WriteLine("[!] VC++ Redist not found!");
                return false;
            }
            using(Process vcinst = new Process())
            {
                vcinst.StartInfo.FileName = redistPath;
                vcinst.StartInfo.UseShellExecute = true;
                vcinst.StartInfo.Arguments = "/quiet /norestart";
                vcinst.StartInfo.Verb = "runas";
                vcinst.StartInfo.CreateNoWindow = true;

                vcinst.Start();
                vcinst.WaitForExit();
                if (vcinst.ExitCode != 0)
                {
                    Console.WriteLine($"[!] VC++ Redist failed with exit code: {vcinst.ExitCode}.");
                    Console.WriteLine("Visit \"https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170\" to install vc_redist.x64");
                    return false;
                }
                return true;
            }
        }
    }
}
