using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SynerCommAuditTool.Util
{
    public class GenerateZip
    {
        public static void Create(String outputDir)
        {
            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            if (File.Exists($"{outputDir}.zip"))
            {
                File.Delete($"{outputDir}.zip");
            }
            ZipFile.CreateFromDirectory(outputDir, $"{outputDir}.zip");

            DirectoryInfo dirInfo = new DirectoryInfo(outputDir);
            dirInfo.Delete(true);

            Console.WriteLine($"[+] Created zip file: {outputDir}.zip");
        }
    }
}
