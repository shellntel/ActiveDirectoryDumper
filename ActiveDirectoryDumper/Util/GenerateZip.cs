using System;
using System.IO;
using System.IO.Compression;

namespace ActiveDirectoryDumper.Util
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
