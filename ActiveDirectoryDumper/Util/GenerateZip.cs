using System;
using System.IO;
using System.IO.Compression;

namespace ActiveDirectoryDumper.Util
{
    public class GenerateZip
    {
        /// <summary>
        /// Builds a unique output base name of the form
        /// ActiveDirectoryDumper_&lt;domain&gt;_&lt;yyyyMMdd-HHmmss&gt; so that dumps from different
        /// domains or runs do not collide. Characters invalid in a file name are replaced with '_'.
        /// </summary>
        public static String BuildName(String domain, DateTime timestamp)
        {
            String safeDomain = String.IsNullOrEmpty(domain) ? "domain" : domain;
            foreach (char c in Path.GetInvalidFileNameChars())
            {
                safeDomain = safeDomain.Replace(c, '_');
            }
            return $"ActiveDirectoryDumper_{safeDomain}_{timestamp.ToString("yyyyMMdd-HHmmss")}";
        }

        /// <summary>
        /// Zips the contents of <paramref name="sourceDir"/> (files at the archive root, unchanged
        /// layout) into &lt;zipBaseName&gt;.zip, then deletes the source directory.
        /// </summary>
        public static void Create(String sourceDir, String zipBaseName)
        {
            if (!Directory.Exists(sourceDir))
            {
                Directory.CreateDirectory(sourceDir);
            }

            String zipPath = $"{zipBaseName}.zip";
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }
            ZipFile.CreateFromDirectory(sourceDir, zipPath);

            DirectoryInfo dirInfo = new DirectoryInfo(sourceDir);
            dirInfo.Delete(true);

            Console.WriteLine($"[+] Created zip file: {zipPath}");
        }
    }
}
