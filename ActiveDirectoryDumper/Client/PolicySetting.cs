using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>A security-template setting with the GPO that supplies its effective value.</summary>
    public class PolicySetting
    {
        /// <summary>"System Access", "Kerberos Policy" or "Registry Values".</summary>
        public string Section { get; set; } = String.Empty;

        /// <summary>Setting name, or the registry path for registry values.</summary>
        public string Name { get; set; } = String.Empty;

        /// <summary>Raw value as written in GptTmpl.inf. Registry values are "type,value" (4 = DWORD, 1 = string, 7 = multi-string).</summary>
        public string Value { get; set; } = String.Empty;

        public string SourceGpo { get; set; } = String.Empty;
    }
}
