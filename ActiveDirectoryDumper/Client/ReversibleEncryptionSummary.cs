using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// Domain-wide roll-up of the reversible encryption analysis, for the report.
    /// </summary>
    public class ReversibleEncryptionSummary
    {
        public bool DomainPolicyEnabled { get; set; }
        public int PsoCount { get; set; }
        public int PsosEnablingReversibleEncryption { get; set; }
        public string[] PsoNamesEnablingReversibleEncryption { get; set; } = Array.Empty<string>();
        public int GpoCount { get; set; }
        public int GposEnablingReversibleEncryption { get; set; }
        public string[] GpoNamesEnablingReversibleEncryption { get; set; } = Array.Empty<string>();

        public int UsersWithAccountFlag { get; set; }
        public int UsersEffectivelyEnabled { get; set; }
        public int UsersEnabledNotStored { get; set; }
        public int UsersWithClearTextStored { get; set; }
        public int UsersStoredSettingDisabled { get; set; }
        public string[] UsersWithClearTextStoredNames { get; set; } = Array.Empty<string>();

        public int ComputersWithAccountFlag { get; set; }
        public int ComputersWithClearTextStored { get; set; }
        public string[] ComputersWithClearTextStoredNames { get; set; } = Array.Empty<string>();

        /// <summary>True when NTDS.dit was examined, so the "stored" counts are meaningful.</summary>
        public bool NtdsChecked { get; set; }
    }
}
