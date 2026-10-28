using System;
using System.Collections.Generic;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// A Group Policy Object with the security-template settings read from SYSVOL
    /// (MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf) and where it is linked.
    ///
    /// Account policy settings in a GPO only affect domain accounts when the GPO is linked at the domain
    /// root; the authoritative resolved values live on the domain object. GPOs linked elsewhere change
    /// the local account policy of the computers in that scope.
    /// </summary>
    public class GroupPolicyObject
    {
        public string DisplayName { get; private set; }
        public string Guid { get; private set; }
        public string DistinguishedName { get; private set; }
        public string SysvolPath { get; private set; }

        /// <summary>GptTmpl.inf existed and was read.</summary>
        public bool GptTmplFound { get; set; }

        /// <summary>[System Access] section: MinimumPasswordLength, PasswordComplexity, ClearTextPassword, LockoutBadCount, ...</summary>
        public Dictionary<string, string> SystemAccess { get; set; } = new Dictionary<string, string>();

        /// <summary>[Kerberos Policy] section: MaxTicketAge, MaxRenewAge, MaxServiceAge, MaxClockSkew, TicketValidateClient.</summary>
        public Dictionary<string, string> KerberosPolicy { get; set; } = new Dictionary<string, string>();

        /// <summary>[Registry Values] section, keyed by registry path, value is "type,data".</summary>
        public Dictionary<string, string> RegistryValues { get; set; } = new Dictionary<string, string>();

        /// <summary>Raw value of ClearTextPassword in [System Access], or null when the GPO does not define it.</summary>
        public int? ClearTextPassword
        {
            get
            {
                string raw;
                int value;
                if (this.SystemAccess.TryGetValue("ClearTextPassword", out raw) && int.TryParse(raw, out value))
                {
                    return value;
                }
                return null;
            }
        }

        /// <summary>Convenience: the GPO defines ClearTextPassword = 1.</summary>
        public bool ReversibleEncryptionEnabled
        {
            get { return this.ClearTextPassword.HasValue && this.ClearTextPassword.Value == 1; }
        }

        /// <summary>GPO flags bit 0x2: computer configuration disabled (security settings would not apply).</summary>
        public bool ComputerSettingsDisabled { get; private set; }

        /// <summary>GPO flags bit 0x1: user configuration disabled.</summary>
        public bool UserSettingsDisabled { get; private set; }

        /// <summary>Every container whose gPLink references this GPO.</summary>
        public List<GpoLink> Links { get; set; } = new List<GpoLink>();

        /// <summary>Linked at the domain root with the link enabled, where account policies take effect for domain accounts.</summary>
        public bool LinkedToDomainRoot { get; set; }

        /// <summary>Error encountered while reading SYSVOL, if any.</summary>
        public string Error { get; set; } = String.Empty;

        public GroupPolicyObject(string displayName, string guid, string distinguishedName, string sysvolPath, int flags)
        {
            this.DisplayName = displayName;
            this.Guid = guid;
            this.DistinguishedName = distinguishedName;
            this.SysvolPath = sysvolPath;
            this.UserSettingsDisabled = (flags & 0x1) != 0;
            this.ComputerSettingsDisabled = (flags & 0x2) != 0;
        }
    }
}
