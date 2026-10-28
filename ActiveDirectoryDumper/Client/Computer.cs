using System;

namespace ActiveDirectoryDumper.Client
{
    public class Computer
    {
        public string Cn { get; private set; }
        public string SamAccountName { get; private set; }
        public string DNSHostName { get; private set; }
        public string OperatingSystem { get; private set; }
        public string OperatingSystemServicePack { get; private set; }
        public string OperatingSystemVersion { get; private set; }
        public string LastLogon { get; private set; }
        public string[] UserAccountControl { get; private set; }
        public string WhenCreated { get; private set; }
        public string SID { get; private set; }
        public string Description { get; private set; }
        private string _ntlmHash;
        public string NTLMHash
        {
            get => _ntlmHash;
            set => _ntlmHash = value;
        }

        // ---- Added for the 2.4 password-security analysis. Timestamps are ISO 8601 UTC. ----

        public string DistinguishedName { get; set; } = String.Empty;

        /// <summary>"Computer", "GroupManagedServiceAccount" or "ManagedServiceAccount". Managed service accounts have random, rotated passwords.</summary>
        public string AccountType { get; set; } = "Computer";

        public bool IsDomainController { get; set; }

        /// <summary>Replicated last logon (lastLogonTimestamp).</summary>
        public string LastLogonTimestamp { get; set; } = String.Empty;

        /// <summary>When the machine password was last changed (ISO 8601 UTC). Member computers rotate every 30 days by default.</summary>
        public string PwdLastSetUtc { get; set; } = String.Empty;

        /// <summary>Legacy LAPS (ms-Mcs-AdmPwdExpirationTime) and Windows LAPS (msLAPS-PasswordExpirationTime) expiry, when managed. The passwords are never read.</summary>
        public string LapsLegacyExpiration { get; set; } = String.Empty;
        public string LapsWindowsExpiration { get; set; } = String.Empty;
        public bool LapsManaged { get; set; }

        public StoredCredentials StoredCredentials { get; set; } = new StoredCredentials();
        public ReversibleEncryptionStatus ReversibleEncryption { get; set; } = new ReversibleEncryptionStatus();

    public Computer(
        string cn,
        string samAccountName,
        string dnsHostName,
        string os,
        string osServicePack,
        string osVersion,
        string lastLogon,
        string[] uacFlags,
        string createdOn,
        string sid,
        string description
    )
        {
            this.Cn = cn;
            this.SamAccountName = samAccountName;
            this.DNSHostName = dnsHostName;
            this.OperatingSystem = os;
            this.OperatingSystemServicePack = osServicePack;
            this.OperatingSystemVersion = osVersion;
            this.LastLogon = lastLogon;
            this.UserAccountControl = uacFlags;
            this.WhenCreated = createdOn;
            this.SID = sid;
            this.Description = description;
            string[] flags = uacFlags ?? Array.Empty<string>();
            this.ReversibleEncryption.AccountFlagSet = Array.IndexOf(flags, UacFlags.PASSWORD_STORE_CLEARTEXT.ToString()) >= 0;
            this.IsDomainController = Array.IndexOf(flags, UacFlags.SERVER_TRUST_ACCOUNT.ToString()) >= 0;
        }
    }
}
