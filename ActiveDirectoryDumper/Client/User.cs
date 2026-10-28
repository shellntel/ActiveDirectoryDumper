using System;

namespace ActiveDirectoryDumper.Client
{
    public class User
    {
        public string Cn { get; private set; }
        public string DistinguishedName { get; private set; }
        public string Name { get; private set; }
        public string First { get; private set; }
        public string Last { get; private set; }
        public string SamAccountName { get; private set; }
        public string GroupMemberCount { get; private set; }
        public string[] MemberOf { get; private set; }
        public string DisplayName { get; private set; }
        public string PrimaryGroupId { get; private set; }
        public string WhenCreated { get; private set; }
        public string WhenChanged { get; private set; }
        public string LastLogon { get; private set; }
        public string[] UserAccountControl { get; private set; }
        public string RawUACValue { get; private set; }
        public string PwdLastSet { get; private set; }
        public string LockoutTime { get; private set; }
        public string ObjectSid { get; private set; }
        public string Description { get; private set; }
        private string _ntlmHash;
        public string NTLMHash
        {
            get => _ntlmHash;
            set => _ntlmHash = value;
        }
        private string[] _historicalNTLMHashes = new string[0];
        public string[] HistoricalNTHashes
        {
            get => _historicalNTLMHashes;
            set => _historicalNTLMHashes = value;
        }
        private string _logonName;
        public string LogonName
        {
            get => _logonName;
            set => _logonName = value;
        }
        public string[] ServicePrincipalNames { get; private set; }
        public string adminCount { get; private set; }
        public string supportedEncryptionTypes { get; private set; }
        public string[] allowedToDelegateTo {  get; private set; }

        // ---- Added for the 2.4 password-security analysis. Timestamps are ISO 8601 UTC. ----

        /// <summary>Replicated last logon (lastLogonTimestamp, accurate to about 14 days). lastLogon above is per-DC and unreliable.</summary>
        public string LastLogonTimestamp { get; set; } = String.Empty;

        /// <summary>pwdLastSet with full precision; PwdLastSet above is a date only.</summary>
        public string PwdLastSetUtc { get; set; } = String.Empty;

        /// <summary>accountExpires, "Never", or empty.</summary>
        public string AccountExpires { get; set; } = String.Empty;

        /// <summary>msDS-UserPasswordExpiryTimeComputed: when the current password expires under the effective policy, "Never", or "Expired".</summary>
        public string PasswordExpiryTime { get; set; } = String.Empty;

        /// <summary>Flags from msDS-User-Account-Control-Computed (ACCOUNT_LOCKED, PASSWORD_EXPIRED, ...), the DC's live view.</summary>
        public string[] UserAccountControlComputed { get; set; } = Array.Empty<string>();
        public bool LockedOut { get; set; }
        public bool PasswordExpired { get; set; }

        /// <summary>Free-text fields that often hold passwords, alongside Description.</summary>
        public string Info { get; set; } = String.Empty;
        public string Comment { get; set; } = String.Empty;

        /// <summary>Names of legacy password attributes present on the object (userPassword, unixUserPassword, msSFU30Password). Values are not collected.</summary>
        public string[] LegacyPasswordAttributes { get; set; } = Array.Empty<string>();

        /// <summary>Privileged groups the account belongs to, including through nested groups and primary group.</summary>
        public string[] PrivilegedGroups { get; set; } = Array.Empty<string>();
        public bool IsPrivileged { get; set; }
        public bool IsProtectedUser { get; set; }

        /// <summary>True for the krbtgt account and RODC krbtgt_* accounts.</summary>
        public bool IsKrbtgt { get; set; }

        /// <summary>Relative identifier from objectSid; 500 is the built-in Administrator, 501 Guest, 502 krbtgt.</summary>
        public int Rid { get; set; }

        public EffectivePasswordPolicy EffectivePasswordPolicy { get; set; } = new EffectivePasswordPolicy();
        public StoredCredentials StoredCredentials { get; set; } = new StoredCredentials();
        public ReversibleEncryptionStatus ReversibleEncryption { get; set; } = new ReversibleEncryptionStatus();

        public User(
            string cn,
            string distinguishedName,
            string name,
            string first,
            string last,
            string samAccountName,
            string groupMemberCount,
            string[] memberOf,
            string displayName,
            string primaryGroupId,
            string whenCreated,
            string whenChanged,
            string lastLogon,
            string[] userAccountControl,
            string rawUACValue,
            string pwdLastSet,
            string lockoutTime,
            string objectSid,
            string description,
            string[] servicePrincipalNames,
            string adminCount,
            string supportedEncryptionTypes,
            string[] allowedToDelegateTo
        )
        {
            this.Cn = cn;
            this.DistinguishedName = distinguishedName;
            this.Name = name;
            this.First = first;
            this.Last = last;
            this.SamAccountName = samAccountName;
            this.GroupMemberCount = groupMemberCount;
            this.MemberOf = memberOf;
            this.DisplayName = displayName;
            this.PrimaryGroupId = primaryGroupId;
            this.WhenCreated = whenCreated;
            this.WhenChanged = whenChanged;
            this.LastLogon = lastLogon;
            this.UserAccountControl = userAccountControl;
            this.RawUACValue = rawUACValue;
            this.PwdLastSet = pwdLastSet;
            this.LockoutTime = lockoutTime;
            this.ObjectSid = objectSid;
            this.Description = description;
            this.ServicePrincipalNames = servicePrincipalNames;
            this.adminCount = adminCount;
            this.supportedEncryptionTypes = supportedEncryptionTypes;
            this.allowedToDelegateTo = allowedToDelegateTo;
        }
    }
}
