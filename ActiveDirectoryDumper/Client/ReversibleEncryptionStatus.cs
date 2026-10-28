using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// String constants for <see cref="ReversibleEncryptionStatus.Status"/>.
    /// </summary>
    public static class ReversibleEncryptionState
    {
        /// <summary>Reversible encryption is not enabled for this account by any source and no cleartext password is stored.</summary>
        public const string NotEnabled = "NotEnabled";

        /// <summary>Reversible encryption is enabled (account flag, PSO or domain policy) but the password has not been changed since, so nothing is stored yet.</summary>
        public const string EnabledNotStored = "EnabledNotStored";

        /// <summary>Reversible encryption is enabled and a cleartext password is stored in NTDS.dit.</summary>
        public const string Stored = "Stored";

        /// <summary>A cleartext password is stored in NTDS.dit even though the setting is no longer in effect. It persists until the next password change.</summary>
        public const string StoredSettingDisabled = "StoredSettingDisabled";

        /// <summary>The NTDS.dit contents for this account were not examined (hash extraction did not run or did not return the account).</summary>
        public const string Unknown = "Unknown";
    }

    /// <summary>
    /// String constants for <see cref="ReversibleEncryptionStatus.EffectiveSource"/>.
    /// </summary>
    public static class ReversibleEncryptionSource
    {
        public const string None = "None";
        public const string Account = "Account";
        public const string FineGrainedPolicy = "FineGrainedPolicy";
        public const string DomainPolicy = "DomainPolicy";
    }

    /// <summary>
    /// Per-account view of whether the password is, or will be, stored with reversible encryption.
    ///
    /// Four sources are combined:
    ///  1. The account's own userAccountControl flag (0x80, ENCRYPTED_TEXT_PWD_ALLOWED).
    ///  2. The fine-grained password policy (PSO) that applies to the account, if any.
    ///  3. The domain password policy (pwdProperties bit 0x10, DOMAIN_PASSWORD_STORE_CLEARTEXT).
    ///  4. What is actually stored in NTDS.dit (the Primary:CLEARTEXT package in supplementalCredentials).
    ///
    /// Sources 1-3 say whether the setting is in effect. Source 4 says whether a cleartext password really
    /// exists, which only happens when the password is set while the setting is in effect.
    /// </summary>
    public class ReversibleEncryptionStatus
    {
        /// <summary>userAccountControl bit 0x80 is set on the account object.</summary>
        public bool AccountFlagSet { get; set; }

        /// <summary>The domain password policy enables reversible encryption (pwdProperties bit 0x10).</summary>
        public bool DomainPolicyEnabled { get; set; }

        /// <summary>Name of the fine-grained password policy applied to this account, or an empty string.</summary>
        public string ResultantPso { get; set; } = String.Empty;

        /// <summary>How the resultant PSO was determined: "msDS-ResultantPSO" (DC computed) or "DirectMatch" (fallback), or empty.</summary>
        public string ResultantPsoSource { get; set; } = String.Empty;

        /// <summary>Whether the resultant PSO enables reversible encryption. Null when no PSO applies.</summary>
        public bool? PsoEnabled { get; set; }

        /// <summary>Reversible encryption is in effect for this account right now.</summary>
        public bool EffectivelyEnabled { get; set; }

        /// <summary>Which source makes it effective. See <see cref="ReversibleEncryptionSource"/>.</summary>
        public string EffectiveSource { get; set; } = ReversibleEncryptionSource.None;

        /// <summary>True when the NTDS.dit data for this account was examined during hash extraction.</summary>
        public bool NtdsChecked { get; set; }

        /// <summary>A cleartext (reversibly encrypted) password is present in supplementalCredentials.</summary>
        public bool ClearTextPasswordStored { get; set; }

        /// <summary>Length of the stored cleartext password, or 0. The password itself is never written to the output.</summary>
        public int ClearTextPasswordLength { get; set; }

        /// <summary>Final classification. See <see cref="ReversibleEncryptionState"/>.</summary>
        public string Status { get; set; } = ReversibleEncryptionState.Unknown;
    }
}
