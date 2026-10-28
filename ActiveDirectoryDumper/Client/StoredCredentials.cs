using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// Facts about the secrets stored for an account in NTDS.dit, observed during hash extraction.
    /// No key or hash material is kept here; the hashes go to the pwdump files as before.
    /// </summary>
    public class StoredCredentials
    {
        /// <summary>True when the account was seen during replication, so the other fields are meaningful.</summary>
        public bool NtdsChecked { get; set; }

        /// <summary>An LM hash other than the empty-password value is stored. LM hashes are trivially crackable.</summary>
        public bool HasLmHash { get; set; }

        /// <summary>The NT hash is the hash of an empty password.</summary>
        public bool HasBlankNtHash { get; set; }

        /// <summary>Number of NT hashes in the password history.</summary>
        public int NtHashHistoryCount { get; set; }

        /// <summary>Kerberos keys exist for this account (Primary:Kerberos-Newer-Keys or Primary:Kerberos).</summary>
        public bool HasKerberosKeys { get; set; }

        /// <summary>Encryption types of the current Kerberos keys, e.g. AES256_CTS_HMAC_SHA1_96, RC4_HMAC_NT, DES_CBC_MD5.</summary>
        public string[] KerberosKeyTypes { get; set; } = Array.Empty<string>();

        /// <summary>At least one AES key is stored. Accounts whose password predates AES support hold only RC4 or DES keys.</summary>
        public bool HasAesKeys { get; set; }

        /// <summary>A DES key is stored.</summary>
        public bool HasDesKeys { get; set; }

        /// <summary>Kerberos keys exist but none of them is AES, so Kerberos tickets for this account are protected only by RC4 or DES.</summary>
        public bool NoAesKeys { get; set; }
    }
}
