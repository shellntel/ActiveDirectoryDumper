using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// A password found in a Group Policy Preferences XML file in SYSVOL (MS14-025). GPP cpassword
    /// values are AES-encrypted with a key Microsoft published, so any authenticated user who can
    /// read SYSVOL can decrypt them. Microsoft stopped new ones being created in 2014 but did not
    /// remove existing ones; each is a standing credential exposure until the GPO is cleaned up and
    /// the account's password is changed.
    /// </summary>
    public class GppPassword
    {
        /// <summary>GPO display name that owns the file.</summary>
        public string Gpo { get; set; } = String.Empty;
        public string GpoGuid { get; set; } = String.Empty;

        /// <summary>Preference type: Groups, Services, ScheduledTasks, DataSources, Printers or Drives.</summary>
        public string FileType { get; set; } = String.Empty;

        /// <summary>Path of the XML file under SYSVOL.</summary>
        public string FilePath { get; set; } = String.Empty;

        /// <summary>The account the password belongs to (userName / accountName / runAs / username).</summary>
        public string UserName { get; set; } = String.Empty;

        /// <summary>The cpassword ciphertext as stored.</summary>
        public string CPassword { get; set; } = String.Empty;

        /// <summary>The decrypted password. This is the exposure: recoverable by any authenticated user.</summary>
        public string Password { get; set; } = String.Empty;

        /// <summary>True when the cpassword decrypted successfully.</summary>
        public bool Decrypted { get; set; }

        /// <summary>The "changed" timestamp on the preference element, if present.</summary>
        public string Changed { get; set; } = String.Empty;
    }
}
