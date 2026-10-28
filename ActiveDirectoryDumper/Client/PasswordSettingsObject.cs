using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// A fine-grained password policy (msDS-PasswordSettings object, "PSO") from
    /// CN=Password Settings Container,CN=System. A PSO overrides the domain password policy
    /// for the users and global security groups listed in msDS-PSOAppliesTo. When several apply,
    /// the lowest precedence value wins.
    /// </summary>
    public class PasswordSettingsObject
    {
        public string Name { get; private set; }
        public string DistinguishedName { get; private set; }
        public int Precedence { get; private set; }
        public bool ReversibleEncryptionEnabled { get; private set; }
        public bool ComplexityEnabled { get; private set; }
        public int MinPasswordLength { get; private set; }
        public int PwdHistoryLength { get; private set; }
        public double MinPwdAge { get; private set; }
        public double MaxPwdAge { get; private set; }
        public int LockoutThreshold { get; private set; }
        public double LockoutDuration { get; private set; }
        public double LockoutObservationWindow { get; private set; }

        /// <summary>Distinguished names of the users and groups this PSO is applied to.</summary>
        public string[] AppliesTo { get; private set; }

        public PasswordSettingsObject(
            string name,
            string distinguishedName,
            int precedence,
            bool reversibleEncryptionEnabled,
            bool complexityEnabled,
            int minPasswordLength,
            int pwdHistoryLength,
            double minPwdAge,
            double maxPwdAge,
            int lockoutThreshold,
            double lockoutDuration,
            double lockoutObservationWindow,
            string[] appliesTo
        )
        {
            this.Name = name;
            this.DistinguishedName = distinguishedName;
            this.Precedence = precedence;
            this.ReversibleEncryptionEnabled = reversibleEncryptionEnabled;
            this.ComplexityEnabled = complexityEnabled;
            this.MinPasswordLength = minPasswordLength;
            this.PwdHistoryLength = pwdHistoryLength;
            this.MinPwdAge = minPwdAge;
            this.MaxPwdAge = maxPwdAge;
            this.LockoutThreshold = lockoutThreshold;
            this.LockoutDuration = lockoutDuration;
            this.LockoutObservationWindow = lockoutObservationWindow;
            this.AppliesTo = appliesTo ?? Array.Empty<string>();
        }
    }
}
