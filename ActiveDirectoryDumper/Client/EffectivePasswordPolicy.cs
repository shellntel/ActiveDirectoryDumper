using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// The password and lockout policy that actually governs one account: the fine-grained
    /// password policy (PSO) that applies to it, or the domain policy when none does.
    /// Group Policy linked below the domain root never changes a domain account's policy.
    /// </summary>
    public class EffectivePasswordPolicy
    {
        /// <summary>"FineGrainedPolicy" or "DomainPolicy".</summary>
        public string Source { get; set; } = String.Empty;

        /// <summary>PSO name, or the domain name for the domain policy.</summary>
        public string PolicyName { get; set; } = String.Empty;

        public int MinPasswordLength { get; set; }
        public bool ComplexityEnabled { get; set; }
        public int PwdHistoryLength { get; set; }
        public double MinPwdAge { get; set; }
        /// <summary>Days. 0 means passwords never expire under this policy.</summary>
        public double MaxPwdAge { get; set; }
        public int LockoutThreshold { get; set; }
        public double LockoutDuration { get; set; }
        public double LockoutObservationWindow { get; set; }
        public bool ReversibleEncryptionEnabled { get; set; }
    }
}
