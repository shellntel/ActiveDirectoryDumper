using System;
using System.Collections.Generic;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>
    /// Domain-wide controls that affect password security, beyond the password policy itself.
    /// </summary>
    public class SecurityPosture
    {
        /// <summary>msDS-Behavior-Version of the domain, e.g. "Windows2016".</summary>
        public string DomainFunctionalLevel { get; set; } = String.Empty;
        public int DomainFunctionalLevelRaw { get; set; }

        /// <summary>The Entra (Azure AD) Password Protection container exists in the configuration partition, meaning a proxy was registered in this forest.</summary>
        public bool EntraPasswordProtectionContainerPresent { get; set; }

        /// <summary>Service connection points registered under that container (proxy servers).</summary>
        public int EntraPasswordProtectionProxyCount { get; set; }

        /// <summary>Service connection points named AzureADPasswordProtection* found in the domain (DC agents).</summary>
        public int EntraPasswordProtectionDcAgentCount { get; set; }

        /// <summary>Number of Domain Controllers (computers with SERVER_TRUST_ACCOUNT).</summary>
        public int DomainControllerCount { get; set; }

        /// <summary>
        /// [System Access] and [Kerberos Policy] settings resolved across the GPOs linked at the domain root,
        /// highest link precedence winning. These are the sources of the domain password, lockout and Kerberos
        /// policy; the authoritative resolved values are the domain object's own attributes.
        /// </summary>
        public List<PolicySetting> DomainAccountPolicySources { get; set; } = new List<PolicySetting>();

        /// <summary>
        /// Settings from all three sections resolved for the Domain Controllers OU (domain-linked GPOs, then the
        /// OU's GPOs, enforced domain GPOs last; block-inheritance honoured). Covers NoLMHash, LmCompatibilityLevel,
        /// cached logons, anonymous access and Netlogon machine-password settings as they apply on DCs.
        /// </summary>
        public List<PolicySetting> DomainControllerSettings { get; set; } = new List<PolicySetting>();
    }
}
