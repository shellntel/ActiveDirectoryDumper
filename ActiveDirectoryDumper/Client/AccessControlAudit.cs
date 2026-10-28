using System;
using System.Collections.Generic;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>One access-control entry of interest on a sensitive object.</summary>
    public class AclRight
    {
        /// <summary>Which object: "Domain" or "AdminSDHolder".</summary>
        public string Object { get; set; } = String.Empty;
        public string ObjectDn { get; set; } = String.Empty;

        /// <summary>Resolved trustee name, or the SID when it cannot be resolved.</summary>
        public string Principal { get; set; } = String.Empty;
        public string PrincipalSid { get; set; } = String.Empty;

        /// <summary>The right granted, e.g. DS-Replication-Get-Changes-All, GenericAll, WriteDacl, AllExtendedRights.</summary>
        public string Right { get; set; } = String.Empty;

        /// <summary>Allow or Deny.</summary>
        public string AccessType { get; set; } = String.Empty;

        /// <summary>True for well-known principals that legitimately hold this right (DCs, Domain/Enterprise Admins, SYSTEM).
        /// A non-default holder is the finding.</summary>
        public bool IsDefault { get; set; }
    }

    /// <summary>
    /// Access-control findings on objects that control the domain's security:
    /// who can replicate directory secrets (DCSync) from the domain head, and who can modify
    /// AdminSDHolder (whose DACL is stamped onto every protected/privileged account by SDProp).
    /// </summary>
    public class AccessControlAudit
    {
        /// <summary>Principals granted directory-replication rights on the domain head.</summary>
        public List<AclRight> DcSyncRights { get; set; } = new List<AclRight>();

        /// <summary>Principals granted control rights (GenericAll/WriteDacl/WriteOwner/WriteProperty/AllExtendedRights) on AdminSDHolder.</summary>
        public List<AclRight> AdminSdHolderRights { get; set; } = new List<AclRight>();

        public bool DomainAclRead { get; set; }
        public bool AdminSdHolderAclRead { get; set; }

        /// <summary>Count of non-default DCSync holders (the headline finding).</summary>
        public int NonDefaultDcSyncHolders { get; set; }

        /// <summary>Count of non-default AdminSDHolder control holders.</summary>
        public int NonDefaultAdminSdHolderHolders { get; set; }
    }
}
