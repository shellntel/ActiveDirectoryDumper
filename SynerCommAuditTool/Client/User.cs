using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SynerCommAuditTool.Client
{
    public class User
    {
        public string Cn { get; private set; }
        public string Name { get; private set; }
        public string First { get; private set; }
        public string Last { get; private set; }
        public string SamAccountName { get; private set; }
        public string MemberOf { get; private set; }
        public string DisplayName { get; private set; }
        public string PrimaryGroupId { get; private set; }
        public string WhenCreated { get; private set; }
        public string WhenChanged { get; private set; }
        public string LastLogon { get; private set; }
        public string[] UserAccountControl { get; private set; }
        public string PwdLastSet { get; private set; }
        public string LockoutTime { get; private set; }
        public string ObjectSid { get; private set; }
        public string Description { get; private set; }

        public User(
            string cn,
            string name,
            string first,
            string last,
            string samAccountName,
            string memberOf,
            string displayName,
            string primaryGroupId,
            string whenCreated,
            string whenChanged,
            string lastLogon,
            string[] userAccountControl,
            string pwdLastSet,
            string lockoutTime,
            string objectSid,
            string description
        )
        {
            this.Cn = cn;
            this.Name = name;
            this.First = first;
            this.Last = last;
            this.SamAccountName = samAccountName;
            this.MemberOf = memberOf;
            this.DisplayName = displayName;
            this.PrimaryGroupId = primaryGroupId;
            this.WhenCreated = whenCreated;
            this.WhenChanged = whenChanged;
            this.LastLogon = lastLogon;
            this.UserAccountControl = userAccountControl;
            this.PwdLastSet = pwdLastSet;
            this.LockoutTime = lockoutTime;
            this.ObjectSid = objectSid;
            this.Description = description;
        }
    }
}
