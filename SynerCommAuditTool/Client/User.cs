using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SynerCommAuditTool.Client
{
    public class User
    {
        public string Cn { get; set; }
        public string Name { get; set; }
        public string SamAccountName { get; set; }
        public string MemberOf { get; set; }
        public string DisplayName { get; set; }
        public string PrimaryGroupId { get; set; }
        public string WhenCreated { get; set; }
        public string WhenChanged { get; set; }
        public string LastLogon { get; set; }
        public string UserAccountControl { get; set; }
        public string PwdLastSet { get; set; }
        public string objectSid { get; set; }
        public string Description { get; set; }
    }
}
