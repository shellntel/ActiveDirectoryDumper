using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ActiveDirectoryDumper.Client
{
    public class Computer
    {
        public string Cn { get; private set; }
        public string SamAccountName { get; private set; }
        public string DNSHostName { get; private set; }
        public string OperatingSystem { get; private set; }
        public string OperatingSystemServicePack { get; private set; }
        public string OperatingSystemVersion { get; private set; }
        public string LastLogon { get; private set; }
        public string[] UserAccountControl { get; private set; }
        public string WhenCreated { get; private set; }
        public string SID { get; private set; }
        public string Description { get; private set; } 
        private string _ntlmHash;
        public string NTLMHash
        {
            get => _ntlmHash;
            set => _ntlmHash = value;
        }

    public Computer(
        string cn,
        string samAccountName,
        string dnsHostName,
        string os,
        string osServicePack,
        string osVersion,
        string lastLogon,
        string[] uacFlags,
        string createdOn,
        string sid,
        string description
    )
        {
            this.Cn = cn;
            this.SamAccountName = samAccountName;
            this.DNSHostName = dnsHostName;
            this.OperatingSystem = os;
            this.OperatingSystemServicePack = osServicePack;
            this.OperatingSystemVersion = osVersion;
            this.LastLogon = lastLogon;
            this.UserAccountControl = uacFlags;
            this.WhenCreated = createdOn;
            this.SID = sid;
            this.Description = description;
        }
    }
}
