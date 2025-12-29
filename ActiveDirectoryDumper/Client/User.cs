namespace ActiveDirectoryDumper.Client
{
    public class User
    {
        public string Cn { get; private set; }
        public string Name { get; private set; }
        public string First { get; private set; }
        public string Last { get; private set; }
        public string SamAccountName { get; private set; }
        public string GroupMemberCount { get; private set; }
        public string[] MemberOf { get; private set; }
        public string DisplayName { get; private set; }
        public string PrimaryGroupId { get; private set; }
        public string WhenCreated { get; private set; }
        public string WhenChanged { get; private set; }
        public string LastLogon { get; private set; }
        public string[] UserAccountControl { get; private set; }
        public string RawUACValue { get; private set; }
        public string PwdLastSet { get; private set; }
        public string LockoutTime { get; private set; }
        public string ObjectSid { get; private set; }
        public string Description { get; private set; }
        private string _ntlmHash;
        public string NTLMHash
        {
            get => _ntlmHash;
            set => _ntlmHash = value;
        }
        private string[] _historicalNTLMHashes = new string[0];
        public string[] HistoricalNTHashes
        {
            get => _historicalNTLMHashes;
            set => _historicalNTLMHashes = value;
        }
        private string _logonName; 
        public string LogonName
        {
            get => _logonName;
            set => _logonName = value;
        }
        public string[] ServicePrincipalNames { get; private set; }
        public string adminCount { get; private set; }
        public string supportedEncryptionTypes { get; private set; }
        public string[] allowedToDelegateTo {  get; private set; }

        public User(
            string cn,
            string name,
            string first,
            string last,
            string samAccountName,
            string groupMemberCount,
            string[] memberOf,
            string displayName,
            string primaryGroupId,
            string whenCreated,
            string whenChanged,
            string lastLogon,
            string[] userAccountControl,
            string rawUACValue,
            string pwdLastSet,
            string lockoutTime,
            string objectSid,
            string description,
            string[] servicePrincipalNames,
            string adminCount,
            string supportedEncryptionTypes,
            string[] allowedToDelegateTo
        )
        {
            this.Cn = cn;
            this.Name = name;
            this.First = first;
            this.Last = last;
            this.SamAccountName = samAccountName;
            this.GroupMemberCount = groupMemberCount;
            this.MemberOf = memberOf;
            this.DisplayName = displayName;
            this.PrimaryGroupId = primaryGroupId;
            this.WhenCreated = whenCreated;
            this.WhenChanged = whenChanged;
            this.LastLogon = lastLogon;
            this.UserAccountControl = userAccountControl;
            this.RawUACValue = rawUACValue;
            this.PwdLastSet = pwdLastSet;
            this.LockoutTime = lockoutTime;
            this.ObjectSid = objectSid;
            this.Description = description;
            this.ServicePrincipalNames = servicePrincipalNames;
            this.adminCount = adminCount;
            this.supportedEncryptionTypes = supportedEncryptionTypes;
            this.allowedToDelegateTo = allowedToDelegateTo;
        }
    }
}
