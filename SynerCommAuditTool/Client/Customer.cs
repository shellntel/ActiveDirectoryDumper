using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Security.Principal;
using System.Text.Json;

namespace SynerCommAuditTool.Client
{
    enum UacFlags : uint
    {
        ACCOUNT_DISABLED = 0x00000002,
        ACCOUNT_LOCKED = 0x00000010,
        PASSWD_NOTREQD = 0x00000020,
        PASSWD_CANT_CHANGE = 0x00000040,
        PASSWORD_STORE_CLEARTEXT = 0x00000080,
        NORMAL_ACCOUNT = 0x00000200,
        WORKSTATION_ACCOUNT = 0x00001000,
        SERVER_TRUST_ACCOUNT = 0x00002000,
        DONT_EXPIRE_PASSWORD = 0x00010000,
        SMARTCARD_REQUIRED = 0x00040000,
        TRUSTED_FOR_DELEGATION = 0x00080000,
        NOT_DELEGATED = 0x00100000,
        USE_DES_KEY_ONLY = 0x00200000,
        DONT_REQ_PREAUTH = 0x00400000,
        PASSWORD_EXPIRED = 0x00800000,
        TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000,
        PARTIAL_SECRETS_ACCOUNT = 0x04000000,
        SCRIPT = 0x00000001,
        HOMEDIR_REQUIRED = 0x0008,
        TEMP_DUPLICATE_ACCOUNT = 0x0100,
        INTERDOMAIN_TRUST_ACCOUNT = 0x0800,
        MNS_LOGON_ACCOUNT = 0x20000
    }


    public class Customer
    {
        public string Name { get; private set; }
        public string PullDate { get; private set; }
        public int UserCount { get; private set; }
        public double MinPwdAge { get; private set; }
        public double MaxPwdAge { get; private set; }
        public int MinPasswordLength { get; private set; }
        public int PwdProperties { get; private set; }
        public double LockoutDuration { get; private set; }
        public double LockoutObservationWindow { get; private set; }
        public int LockoutThreshold { get; private set; }
        public int PwdHistoryLength { get; private set; }

        public List<Dictionary<String, String>> DomainTrusts { get; private set; }
        public User[] Users { get; private set; }

        public Group[] Groups { get; private set; }


        public Customer()
        {
            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);

            this.Name = adDomain.Name;
            this.PullDate = DateTime.Now.ToString("MM/dd/yyyy");
        }

        private string[] ParseUacFlags(String uacVal)
        {
            List<String> flags = new List<String>();
            foreach (uint i in Enum.GetValues(typeof(UacFlags)))
            {
                String flagName = Enum.GetName(typeof(UacFlags), i);

                if ((uint.Parse(uacVal) & i) != 0)
                {
                    flags.Add(flagName);
                }
            }

            return flags.ToArray();
        }

        private String GetLdapString()
        {
            String domain = this.Name;

            string[] domainFqdn = domain.Split('.');

            String endString = $"dc={domainFqdn[domainFqdn.Length - 1]}";
            String LdapString = "LDAP://";

            for (int i = 0; i <= domainFqdn.Length - 2; i++)
            {
                LdapString += $"dc={domainFqdn[i]},";
            }

            LdapString += endString;

            return LdapString;
        }

        private String ParseDateTime(long propCol)
        {
            if (propCol == 0)
            {
                return "0";
            }

            DateTime dt = DateTime.FromFileTime(propCol);

            return $"{dt.Month}/{dt.Day}/{dt.ToString("yyyy")}";
        }

        private (string, string) ParseName(String name)
        {
            if (name.Split(' ').Length == 1)
            {
                return (String.Empty, String.Empty);
            }

            String[] nameArray = name.Split(' ');

            String first = nameArray[0];

            // make sure to account for multiple last names
            int arrayLenMinusFirst = nameArray.Length - 1;
            String[] slicedArray = new string[arrayLenMinusFirst];
            Array.Copy(nameArray, 1, slicedArray, 0, arrayLenMinusFirst);

            String last = String.Join(" ", slicedArray);

            return (first, last);
        }

        public void EnumerateDomain(bool verbose, String outputDir)
        {
            Console.WriteLine("[+] Starting enumeration");

            String LdapString = GetLdapString();

            Console.WriteLine("[+] Connecting to LDAP");

            DirectoryEntry directoryEntry = new DirectoryEntry(LdapString);
            directoryEntry.RefreshCache();

            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(&(objectCategory=person)(objectClass=user))");
            String[] userProperties = new string[] {
                "cn",
                "name",
                "samaccountname",
                "memberof",
                "displayname",
                "primarygroupid",
                "whencreated",
                "whenchanged",
                "lastlogon",
                "useraccountcontrol",
                "pwdlastset",
                "lockouttime",
                "objectsid",
                "description"
            };

            directorySearcher.PropertiesToLoad.AddRange(userProperties);


            SearchResultCollection results = directorySearcher.FindAll();

            Console.WriteLine($"[*] Found {results.Count} users!");
            this.UserCount = results.Count;

            this.Users = new User[results.Count];

            int count = 0;
            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultPropColl = result.Properties;

                String cn = resultPropColl["cn"].Count > 0 ? resultPropColl["cn"][0].ToString() : "";
                String name = resultPropColl["name"].Count > 0 ? resultPropColl["name"][0].ToString() : "";
                String samAccountName = resultPropColl["samAccountName"].Count > 0 ? resultPropColl["samAccountName"][0].ToString() : "";
                String memberOf = resultPropColl["memberof"].Count > 0 ? resultPropColl["memberof"][0].ToString() : "";
                String displayName = resultPropColl["displayname"].Count > 0 ? resultPropColl["displayname"][0].ToString() : "";
                String primaryGroupId = resultPropColl["primarygroupid"].Count > 0 ? resultPropColl["primarygroupid"][0].ToString() : "";
                String description = resultPropColl["description"].Count > 0 ? resultPropColl["description"][0].ToString() : "";
                String pwdLastSet = resultPropColl["pwdlastset"].Count > 0 ? this.ParseDateTime((long)resultPropColl["pwdlastset"][0]) : "";
                String lockoutTime = resultPropColl["lockouttime"].Count > 0 ? this.ParseDateTime((long)resultPropColl["lockouttime"][0]) : "";
                String whenCreated = resultPropColl["whencreated"].Count > 0 ? resultPropColl["whencreated"][0].ToString() : "";
                String whenChanged = resultPropColl["whenchanged"].Count > 0 ? resultPropColl["whenchanged"][0].ToString() : "";
                String lastLogon = resultPropColl["lastlogon"].Count > 0 ? this.ParseDateTime((long)resultPropColl["lastlogon"][0]) : "";

                (String first, String last) = this.ParseName(name);
                List<String> memberGroups = new List<String>();
                int groupMemberCount = resultPropColl["memberof"].Count;

                if (groupMemberCount > 0)
                {
                    foreach (String item in resultPropColl["memberof"])
                    {
                        String groupString = item.Split(',')[0];
                        memberGroups.Add(groupString.Substring(3));
                    }
                }

                String objectSid = "";
                if (resultPropColl["objectsid"].Count > 0)
                {
                    SecurityIdentifier sid = new SecurityIdentifier((byte[])resultPropColl["objectSid"][0], 0);
                    objectSid = sid.ToString();
                }

                String userAccountControl = resultPropColl["useraccountcontrol"].Count > 0 ? resultPropColl["useraccountcontrol"][0].ToString() : "";
                String[] uacFlags = Array.Empty<string>();

                if (!string.IsNullOrEmpty(userAccountControl))
                {
                    uacFlags = this.ParseUacFlags(userAccountControl);
                }

                if (verbose)
                {
                    Console.WriteLine($"CN: {cn}, SamAccountName: {samAccountName}, Group Count: {groupMemberCount}, UAC Flags: [{String.Join(",", uacFlags)}], Password Last Set: {pwdLastSet}, SID: {objectSid}, Description: {description}");
                }

                User user = new User(
                    cn,
                    name,
                    first,
                    last,
                    samAccountName,
                    groupMemberCount.ToString(),
                    memberGroups.ToArray(),
                    displayName,
                    primaryGroupId,
                    whenCreated,
                    whenChanged,
                    lastLogon,
                    uacFlags,
                    pwdLastSet,
                    lockoutTime,
                    objectSid,
                    description
                );

                this.Users[count] = user;

                count++;
            }

            results.Dispose();
            directoryEntry.Dispose();
            directorySearcher.Dispose();

            this.GetDomainTrusts(verbose);
            this.GetGroupInfo(verbose);
            this.GetPassPol(verbose);

            //this.GenerateCSVs(outputDir);
        }

        private (String, String) ParseTrustInfo(String trustDirection, String trustType)
        {
            String parsedTrustDirection = String.Empty;
            String parsedTrustType = String.Empty;

            switch (trustDirection)
            {
                case "1":
                    parsedTrustDirection = "Inbound";
                    break;
                case "2":
                    parsedTrustDirection = "Outbound";
                    break;
                case "3":
                    parsedTrustDirection = "Bidirectional";
                    break;
                default:
                    parsedTrustDirection = "Unknown";
                    break;
            }

            switch (trustType)
            {
                case "1":
                    parsedTrustType = "Downlevel";
                    break;
                case "2":
                    parsedTrustType = "Uplevel";
                    break;
                case "3":
                    parsedTrustType = "MIT";
                    break;
                case "4":
                    parsedTrustType = "DCE";
                    break;
                default:
                    parsedTrustType = "Unknown";
                    break;
            }

            return (parsedTrustDirection, parsedTrustType);
        }

        public void GetDomainTrusts(bool verbose)
        {
            Console.WriteLine("[+] Finding Domain Trusts");

            String LdapString = GetLdapString();

            DirectoryEntry directoryEntry = new DirectoryEntry(LdapString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=trustedDomain)");

            String[] trustFields = { "trustpartner", "trustdirection", "trusttype" };

            directorySearcher.PropertiesToLoad.AddRange(trustFields);

            SearchResultCollection results = directorySearcher.FindAll();
            if (results.Count == 0)
            {
                Console.WriteLine("[+] No Trusts found!");
                return;
            }

            List<Dictionary<String, String>> domainTrusts = new List<Dictionary<String, String>>();

            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultPropColl = result.Properties;

                String trustPartner = resultPropColl["trustpartner"].Count > 0 ? resultPropColl["trustpartner"][0].ToString() : "";
                String trustDirection = resultPropColl["trustdirection"].Count > 0 ? resultPropColl["trustdirection"][0].ToString() : "";
                String trustType = resultPropColl["trustType"].Count > 0 ? resultPropColl["trustType"][0].ToString() : "";

                (String parsedTrustDirection, String parsedTrustType) = this.ParseTrustInfo(trustDirection, trustType);

                if (verbose)
                {
                    Console.WriteLine($"Trust: {trustPartner}");
                    Console.WriteLine($"Trust Direction: {parsedTrustDirection}");
                    Console.WriteLine($"Trust Type: {parsedTrustType}");
                }

                Dictionary<String, String> trust = new Dictionary<String, String>();

                trust.Add("Trust", trustPartner);
                trust.Add("TrustDirection", parsedTrustDirection);
                trust.Add("TrustType", parsedTrustType);

                domainTrusts.Add(trust);
            }
            this.DomainTrusts = domainTrusts;
        }

        private String ParseGroupType(int groupType)
        {
            bool isSecurity = (groupType & 0x80000000) != 0;
            String securityType = isSecurity ? "Security" : "Distribution";

            int scope = groupType & 0x0000000E;
            String scopeType = String.Empty;

            switch (scope)
            {
                case 2:
                    scopeType = "Global";
                    break;
                case 4:
                    scopeType = "Domain Local";
                    break;
                case 8:
                    scopeType = "Universal";
                    break;
                default:
                    scopeType = "Unknown";
                    break;
            }
            return $"{scopeType} {securityType} Group";
        }

        public void GetGroupInfo(bool verbose)
        {
            Console.WriteLine("[+] Getting Domain Groups");

            String LdapString = GetLdapString();

            DirectoryEntry directoryEntry = new DirectoryEntry(LdapString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=group)");

            String[] groupFields = { "cn", "description", "grouptype", "member" };

            directorySearcher.PropertiesToLoad.AddRange(groupFields);

            SearchResultCollection results = directorySearcher.FindAll();
            if (results.Count == 0)
            {
                Console.WriteLine("[+] No Groups found!");
                return;
            }

            this.Groups = new Group[results.Count];

            int count = 0;
            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultProps = result.Properties;

                String cn = resultProps["cn"].Count > 0 ? resultProps["cn"][0].ToString() : "";
                String description = resultProps["description"].Count > 0 ? resultProps["description"][0].ToString() : "";
                int groupType = resultProps["grouptype"].Count > 0 ? (int)resultProps["grouptype"][0] : 0;
                int memberCount = resultProps["member"].Count;
                String parsedGroupType = this.ParseGroupType(groupType);

                if (verbose)
                {
                    Console.WriteLine($"CN: {cn}, Description: {description}, Group Type: {parsedGroupType}, Member Count: {memberCount}");
                }

                List<String> groupMembers = new List<string>();
                foreach (String m in resultProps["member"])
                {
                    String userString = m.Split(',')[0];
                    groupMembers.Add(userString.Substring(3));
                }
                Group group = new Group(cn, description, parsedGroupType, memberCount, groupMembers);
                this.Groups[count] = group;

                count++;
            }
        }

        public void GetPassPol(bool verbose)
        {
            String LdapString = GetLdapString();

            Console.WriteLine("[+] Getting password policy");

            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();

            String domainString = LdapString.Substring(7);

            String ldapConnectionString = $"LDAP://{dc}/{domainString}";

            DirectoryEntry directoryEntry = new DirectoryEntry(ldapConnectionString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=domainDNS)");

            String[] passwordProps = { "maxPwdAge", "minPwdAge", "minPwdLength", "pwdProperties", "lockoutDuration", "lockoutObservationWindow", "lockoutThreshold", "PwdHistoryLength" };

            directorySearcher.PropertiesToLoad.AddRange(passwordProps);

            SearchResult result = directorySearcher.FindOne();
            if (result == null)
            {
                Console.WriteLine("[!] Could not get password policy!");
                return;
            }

            TimeSpan minPwdAge = TimeSpan.FromTicks((long)result.Properties["minPwdAge"][0]);
            TimeSpan maxPwdAge = TimeSpan.FromTicks((long)result.Properties["maxPwdAge"][0]);
            TimeSpan lockoutDuration = TimeSpan.FromTicks((long)result.Properties["lockoutDuration"][0]);
            TimeSpan lockoutTimeWindow = TimeSpan.FromTicks((long)result.Properties["lockoutObservationWindow"][0]);

            if (verbose)
            {
                Console.WriteLine($"Min Password Age: {Math.Abs(minPwdAge.TotalDays)}");
                Console.WriteLine($"Max Password Age: {Math.Abs(maxPwdAge.TotalDays)}");
                Console.WriteLine($"Min Password Length: {result.Properties["minPwdLength"][0]}");
                Console.WriteLine($"Password Properties: {result.Properties["pwdProperties"][0]}");
                Console.WriteLine($"Lockout Duration: {Math.Abs(lockoutDuration.TotalMinutes)} minutes");
                Console.WriteLine($"Lockout Time Window: Resets in {Math.Abs(lockoutTimeWindow.TotalMinutes)} minutes");
                Console.WriteLine($"Lockout Threshold: {result.Properties["lockoutThreshold"][0]} invalid attempts");
                Console.WriteLine($"Password History Length: {result.Properties["PwdHistoryLength"][0]}");
            }

            this.MinPwdAge = Math.Abs(minPwdAge.TotalDays);
            this.MaxPwdAge = Math.Abs(maxPwdAge.TotalDays);
            this.MinPasswordLength = (int)result.Properties["minPwdLength"][0];
            this.PwdProperties = (int)result.Properties["pwdProperties"][0];
            this.LockoutDuration = Math.Abs(lockoutDuration.TotalMinutes);
            this.LockoutObservationWindow = Math.Abs(lockoutTimeWindow.TotalMinutes);
            this.LockoutThreshold = (int)result.Properties["lockoutThreshold"][0];
            this.PwdHistoryLength =(int)result.Properties["PwdHistoryLength"][0];

            directoryEntry.Dispose();
            directorySearcher.Dispose();
        }

        public void GenerateFiles(String outputDir)
        {
            Console.WriteLine("[+] Generating CSV files");
            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\policies.csv", false))
            {
                writetext.WriteLine("Name\tMinPasswordAge\tMaxPwdAge\tMinPasswordLength\tPwdProperties\tLockoutDuration\tLockoutWindow\tLockoutThreshold\tPasswordHistoryLength");
                writetext.WriteLine($"{this.Name}\t{this.MinPasswordLength}\t{this.MaxPwdAge}\t{this.MinPasswordLength}\t{this.PwdProperties}\t{this.LockoutDuration}\t{this.LockoutObservationWindow}\t{this.LockoutThreshold}\t{this.PwdHistoryLength}");
            }


            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\users.csv", false))
            {
                writetext.WriteLine("Name\tFirst\tLast\tSamAccountName\tGroupMemberCount\tMemberOf\tDisplayName\tPrimaryGroupID\tWhenCreated\tWhenChanged\tLastLogon\tUACFlags\tPasswordLastSet\tLockoutTime\tSID\tDescription");
                foreach (User user in this.Users)
                {
                    writetext.WriteLine($"{user.Cn}\t{user.First}\t{user.Last}\t{user.SamAccountName}\t{user.GroupMemberCount}\t{String.Join(",", user.MemberOf)}\t{user.DisplayName}\t{user.PrimaryGroupId}\t{user.WhenCreated}\t{user.WhenChanged}\t{user.LastLogon}\t{String.Join(",", user.UserAccountControl)}\t{user.PwdLastSet}\t{user.LockoutTime}\t{user.ObjectSid}\t{user.Description}");
                }
            }

            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\groups.csv", false))
            {
                writetext.WriteLine("Name\tDescription\tGroupType\tMemberCount\tMembers");
                foreach (Group group in this.Groups)
                {
                    writetext.WriteLine($"{group.Cn}\t{group.Description}\t{group.GroupType}\t{group.MemberCount}\t{String.Join(",", group.Members)}");
                }
            }

            Console.WriteLine("[+] Generating JSON file");
            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\hm_domainoutput.json", false))
            {
                string jsonString = JsonSerializer.Serialize(this);
                writetext.WriteLine(jsonString);
            }
        }
    }
}
