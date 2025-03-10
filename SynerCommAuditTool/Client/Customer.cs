using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

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
        DONT_EXPIRE_PASSWD = 0x00010000,
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
        DONT_EXPIRE_PASSWORD = 0x10000,
        MNS_LOGON_ACCOUNT = 0x20000
    }


    public class Customer
    {
        public string Name { get; private set; }
        public string PullDate { get; private set; }
        public int NumberOfResults { get; private set; }
        public double MinPwdAge { get; private set; }
        public double MaxPwdAge {  get; private set; }
        public int MinPasswordLength { get; private set; }
        public int PwdProperties {  get; private set; }
        public double LockoutDuration {  get; private set; }
        public double LockoutObservationWindow {  get; private set; }
        public int LockoutThreshold {  get; private set; }
        public User[] Users { get; private set; }


        public Customer(string name)
        {
            this.Name = name;
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

        private static String GetLdapString(String domain)
        {
            string[] domainFqdn = domain.Split('.');
            if (domainFqdn.Length == 1)
            {
                Console.WriteLine("[!] Need domain FQDN! E.g., acme.local");
                return "";
            }

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

        public void EnumerateUsers(String domain, bool verbose)
        {
            String LdapString = GetLdapString(domain);

            Console.WriteLine("[+] Connecting to LDAP");

            DirectoryEntry directoryEntry = new DirectoryEntry(LdapString);
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(&(objectCategory=person)(objectClass=user))");
            String[] userProperties = new string[] { "cn", "name", "samaccountname", "memberof", "displayname", "primarygroupid", "whencreated", "whenchanged", "lastlogon", "useraccountcontrol", "pwdlastset", "objectsid", "description"};

            directorySearcher.PropertiesToLoad.AddRange(userProperties);

            SearchResultCollection results = directorySearcher.FindAll();

            Console.WriteLine($"[*] Found {results.Count} users!");
            this.NumberOfResults = results.Count;

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
                String objectSid = "";
                String pwdLastSet = resultPropColl["pwdlastset"].Count > 0 ? this.ParseDateTime((long)resultPropColl["pwdlastset"][0]) : "";
                String whenCreated = resultPropColl["whencreated"].Count > 0 ? resultPropColl["whencreated"][0].ToString() : "";
                String whenChanged = resultPropColl["whenchanged"].Count > 0 ? resultPropColl["whenchanged"][0].ToString() : "";
                String lastLogon = resultPropColl["lastlogon"].Count > 0 ? this.ParseDateTime((long)resultPropColl["lastlogon"][0]) : "";

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
                    Console.WriteLine($"{cn}, {name}, {samAccountName}, {memberOf}, {displayName}, {primaryGroupId}, {whenCreated}, {whenChanged}, {lastLogon}, [{String.Join(",", uacFlags)}], {pwdLastSet}, {objectSid}, {description}");
                }

                User user = new User(cn, name, samAccountName, memberOf, displayName, primaryGroupId, whenCreated, whenChanged, lastLogon, uacFlags, pwdLastSet, objectSid, description);

                this.Users[count] = user;

                count++;
            }

            results.Dispose();
            directoryEntry.Dispose();
            directorySearcher.Dispose();
        }

        public void GetPassPol(String domain, bool verbose)
        {
            String LdapString = GetLdapString(domain);

            Console.WriteLine("[+] Finding Domain Controller");

            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();
            Console.WriteLine($"[+] Found DC: {dc.Name}");

            String domainString = LdapString.Substring(7);

            String ldapConnectionString = $"LDAP://{dc}/{domainString}";


            Console.WriteLine("[+] Connecting to LDAP");

            DirectoryEntry directoryEntry = new DirectoryEntry(ldapConnectionString);
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=domainDNS)");

            String[] passwordProps = {"maxPwdAge", "minPwdAge", "minPwdLength", "pwdProperties", "lockoutDuration", "lockoutObservationWindow", "lockoutThreshold"};

            directorySearcher.PropertiesToLoad.AddRange(passwordProps);

            Console.WriteLine("[+] Querying password policy");

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
                Console.WriteLine($"--- Min Password Age: {Math.Abs(minPwdAge.TotalDays)} ----");
                Console.WriteLine($"--- Max Password Age: {Math.Abs(maxPwdAge.TotalDays)} ----");
                Console.WriteLine($"--- Min Password Length: {result.Properties["minPwdLength"][0]} ----");
                Console.WriteLine($"--- Password Properties: {result.Properties["pwdProperties"][0]} ----");
                Console.WriteLine($"--- Lockout Duration: {Math.Abs(lockoutDuration.TotalMinutes)} minutes ----");
                Console.WriteLine($"--- Lockout Time Window: Resets in {Math.Abs(lockoutTimeWindow.TotalMinutes)} minutes ----");
                Console.WriteLine($"--- Lockout Threshold: {result.Properties["lockoutThreshold"][0]} invalid attempts ----");
            }

            this.MinPwdAge = Math.Abs(minPwdAge.TotalDays);
            this.MaxPwdAge = Math.Abs(maxPwdAge.TotalDays);
            this.MinPasswordLength = (int)result.Properties["minPwdLength"][0];
            this.PwdProperties = (int)result.Properties["pwdProperties"][0];
            this.LockoutDuration = Math.Abs(lockoutDuration.TotalMinutes);
            this.LockoutObservationWindow = Math.Abs(lockoutTimeWindow.TotalMinutes);
            this.LockoutThreshold = (int)result.Properties["lockoutThreshold"][0];

            directoryEntry.Dispose();
            directorySearcher.Dispose();
        }
    }
}
