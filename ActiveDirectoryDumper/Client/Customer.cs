using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace ActiveDirectoryDumper.Client
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
        USE_AES_KEYS = 0x08000000,
        SCRIPT = 0x00000001,
        HOMEDIR_REQUIRED = 0x0008,
        TEMP_DUPLICATE_ACCOUNT = 0x0100,
        INTERDOMAIN_TRUST_ACCOUNT = 0x0800,
        MNS_LOGON_ACCOUNT = 0x20000
    }

    // Bits of the domain object's pwdProperties attribute (MS-SAMR DOMAIN_PASSWORD_INFORMATION).
    enum PwdPropertyFlags : int
    {
        DOMAIN_PASSWORD_COMPLEX = 0x00000001,
        DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x00000002,
        DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004,
        DOMAIN_LOCKOUT_ADMINS = 0x00000008,
        DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010,
        DOMAIN_REFUSE_PASSWORD_CHANGE = 0x00000020
    }

    /// <summary>Counts computed by ADD for the console and as a cross-check for Hash Master 1000.</summary>
    public class PasswordSecuritySummary
    {
        public int Users { get; set; }
        public int UsersEnabled { get; set; }
        public int UsersPrivileged { get; set; }
        public int UsersProtectedUsers { get; set; }
        public int UsersUnderFineGrainedPolicy { get; set; }
        public int UsersPasswordNeverExpires { get; set; }
        public int UsersPasswordNotRequired { get; set; }
        public int UsersPasswordExpired { get; set; }
        public int UsersLockedOut { get; set; }
        public int UsersKerberoastable { get; set; }
        public int UsersAsRepRoastable { get; set; }
        public int UsersWithLmHash { get; set; }
        public int UsersWithBlankNtHash { get; set; }
        public int UsersNoAesKeys { get; set; }
        public int UsersWithLegacyPasswordAttributes { get; set; }
        public int UsersSmartCardRequired { get; set; }
        public double KrbtgtPasswordAgeDays { get; set; }
        public int Computers { get; set; }
        public int ComputersDomainControllers { get; set; }
        public int ComputersManagedServiceAccounts { get; set; }
        public int ComputersLapsManaged { get; set; }
        public int ComputersPasswordOlderThan90Days { get; set; }
    }

    public class Customer
    {
        public string Name { get; private set; }
        public string PullDate { get; private set; }
        public string PullTimeUtc { get; private set; }
        public string CollectorVersion { get; private set; }
        /// <summary>Data-contract version of this file, independent of the collector tool. 2.3 and earlier files have no such field (treat as schema 1).</summary>
        public string SchemaVersion { get; private set; } = "2.1";
        public int UserCount { get; private set; }
        public double MinPwdAge { get; private set; }
        public double MaxPwdAge { get; private set; }
        public int MinPasswordLength { get; private set; }
        public int PwdProperties { get; private set; }
        public double LockoutDuration { get; private set; }
        public double LockoutObservationWindow { get; private set; }
        public int LockoutThreshold { get; private set; }
        public int PwdHistoryLength { get; private set; }
        public string[] PwdPropertiesFlags { get; private set; } = Array.Empty<string>();
        public bool DomainReversibleEncryptionEnabled { get; private set; }
        public bool DomainComplexityEnabled { get; private set; }
        public string DomainSid { get; private set; } = String.Empty;
        public string DomainDistinguishedName { get; private set; } = String.Empty;
        public List<PasswordSettingsObject> PasswordSettingsObjects { get; private set; } = new List<PasswordSettingsObject>();
        public List<GroupPolicyObject> GroupPolicyObjects { get; private set; } = new List<GroupPolicyObject>();
        public SecurityPosture SecurityPosture { get; private set; } = new SecurityPosture();
        public List<GppPassword> GroupPolicyPasswords { get; private set; } = new List<GppPassword>();
        public AccessControlAudit AccessControl { get; private set; } = new AccessControlAudit();
        public ReversibleEncryptionSummary ReversibleEncryption { get; private set; } = new ReversibleEncryptionSummary();
        public PasswordSecuritySummary Summary { get; private set; } = new PasswordSecuritySummary();
        public CollectionReport Report { get; private set; } = new CollectionReport();

        public List<Dictionary<String, String>> DomainTrusts { get; private set; } = new List<Dictionary<String, String>>();
        public User[] Users { get; private set; }

        public Group[] Groups { get; private set; }
        public Computer[] Computers { get; private set; }

        // Not serialized: working data for the analysis step.
        private readonly Dictionary<String, int> containerGpOptions = new Dictionary<String, int>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, List<String>> privilegedMembership = new Dictionary<String, List<String>>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<String> protectedUsers = new HashSet<String>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, long> userPwdLastSetRaw = new Dictionary<String, long>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<String, long> computerPwdLastSetRaw = new Dictionary<String, long>(StringComparer.OrdinalIgnoreCase);

        private const long NeverFileTime = 0x7FFFFFFFFFFFFFFF;
        private const string BlankNtHash = "31d6cfe0d16ae931b73c59d7e0c089c0";
        private const int MaxStoredNamesListed = 100;

        public Customer()
        {
            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);

            this.Name = adDomain.Name;
            this.PullDate = DateTime.Now.ToString("MM/dd/yyyy");
            this.PullTimeUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            this.CollectorVersion = typeof(Customer).Assembly.GetName().Version.ToString();
        }

        // ------------------------------------------------------------------ helpers

        private string[] ParseUacFlags(String uacVal)
        {
            List<String> flags = new List<String>();
            uint value;
            if (!uint.TryParse(uacVal, out value))
            {
                return flags.ToArray();
            }
            foreach (uint i in Enum.GetValues(typeof(UacFlags)))
            {
                if ((value & i) != 0)
                {
                    flags.Add(Enum.GetName(typeof(UacFlags), i));
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

        /// <summary>FILETIME to ISO 8601 UTC. 0 gives an empty string, the "never" sentinel gives "Never".</summary>
        private static String ToIso(long fileTime)
        {
            if (fileTime <= 0)
            {
                return String.Empty;
            }
            if (fileTime == NeverFileTime)
            {
                return "Never";
            }
            try
            {
                return DateTime.FromFileTimeUtc(fileTime).ToString("yyyy-MM-ddTHH:mm:ssZ");
            }
            catch (ArgumentOutOfRangeException)
            {
                return String.Empty;
            }
        }

        private static long GetLong(ResultPropertyCollection props, String name)
        {
            if (props[name].Count == 0)
            {
                return 0;
            }
            object v = props[name][0];
            if (v is long) return (long)v;
            if (v is int) return (int)v;
            long parsed;
            return long.TryParse(v.ToString(), out parsed) ? parsed : 0;
        }

        private static String GetString(ResultPropertyCollection props, String name)
        {
            return props[name].Count > 0 ? props[name][0].ToString() : String.Empty;
        }

        private static String GetSid(ResultPropertyCollection props, String name)
        {
            if (props[name].Count == 0)
            {
                return String.Empty;
            }
            byte[] raw = props[name][0] as byte[];
            return raw != null ? new SecurityIdentifier(raw, 0).ToString() : String.Empty;
        }

        private static int RidOf(String sid)
        {
            if (String.IsNullOrEmpty(sid))
            {
                return 0;
            }
            String[] parts = sid.Split('-');
            int rid;
            return int.TryParse(parts[parts.Length - 1], out rid) ? rid : 0;
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

        private String[] GetDataValues(ResultPropertyValueCollection data)
        {
            List<String> values = new List<String>();
            for (int i = 0;i < data.Count; i++)
            {
                values.Add(data[i].ToString());
            }
            return values.ToArray();
        }

        private static String EscapeLdapFilterValue(String value)
        {
            StringBuilder sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\5c"); break;
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        private static String GetRdnValue(String distinguishedName)
        {
            if (String.IsNullOrEmpty(distinguishedName))
            {
                return String.Empty;
            }

            // First RDN, honouring escaped commas (e.g. "CN=Smith\, John,OU=...").
            int end = 0;
            while (end < distinguishedName.Length)
            {
                if (distinguishedName[end] == '\\')
                {
                    end += 2;
                    continue;
                }
                if (distinguishedName[end] == ',')
                {
                    break;
                }
                end++;
            }
            String rdn = distinguishedName.Substring(0, Math.Min(end, distinguishedName.Length));
            int eq = rdn.IndexOf('=');
            String value = eq >= 0 ? rdn.Substring(eq + 1) : rdn;
            return value.Replace("\\,", ",");
        }

        private static TimeSpan ParseNegativeInterval(long value)
        {
            // Password age / lockout intervals are stored as negative 100ns intervals; long.MinValue means "never".
            if (value == long.MinValue || value == 0)
            {
                return TimeSpan.Zero;
            }
            return TimeSpan.FromTicks(Math.Abs(value));
        }

        // ------------------------------------------------------------------ enumeration

        public void EnumerateDomain(String outputDir)
        {
            Console.WriteLine("[+] Starting enumeration");

            String ldapString = GetLdapString();
            this.DomainDistinguishedName = ldapString.Substring(7);

            Console.WriteLine("[+] Connecting to LDAP");

            // Policies are collected first so that user records can be matched against them.
            this.GetPassPol(ldapString);
            this.GetFineGrainedPasswordPolicies(ldapString);
            this.GetGroupPolicyPasswordSettings(ldapString);
            this.GetGroupPolicyPasswords();
            this.GetSecurityPosture(ldapString);
            this.GetAccessControlAudit(ldapString);
            this.GetPrivilegedGroupMembership(ldapString);
            this.GetDomainUsers(ldapString);
            this.GetDomainComputers(ldapString);
            this.GetDomainTrusts(ldapString);
            this.GetGroupInfo(ldapString);
        }

        private void GetDomainUsers(string ldapString)
        {
            DirectoryEntry directoryEntry = new DirectoryEntry(ldapString);
            directoryEntry.RefreshCache();

            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(&(objectCategory=person)(objectClass=user))");
            directorySearcher.PageSize = 1000;

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
                "description",
                "serviceprincipalname",
                "admincount",
                "msds-supportedencryptiontypes",
                "msds-allowedtodelegateto",
                "distinguishedname",
                "msds-resultantpso",
                "lastlogontimestamp",
                "accountexpires",
                "msds-userpasswordexpirytimecomputed",
                "msds-user-account-control-computed",
                "info",
                "comment",
                "userpassword",
                "unixuserpassword",
                "mssfu30password"
            };

            directorySearcher.PropertiesToLoad.AddRange(userProperties);


            SearchResultCollection results = directorySearcher.FindAll();

            Console.WriteLine($"[*] Found {results.Count} users!");
            this.UserCount = results.Count;
            this.Report.Record("Domain users", "OK", results.Count);

            this.Users = new User[results.Count];

            int count = 0;
            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultPropColl = result.Properties;

                String cn = GetString(resultPropColl, "cn");
                String distinguishedName = GetString(resultPropColl, "distinguishedname");
                String name = GetString(resultPropColl, "name");
                String samAccountName = GetString(resultPropColl, "samaccountname");
                String displayName = GetString(resultPropColl, "displayname");
                String primaryGroupId = GetString(resultPropColl, "primarygroupid");
                String description = GetString(resultPropColl, "description");
                long pwdLastSetRaw = GetLong(resultPropColl, "pwdlastset");
                String pwdLastSet = resultPropColl["pwdlastset"].Count > 0 ? this.ParseDateTime(pwdLastSetRaw) : "";
                String lockoutTime = resultPropColl["lockouttime"].Count > 0 ? this.ParseDateTime(GetLong(resultPropColl, "lockouttime")) : "";
                String whenCreated = GetString(resultPropColl, "whencreated");
                String whenChanged = GetString(resultPropColl, "whenchanged");
                String lastLogon = resultPropColl["lastlogon"].Count > 0 ? this.ParseDateTime(GetLong(resultPropColl, "lastlogon")) : "";
                String adminCount = resultPropColl["admincount"].Count > 0 ? resultPropColl["admincount"][0].ToString() : "0";
                String supportedEncryptionTypes = GetString(resultPropColl, "msds-supportedencryptiontypes");

                (String first, String last) = this.ParseName(name);
                List<String> memberGroups = new List<String>();
                List<String> memberOfDns = new List<String>();
                int groupMemberCount = resultPropColl["memberof"].Count;


                if (groupMemberCount > 0)
                {
                    foreach (String item in resultPropColl["memberof"])
                    {
                        memberOfDns.Add(item);
                        memberGroups.Add(GetRdnValue(item));
                    }
                }

                String objectSid = GetSid(resultPropColl, "objectsid");

                String rawUAC = GetString(resultPropColl, "useraccountcontrol");
                String[] uacFlags = Array.Empty<string>();

                if (!string.IsNullOrEmpty(rawUAC))
                {
                    uacFlags = this.ParseUacFlags(rawUAC);
                }

                String[] spns = this.GetDataValues(resultPropColl["serviceprincipalname"]);
                String[] delegations = this.GetDataValues(resultPropColl["msds-allowedtodelegateto"]);

                User user = new User(
                    cn,
                    distinguishedName,
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
                    rawUAC,
                    pwdLastSet,
                    lockoutTime,
                    objectSid,
                    description,
                    spns,
                    adminCount,
                    supportedEncryptionTypes,
                    delegations
                );

                // Timestamps with full precision, replicated last logon, expiry.
                user.PwdLastSetUtc = ToIso(pwdLastSetRaw);
                user.LastLogonTimestamp = ToIso(GetLong(resultPropColl, "lastlogontimestamp"));
                long accountExpires = GetLong(resultPropColl, "accountexpires");
                user.AccountExpires = (accountExpires == 0 || accountExpires == NeverFileTime) ? "Never" : ToIso(accountExpires);
                if (resultPropColl["msds-userpasswordexpirytimecomputed"].Count > 0)
                {
                    long expiry = GetLong(resultPropColl, "msds-userpasswordexpirytimecomputed");
                    user.PasswordExpiryTime = expiry == 0 ? "Expired" : ToIso(expiry);
                }
                if (!String.IsNullOrEmpty(samAccountName))
                {
                    this.userPwdLastSetRaw[samAccountName] = pwdLastSetRaw;
                }

                // Live account state computed by the DC.
                String computedUac = GetString(resultPropColl, "msds-user-account-control-computed");
                if (!String.IsNullOrEmpty(computedUac))
                {
                    user.UserAccountControlComputed = this.ParseUacFlags(computedUac);
                    user.LockedOut = Array.IndexOf(user.UserAccountControlComputed, UacFlags.ACCOUNT_LOCKED.ToString()) >= 0;
                    user.PasswordExpired = Array.IndexOf(user.UserAccountControlComputed, UacFlags.PASSWORD_EXPIRED.ToString()) >= 0;
                }

                user.Info = GetString(resultPropColl, "info");
                user.Comment = GetString(resultPropColl, "comment");

                List<String> legacy = new List<String>();
                foreach (String attr in new[] { "userpassword", "unixuserpassword", "mssfu30password" })
                {
                    if (resultPropColl[attr].Count > 0)
                    {
                        legacy.Add(attr == "userpassword" ? "userPassword" : attr == "unixuserpassword" ? "unixUserPassword" : "msSFU30Password");
                    }
                }
                user.LegacyPasswordAttributes = legacy.ToArray();

                user.Rid = RidOf(objectSid);
                user.IsKrbtgt = samAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) || samAccountName.StartsWith("krbtgt_", StringComparison.OrdinalIgnoreCase);

                // Privileged and protected group membership (resolved recursively earlier).
                List<String> privileged;
                if (this.privilegedMembership.TryGetValue(samAccountName, out privileged))
                {
                    user.PrivilegedGroups = privileged.Distinct().OrderBy(g => g).ToArray();
                    user.IsPrivileged = user.PrivilegedGroups.Length > 0;
                }
                user.IsProtectedUser = this.protectedUsers.Contains(samAccountName);

                // Reversible encryption: account flag plus the fine-grained policy that applies to this user.
                user.ReversibleEncryption.AccountFlagSet = Array.IndexOf(uacFlags, UacFlags.PASSWORD_STORE_CLEARTEXT.ToString()) >= 0;
                if (resultPropColl["msds-resultantpso"].Count > 0)
                {
                    user.ReversibleEncryption.ResultantPso = this.ResolvePsoName(resultPropColl["msds-resultantpso"][0].ToString());
                    user.ReversibleEncryption.ResultantPsoSource = "msDS-ResultantPSO";
                }
                else if (this.PasswordSettingsObjects.Count > 0)
                {
                    // The DC did not return the constructed attribute; fall back to a direct match on the
                    // user DN and its direct group memberships (nested groups are not resolved).
                    PasswordSettingsObject matched = this.FindDirectlyAppliedPso(distinguishedName, memberOfDns);
                    if (matched != null)
                    {
                        user.ReversibleEncryption.ResultantPso = matched.Name;
                        user.ReversibleEncryption.ResultantPsoSource = "DirectMatch";
                    }
                }

                this.Users[count] = user;

                count++;
            }

            results.Dispose();
            directoryEntry.Dispose();
            directorySearcher.Dispose();
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

        public void GetDomainTrusts(string ldapString)
        {
            Console.WriteLine("[+] Finding Domain Trusts");

            DirectoryEntry directoryEntry = new DirectoryEntry(ldapString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=trustedDomain)");

            String[] trustFields = { "trustpartner", "trustdirection", "trusttype" };

            directorySearcher.PropertiesToLoad.AddRange(trustFields);

            SearchResultCollection results = directorySearcher.FindAll();
            if (results.Count == 0)
            {
                Console.WriteLine("[+] No Trusts found!");
                this.Report.Record("Domain trusts", "NONE", 0);
                return;
            }

            List<Dictionary<String, String>> domainTrusts = new List<Dictionary<String, String>>();

            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultPropColl = result.Properties;

                String trustPartner = GetString(resultPropColl, "trustpartner");
                String trustDirection = GetString(resultPropColl, "trustdirection");
                String trustType = GetString(resultPropColl, "trusttype");

                (String parsedTrustDirection, String parsedTrustType) = this.ParseTrustInfo(trustDirection, trustType);

                Dictionary<String, String> trust = new Dictionary<String, String>();

                trust.Add("Trust", trustPartner);
                trust.Add("TrustDirection", parsedTrustDirection);
                trust.Add("TrustType", parsedTrustType);

                domainTrusts.Add(trust);
            }
            this.DomainTrusts = domainTrusts;
            this.Report.Record("Domain trusts", "OK", domainTrusts.Count);
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

        public void GetGroupInfo(string ldapString)
        {
            Console.WriteLine("[+] Getting Domain Groups");

            DirectoryEntry directoryEntry = new DirectoryEntry(ldapString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=group)");
            directorySearcher.PageSize = 1000;

            String[] groupFields = { "cn", "description", "grouptype", "member" };

            directorySearcher.PropertiesToLoad.AddRange(groupFields);

            SearchResultCollection results = directorySearcher.FindAll();
            if (results.Count == 0)
            {
                Console.WriteLine("[+] No Groups found!");
                this.Report.Record("Domain groups", "NONE", 0);
                return;
            }

            this.Groups = new Group[results.Count];

            int count = 0;
            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultProps = result.Properties;

                String cn = GetString(resultProps, "cn");
                String description = GetString(resultProps, "description");
                int groupType = resultProps["grouptype"].Count > 0 ? (int)resultProps["grouptype"][0] : 0;
                int memberCount = resultProps["member"].Count;
                String parsedGroupType = this.ParseGroupType(groupType);

                List<String> groupMembers = new List<string>();
                foreach (String m in resultProps["member"])
                {
                    groupMembers.Add(GetRdnValue(m));
                }
                Group group = new Group(cn, description, parsedGroupType, memberCount, groupMembers);
                this.Groups[count] = group;

                count++;
            }
            this.Report.Record("Domain groups", "OK", this.Groups.Length);
        }

        public void GetPassPol(string ldapString)
        {
            Console.WriteLine("[+] Getting password policy");

            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();

            String domainString = ldapString.Substring(7);

            String ldapConnectionString = $"LDAP://{dc}/{domainString}";

            DirectoryEntry directoryEntry = new DirectoryEntry(ldapConnectionString);
            directoryEntry.RefreshCache();
            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=domainDNS)");

            String[] passwordProps = { "maxPwdAge", "minPwdAge", "minPwdLength", "pwdProperties", "lockoutDuration", "lockoutObservationWindow", "lockoutThreshold", "PwdHistoryLength", "objectSid", "msDS-Behavior-Version" };

            directorySearcher.PropertiesToLoad.AddRange(passwordProps);

            SearchResult result = directorySearcher.FindOne();
            if (result == null)
            {
                Console.WriteLine("[!] Could not get password policy!");
                this.Report.Record("Password policy", "FAILED", null, "domainDNS query returned no result");
                return;
            }

            TimeSpan minPwdAge = TimeSpan.FromTicks((long)result.Properties["minPwdAge"][0]);
            TimeSpan maxPwdAge = TimeSpan.FromTicks((long)result.Properties["maxPwdAge"][0]);
            TimeSpan lockoutDuration = TimeSpan.FromTicks((long)result.Properties["lockoutDuration"][0]);
            TimeSpan lockoutTimeWindow = TimeSpan.FromTicks((long)result.Properties["lockoutObservationWindow"][0]);

            this.MinPwdAge = Math.Abs(minPwdAge.TotalDays);
            this.MaxPwdAge = Math.Abs(maxPwdAge.TotalDays);
            this.MinPasswordLength = (int)result.Properties["minPwdLength"][0];
            this.PwdProperties = (int)result.Properties["pwdProperties"][0];
            this.LockoutDuration = Math.Abs(lockoutDuration.TotalMinutes);
            this.LockoutObservationWindow = Math.Abs(lockoutTimeWindow.TotalMinutes);
            this.LockoutThreshold = (int)result.Properties["lockoutThreshold"][0];
            this.PwdHistoryLength =(int)result.Properties["PwdHistoryLength"][0];

            List<String> pwdFlags = new List<String>();
            foreach (int flag in Enum.GetValues(typeof(PwdPropertyFlags)))
            {
                if ((this.PwdProperties & flag) != 0)
                {
                    pwdFlags.Add(Enum.GetName(typeof(PwdPropertyFlags), flag));
                }
            }
            this.PwdPropertiesFlags = pwdFlags.ToArray();
            this.DomainReversibleEncryptionEnabled = (this.PwdProperties & (int)PwdPropertyFlags.DOMAIN_PASSWORD_STORE_CLEARTEXT) != 0;
            this.DomainComplexityEnabled = (this.PwdProperties & (int)PwdPropertyFlags.DOMAIN_PASSWORD_COMPLEX) != 0;

            if (this.DomainReversibleEncryptionEnabled)
            {
                Console.WriteLine("[!] Domain password policy stores passwords using reversible encryption (pwdProperties & 0x10)");
            }
            this.Report.Record("Password policy", "OK");

            this.DomainSid = GetSid(result.Properties, "objectSid");
            int level = (int)GetLong(result.Properties, "msDS-Behavior-Version");
            this.SecurityPosture.DomainFunctionalLevelRaw = level;
            this.SecurityPosture.DomainFunctionalLevel = FunctionalLevelName(level);

            directoryEntry.Dispose();
            directorySearcher.Dispose();
        }

        private static String FunctionalLevelName(int level)
        {
            switch (level)
            {
                case 0: return "Windows2000";
                case 1: return "Windows2003Interim";
                case 2: return "Windows2003";
                case 3: return "Windows2008";
                case 4: return "Windows2008R2";
                case 5: return "Windows2012";
                case 6: return "Windows2012R2";
                case 7: return "Windows2016";
                case 10: return "Windows2025";
                default: return $"Unknown({level})";
            }
        }

        private String ResolvePsoName(String psoDn)
        {
            PasswordSettingsObject pso = this.PasswordSettingsObjects.Find(
                p => String.Equals(p.DistinguishedName, psoDn, StringComparison.OrdinalIgnoreCase));
            return pso != null ? pso.Name : GetRdnValue(psoDn);
        }

        private PasswordSettingsObject FindDirectlyAppliedPso(String userDn, List<String> memberOfDns)
        {
            // PSOs applied directly to the user win over PSOs applied to its groups; lowest precedence wins within each.
            PasswordSettingsObject direct = this.PasswordSettingsObjects
                .Where(p => p.AppliesTo.Any(a => String.Equals(a, userDn, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(p => p.Precedence)
                .FirstOrDefault();
            if (direct != null)
            {
                return direct;
            }

            return this.PasswordSettingsObjects
                .Where(p => p.AppliesTo.Any(a => memberOfDns.Any(g => String.Equals(a, g, StringComparison.OrdinalIgnoreCase))))
                .OrderBy(p => p.Precedence)
                .FirstOrDefault();
        }

        /// <summary>
        /// Collects fine-grained password policies (msDS-PasswordSettings). A PSO overrides the domain
        /// password policy, including reversible encryption, for the users and groups it applies to.
        /// </summary>
        public void GetFineGrainedPasswordPolicies(string ldapString)
        {
            Console.WriteLine("[+] Getting fine-grained password policies");

            try
            {
                using (DirectoryEntry directoryEntry = new DirectoryEntry(ldapString))
                using (DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=msDS-PasswordSettings)"))
                {
                    directorySearcher.PageSize = 1000;
                    String[] psoProps = {
                        "name",
                        "distinguishedname",
                        "msds-passwordsettingsprecedence",
                        "msds-passwordreversibleencryptionenabled",
                        "msds-passwordcomplexityenabled",
                        "msds-minimumpasswordlength",
                        "msds-passwordhistorylength",
                        "msds-minimumpasswordage",
                        "msds-maximumpasswordage",
                        "msds-lockoutthreshold",
                        "msds-lockoutduration",
                        "msds-lockoutobservationwindow",
                        "msds-psoappliesto"
                    };
                    directorySearcher.PropertiesToLoad.AddRange(psoProps);

                    using (SearchResultCollection results = directorySearcher.FindAll())
                    {
                        foreach (SearchResult result in results)
                        {
                            ResultPropertyCollection props = result.Properties;

                            String name = GetString(props, "name");
                            String dn = GetString(props, "distinguishedname");
                            int precedence = props["msds-passwordsettingsprecedence"].Count > 0 ? Convert.ToInt32(props["msds-passwordsettingsprecedence"][0]) : int.MaxValue;
                            bool reversible = props["msds-passwordreversibleencryptionenabled"].Count > 0 && Convert.ToBoolean(props["msds-passwordreversibleencryptionenabled"][0]);
                            bool complexity = props["msds-passwordcomplexityenabled"].Count > 0 && Convert.ToBoolean(props["msds-passwordcomplexityenabled"][0]);
                            int minLength = props["msds-minimumpasswordlength"].Count > 0 ? Convert.ToInt32(props["msds-minimumpasswordlength"][0]) : 0;
                            int history = props["msds-passwordhistorylength"].Count > 0 ? Convert.ToInt32(props["msds-passwordhistorylength"][0]) : 0;
                            TimeSpan minAge = ParseNegativeInterval(GetLong(props, "msds-minimumpasswordage"));
                            TimeSpan maxAge = ParseNegativeInterval(GetLong(props, "msds-maximumpasswordage"));
                            int lockoutThreshold = props["msds-lockoutthreshold"].Count > 0 ? Convert.ToInt32(props["msds-lockoutthreshold"][0]) : 0;
                            TimeSpan lockoutDuration = ParseNegativeInterval(GetLong(props, "msds-lockoutduration"));
                            TimeSpan lockoutWindow = ParseNegativeInterval(GetLong(props, "msds-lockoutobservationwindow"));
                            String[] appliesTo = this.GetDataValues(props["msds-psoappliesto"]);

                            PasswordSettingsObject pso = new PasswordSettingsObject(
                                name,
                                dn,
                                precedence,
                                reversible,
                                complexity,
                                minLength,
                                history,
                                minAge.TotalDays,
                                maxAge.TotalDays,
                                lockoutThreshold,
                                lockoutDuration.TotalMinutes,
                                lockoutWindow.TotalMinutes,
                                appliesTo
                            );
                            this.PasswordSettingsObjects.Add(pso);

                            if (reversible)
                            {
                                Console.WriteLine($"[!] Fine-grained password policy '{name}' (precedence {precedence}) enables reversible encryption for {appliesTo.Length} target(s)");
                            }
                        }
                    }
                }

                Console.WriteLine($"[*] Found {this.PasswordSettingsObjects.Count} fine-grained password policies");
                this.Report.Record("Fine-grained password policies", "OK", this.PasswordSettingsObjects.Count);
            }
            catch (Exception ex)
            {
                // Reading the Password Settings Container needs read access that ordinary users may lack.
                Console.WriteLine($"[!] Could not read fine-grained password policies: {ex.Message}");
                this.Report.Record("Fine-grained password policies", "FAILED", null, "access denied or unavailable");
            }
        }

        // ------------------------------------------------------------------ Group Policy

        private Dictionary<String, List<GpoLink>> GetGpoLinks(String ldapString)
        {
            // Map of GPO DN (lower case) -> links from every container whose gPLink references it.
            Dictionary<String, List<GpoLink>> links = new Dictionary<String, List<GpoLink>>();

            using (DirectoryEntry directoryEntry = new DirectoryEntry(ldapString))
            using (DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(gplink=*)"))
            {
                directorySearcher.PageSize = 1000;
                directorySearcher.PropertiesToLoad.AddRange(new string[] { "distinguishedname", "gplink", "gpoptions" });

                using (SearchResultCollection results = directorySearcher.FindAll())
                {
                    foreach (SearchResult result in results)
                    {
                        String containerDn = GetString(result.Properties, "distinguishedname");
                        String gpLink = GetString(result.Properties, "gplink");
                        if (containerDn.Length == 0 || gpLink.Length == 0)
                        {
                            continue;
                        }
                        this.containerGpOptions[containerDn] = (int)GetLong(result.Properties, "gpoptions");

                        // Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=x;<options>][...]
                        // options bit 1 = link disabled, bit 2 = enforced. The last entry has link order 1.
                        String[] entries = gpLink.Split(new[] { '[', ']' }, StringSplitOptions.RemoveEmptyEntries);
                        for (int i = 0; i < entries.Length; i++)
                        {
                            String[] parts = entries[i].Split(';');
                            String gpoDn = parts[0].StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase) ? parts[0].Substring(7) : parts[0];
                            int options = 0;
                            if (parts.Length > 1)
                            {
                                int.TryParse(parts[1], out options);
                            }

                            GpoLink link = new GpoLink
                            {
                                Container = containerDn,
                                LinkOrder = entries.Length - i,
                                Enabled = (options & 1) == 0,
                                Enforced = (options & 2) != 0
                            };

                            String key = gpoDn.ToLowerInvariant();
                            if (!links.ContainsKey(key))
                            {
                                links[key] = new List<GpoLink>();
                            }
                            links[key].Add(link);
                        }
                    }
                }
            }
            return links;
        }

        /// <summary>Parses a secedit template (INI) into section -> key -> value.</summary>
        private static Dictionary<String, Dictionary<String, String>> ParseGptTmpl(String gptTmplPath)
        {
            // GptTmpl.inf is normally UTF-16 LE with BOM; ReadAllLines honours the BOM.
            Dictionary<String, Dictionary<String, String>> sections = new Dictionary<String, Dictionary<String, String>>(StringComparer.OrdinalIgnoreCase);
            Dictionary<String, String> current = null;

            foreach (String rawLine in File.ReadAllLines(gptTmplPath))
            {
                String line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith(";"))
                {
                    continue;
                }
                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    String sectionName = line.Substring(1, line.Length - 2).Trim();
                    if (!sections.TryGetValue(sectionName, out current))
                    {
                        current = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);
                        sections[sectionName] = current;
                    }
                    continue;
                }
                if (current == null)
                {
                    continue;
                }
                int eq = line.IndexOf('=');
                if (eq < 0)
                {
                    continue;
                }
                String key = line.Substring(0, eq).Trim();
                String value = line.Substring(eq + 1).Trim();
                current[key] = value;
            }
            return sections;
        }

        /// <summary>
        /// Reads every GPO's security template in SYSVOL and records where each GPO is linked. Account
        /// policy values here are the sources of the domain policy; the resolved values are on the domain
        /// object. GPOs linked below the domain change local account policy on the computers in scope.
        /// </summary>
        public void GetGroupPolicyPasswordSettings(string ldapString)
        {
            Console.WriteLine("[+] Scanning Group Policy Objects for security settings");

            try
            {
                String domainDn = ldapString.Substring(7);
                Dictionary<String, List<GpoLink>> links = this.GetGpoLinks(ldapString);

                using (DirectoryEntry directoryEntry = new DirectoryEntry(ldapString))
                using (DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(objectClass=groupPolicyContainer)"))
                {
                    directorySearcher.PageSize = 1000;
                    directorySearcher.PropertiesToLoad.AddRange(new string[] { "displayname", "name", "distinguishedname", "gpcfilesyspath", "flags" });

                    using (SearchResultCollection results = directorySearcher.FindAll())
                    {
                        foreach (SearchResult result in results)
                        {
                            ResultPropertyCollection props = result.Properties;

                            String displayName = GetString(props, "displayname");
                            String guid = GetString(props, "name");
                            String dn = GetString(props, "distinguishedname");
                            String sysvolPath = GetString(props, "gpcfilesyspath");
                            int flags = (int)GetLong(props, "flags");

                            GroupPolicyObject gpo = new GroupPolicyObject(displayName, guid, dn, sysvolPath, flags);

                            List<GpoLink> gpoLinks;
                            if (links.TryGetValue(dn.ToLowerInvariant(), out gpoLinks))
                            {
                                gpo.Links = gpoLinks;
                                gpo.LinkedToDomainRoot = gpoLinks.Any(l => l.Enabled && String.Equals(l.Container, domainDn, StringComparison.OrdinalIgnoreCase));
                            }

                            try
                            {
                                String gptTmpl = Path.Combine(sysvolPath, @"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf");
                                if (!String.IsNullOrEmpty(sysvolPath) && File.Exists(gptTmpl))
                                {
                                    gpo.GptTmplFound = true;
                                    Dictionary<String, Dictionary<String, String>> sections = ParseGptTmpl(gptTmpl);
                                    Dictionary<String, String> section;
                                    if (sections.TryGetValue("System Access", out section)) gpo.SystemAccess = section;
                                    if (sections.TryGetValue("Kerberos Policy", out section)) gpo.KerberosPolicy = section;
                                    if (sections.TryGetValue("Registry Values", out section)) gpo.RegistryValues = section;
                                }
                            }
                            catch (Exception ex)
                            {
                                gpo.Error = ex.Message;
                            }

                            if (gpo.ReversibleEncryptionEnabled)
                            {
                                String scope = gpo.LinkedToDomainRoot ? "linked at the domain root" : $"linked to: {String.Join("; ", gpo.Links.Select(l => l.Container))}";
                                if (gpo.Links.Count == 0)
                                {
                                    scope = "not linked";
                                }
                                Console.WriteLine($"[!] GPO '{displayName}' sets ClearTextPassword = 1 ({scope})");
                            }

                            this.GroupPolicyObjects.Add(gpo);
                        }
                    }
                }

                int unreadable = this.GroupPolicyObjects.Count(g => !String.IsNullOrEmpty(g.Error));
                int withTmpl = this.GroupPolicyObjects.Count(g => g.GptTmplFound);
                Console.WriteLine($"[*] Scanned {this.GroupPolicyObjects.Count} GPOs ({unreadable} with SYSVOL read errors)");

                this.ResolveGroupPolicySettings(domainDn);
                this.Report.Record("Group Policy security templates", unreadable > 0 ? "PARTIAL" : "OK", this.GroupPolicyObjects.Count, $"{withTmpl} with template, {unreadable} SYSVOL read error(s)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not scan Group Policy Objects: {ex.Message}");
                this.Report.Record("Group Policy security templates", "FAILED", null, "SYSVOL or LDAP unavailable");
            }
        }

        private List<GroupPolicyObject> GposLinkedTo(String containerDn, bool enforcedOnly, bool excludeEnforced)
        {
            // Apply order: lowest precedence first, so that link order 1 is applied last and wins.
            return this.GroupPolicyObjects
                .Where(g => !g.ComputerSettingsDisabled && g.GptTmplFound)
                .Select(g => new { Gpo = g, Link = g.Links.FirstOrDefault(l => l.Enabled && String.Equals(l.Container, containerDn, StringComparison.OrdinalIgnoreCase)) })
                .Where(x => x.Link != null)
                .Where(x => !enforcedOnly || x.Link.Enforced)
                .Where(x => !excludeEnforced || !x.Link.Enforced)
                .OrderByDescending(x => x.Link.LinkOrder)
                .Select(x => x.Gpo)
                .ToList();
        }

        private static List<PolicySetting> ApplyInOrder(IEnumerable<GroupPolicyObject> applyOrder, bool includeRegistry)
        {
            Dictionary<String, PolicySetting> effective = new Dictionary<String, PolicySetting>(StringComparer.OrdinalIgnoreCase);
            foreach (GroupPolicyObject gpo in applyOrder)
            {
                var sectionsToApply = new List<KeyValuePair<String, Dictionary<String, String>>>
                {
                    new KeyValuePair<String, Dictionary<String, String>>("System Access", gpo.SystemAccess),
                    new KeyValuePair<String, Dictionary<String, String>>("Kerberos Policy", gpo.KerberosPolicy)
                };
                if (includeRegistry)
                {
                    sectionsToApply.Add(new KeyValuePair<String, Dictionary<String, String>>("Registry Values", gpo.RegistryValues));
                }
                foreach (var section in sectionsToApply)
                {
                    foreach (KeyValuePair<String, String> kv in section.Value)
                    {
                        effective[section.Key + "|" + kv.Key] = new PolicySetting
                        {
                            Section = section.Key,
                            Name = kv.Key,
                            Value = kv.Value,
                            SourceGpo = gpo.DisplayName
                        };
                    }
                }
            }
            return effective.Values.OrderBy(s => s.Section).ThenBy(s => s.Name).ToList();
        }

        /// <summary>Resolves template settings for the domain root and for the Domain Controllers OU.</summary>
        private void ResolveGroupPolicySettings(String domainDn)
        {
            // Domain root: account policies come only from here.
            List<GroupPolicyObject> rootOrder = this.GposLinkedTo(domainDn, false, false);
            this.SecurityPosture.DomainAccountPolicySources = ApplyInOrder(rootOrder, false);

            // Domain Controllers OU: domain GPOs, then OU GPOs, then enforced domain GPOs. Block inheritance drops the first group.
            String dcOu = "OU=Domain Controllers," + domainDn;
            int options;
            bool blockInheritance = this.containerGpOptions.TryGetValue(dcOu, out options) && (options & 1) != 0;

            List<GroupPolicyObject> dcOrder = new List<GroupPolicyObject>();
            if (!blockInheritance)
            {
                dcOrder.AddRange(this.GposLinkedTo(domainDn, false, true));
            }
            dcOrder.AddRange(this.GposLinkedTo(dcOu, false, false));
            dcOrder.AddRange(this.GposLinkedTo(domainDn, true, false));
            this.SecurityPosture.DomainControllerSettings = ApplyInOrder(dcOrder, true);
        }

        // ------------------------------------------------------------------ posture and privileged groups

        /// <summary>Detects Entra Password Protection registration and counts domain controllers.</summary>
        public void GetSecurityPosture(string ldapString)
        {
            Console.WriteLine("[+] Checking password-protection posture");
            try
            {
                String configNc;
                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://RootDSE"))
                {
                    configNc = rootDse.Properties["configurationNamingContext"].Value.ToString();
                }

                String containerPath = $"LDAP://CN=Azure AD Password Protection,CN=Services,{configNc}";
                if (DirectoryEntry.Exists(containerPath))
                {
                    this.SecurityPosture.EntraPasswordProtectionContainerPresent = true;
                    using (DirectoryEntry container = new DirectoryEntry(containerPath))
                    using (DirectorySearcher searcher = new DirectorySearcher(container, "(objectClass=serviceConnectionPoint)", new[] { "cn" }))
                    using (SearchResultCollection results = searcher.FindAll())
                    {
                        this.SecurityPosture.EntraPasswordProtectionProxyCount = results.Count;
                    }
                }

                using (DirectoryEntry domain = new DirectoryEntry(ldapString))
                using (DirectorySearcher searcher = new DirectorySearcher(domain, "(&(objectClass=serviceConnectionPoint)(cn=AzureADPasswordProtection*))", new[] { "cn" }))
                using (SearchResultCollection results = searcher.FindAll())
                {
                    this.SecurityPosture.EntraPasswordProtectionDcAgentCount = results.Count;
                }

                if (this.SecurityPosture.EntraPasswordProtectionContainerPresent || this.SecurityPosture.EntraPasswordProtectionDcAgentCount > 0)
                {
                    Console.WriteLine($"[*] Entra Password Protection registered: {this.SecurityPosture.EntraPasswordProtectionProxyCount} proxy SCP(s), {this.SecurityPosture.EntraPasswordProtectionDcAgentCount} DC agent SCP(s)");
                }
                this.Report.Record("Password-protection posture", "OK");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not check Entra Password Protection registration: {ex.Message}");
                this.Report.Record("Password-protection posture", "FAILED", null, ex.Message);
            }
        }

        /// <summary>
        /// Resolves the effective (recursive) membership of the well-known privileged groups and of
        /// Protected Users, using the LDAP_MATCHING_RULE_IN_CHAIN operator and primaryGroupID.
        /// Groups are located by SID so localized names do not matter.
        /// </summary>
        public void GetPrivilegedGroupMembership(string ldapString)
        {
            Console.WriteLine("[+] Resolving privileged group membership");

            if (String.IsNullOrEmpty(this.DomainSid))
            {
                Console.WriteLine("[!] Domain SID unknown; skipping privileged group resolution");
                this.Report.Record("Privileged group membership", "SKIPPED", null, "domain SID unknown");
                return;
            }

            String rootSid = this.DomainSid;
            try
            {
                Forest forest = Forest.GetCurrentForest();
                using (DirectoryEntry rootDomain = forest.RootDomain.GetDirectoryEntry())
                {
                    byte[] raw = rootDomain.Properties["objectSid"].Value as byte[];
                    if (raw != null)
                    {
                        rootSid = new SecurityIdentifier(raw, 0).ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not read the forest root domain SID, using the current domain for Enterprise and Schema Admins: {ex.Message}");
            }

            var targets = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<String, String>($"{this.DomainSid}-512", "Domain Admins"),
                new KeyValuePair<String, String>($"{rootSid}-519", "Enterprise Admins"),
                new KeyValuePair<String, String>($"{rootSid}-518", "Schema Admins"),
                new KeyValuePair<String, String>($"{this.DomainSid}-520", "Group Policy Creator Owners"),
                new KeyValuePair<String, String>($"{this.DomainSid}-526", "Key Admins"),
                new KeyValuePair<String, String>($"{rootSid}-527", "Enterprise Key Admins"),
                new KeyValuePair<String, String>("S-1-5-32-544", "Administrators"),
                new KeyValuePair<String, String>("S-1-5-32-548", "Account Operators"),
                new KeyValuePair<String, String>("S-1-5-32-549", "Server Operators"),
                new KeyValuePair<String, String>("S-1-5-32-550", "Print Operators"),
                new KeyValuePair<String, String>("S-1-5-32-551", "Backup Operators"),
                new KeyValuePair<String, String>($"{this.DomainSid}-525", "Protected Users")
            };

            int resolved = 0;
            foreach (KeyValuePair<String, String> target in targets)
            {
                try
                {
                    String groupDn;
                    String groupName;
                    using (DirectoryEntry group = new DirectoryEntry($"LDAP://<SID={target.Key}>"))
                    {
                        groupDn = group.Properties["distinguishedName"].Value.ToString();
                        groupName = group.Properties["sAMAccountName"].Value.ToString();
                    }
                    this.CollectGroupMembers(ldapString, groupDn, groupName, RidOf(target.Key), target.Value == "Protected Users");
                    resolved++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Could not resolve {target.Value} ({target.Key}): {ex.Message}");
                }
            }

            // DnsAdmins has no well-known SID.
            try
            {
                using (DirectoryEntry domain = new DirectoryEntry(ldapString))
                using (DirectorySearcher searcher = new DirectorySearcher(domain, "(&(objectClass=group)(sAMAccountName=DnsAdmins))", new[] { "distinguishedname", "samaccountname" }))
                {
                    SearchResult result = searcher.FindOne();
                    if (result != null)
                    {
                        this.CollectGroupMembers(ldapString, GetString(result.Properties, "distinguishedname"), "DnsAdmins", 0, false);
                        resolved++;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not resolve DnsAdmins: {ex.Message}");
            }

            Console.WriteLine($"[*] Resolved {resolved} privileged/protected groups; {this.privilegedMembership.Count} privileged accounts, {this.protectedUsers.Count} protected users");
            this.Report.Record("Privileged group membership", "OK", this.privilegedMembership.Count, $"{resolved} groups resolved");
        }

        private void CollectGroupMembers(String ldapString, String groupDn, String groupName, int rid, bool isProtectedUsers)
        {
            String filter = rid > 0
                ? $"(&(objectCategory=person)(objectClass=user)(|(memberOf:1.2.840.113556.1.4.1941:={EscapeLdapFilterValue(groupDn)})(primaryGroupID={rid})))"
                : $"(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={EscapeLdapFilterValue(groupDn)}))";

            using (DirectoryEntry domain = new DirectoryEntry(ldapString))
            using (DirectorySearcher searcher = new DirectorySearcher(domain, filter, new[] { "samaccountname" }))
            {
                searcher.PageSize = 1000;
                using (SearchResultCollection results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                    {
                        String sam = GetString(result.Properties, "samaccountname");
                        if (sam.Length == 0)
                        {
                            continue;
                        }
                        if (isProtectedUsers)
                        {
                            this.protectedUsers.Add(sam);
                            continue;
                        }
                        List<String> groups;
                        if (!this.privilegedMembership.TryGetValue(sam, out groups))
                        {
                            groups = new List<String>();
                            this.privilegedMembership[sam] = groups;
                        }
                        groups.Add(groupName);
                    }
                }
            }
        }

        // ------------------------------------------------------------------ analysis

        private void ResolveReversibleEncryption(ReversibleEncryptionStatus status, bool psoApplicable)
        {
            status.DomainPolicyEnabled = this.DomainReversibleEncryptionEnabled;

            PasswordSettingsObject pso = null;
            if (psoApplicable && !String.IsNullOrEmpty(status.ResultantPso))
            {
                pso = this.PasswordSettingsObjects.Find(p => String.Equals(p.Name, status.ResultantPso, StringComparison.OrdinalIgnoreCase));
            }
            status.PsoEnabled = pso != null ? (bool?)pso.ReversibleEncryptionEnabled : null;

            // The account flag always enables it. Otherwise the resultant PSO, if any, replaces the domain policy.
            if (status.AccountFlagSet)
            {
                status.EffectivelyEnabled = true;
                status.EffectiveSource = ReversibleEncryptionSource.Account;
            }
            else if (pso != null)
            {
                status.EffectivelyEnabled = pso.ReversibleEncryptionEnabled;
                status.EffectiveSource = pso.ReversibleEncryptionEnabled ? ReversibleEncryptionSource.FineGrainedPolicy : ReversibleEncryptionSource.None;
            }
            else
            {
                status.EffectivelyEnabled = this.DomainReversibleEncryptionEnabled;
                status.EffectiveSource = this.DomainReversibleEncryptionEnabled ? ReversibleEncryptionSource.DomainPolicy : ReversibleEncryptionSource.None;
            }

            if (!status.NtdsChecked)
            {
                status.Status = ReversibleEncryptionState.Unknown;
            }
            else if (status.ClearTextPasswordStored && status.EffectivelyEnabled)
            {
                status.Status = ReversibleEncryptionState.Stored;
            }
            else if (status.ClearTextPasswordStored)
            {
                status.Status = ReversibleEncryptionState.StoredSettingDisabled;
            }
            else if (status.EffectivelyEnabled)
            {
                status.Status = ReversibleEncryptionState.EnabledNotStored;
            }
            else
            {
                status.Status = ReversibleEncryptionState.NotEnabled;
            }
        }

        private EffectivePasswordPolicy ResolveEffectivePolicy(String resultantPsoName)
        {
            PasswordSettingsObject pso = null;
            if (!String.IsNullOrEmpty(resultantPsoName))
            {
                pso = this.PasswordSettingsObjects.Find(p => String.Equals(p.Name, resultantPsoName, StringComparison.OrdinalIgnoreCase));
            }

            if (pso != null)
            {
                return new EffectivePasswordPolicy
                {
                    Source = "FineGrainedPolicy",
                    PolicyName = pso.Name,
                    MinPasswordLength = pso.MinPasswordLength,
                    ComplexityEnabled = pso.ComplexityEnabled,
                    PwdHistoryLength = pso.PwdHistoryLength,
                    MinPwdAge = pso.MinPwdAge,
                    MaxPwdAge = pso.MaxPwdAge,
                    LockoutThreshold = pso.LockoutThreshold,
                    LockoutDuration = pso.LockoutDuration,
                    LockoutObservationWindow = pso.LockoutObservationWindow,
                    ReversibleEncryptionEnabled = pso.ReversibleEncryptionEnabled
                };
            }

            return new EffectivePasswordPolicy
            {
                Source = "DomainPolicy",
                PolicyName = this.Name,
                MinPasswordLength = this.MinPasswordLength,
                ComplexityEnabled = this.DomainComplexityEnabled,
                PwdHistoryLength = this.PwdHistoryLength,
                MinPwdAge = this.MinPwdAge,
                MaxPwdAge = this.MaxPwdAge,
                LockoutThreshold = this.LockoutThreshold,
                LockoutDuration = this.LockoutDuration,
                LockoutObservationWindow = this.LockoutObservationWindow,
                ReversibleEncryptionEnabled = this.DomainReversibleEncryptionEnabled
            };
        }

        private static bool Has(string[] flags, UacFlags flag)
        {
            return flags != null && Array.IndexOf(flags, flag.ToString()) >= 0;
        }

        /// <summary>
        /// Combines policy, directory and NTDS.dit data into per-account results and domain summaries.
        /// Call after hash extraction so the NTDS data is present.
        /// </summary>
        public void Analyze()
        {
            Console.WriteLine("[+] Analyzing accounts");

            ReversibleEncryptionSummary rev = new ReversibleEncryptionSummary();
            rev.DomainPolicyEnabled = this.DomainReversibleEncryptionEnabled;
            rev.PsoCount = this.PasswordSettingsObjects.Count;
            rev.PsoNamesEnablingReversibleEncryption = this.PasswordSettingsObjects.Where(p => p.ReversibleEncryptionEnabled).Select(p => p.Name).ToArray();
            rev.PsosEnablingReversibleEncryption = rev.PsoNamesEnablingReversibleEncryption.Length;
            rev.GpoCount = this.GroupPolicyObjects.Count;
            rev.GpoNamesEnablingReversibleEncryption = this.GroupPolicyObjects.Where(g => g.ReversibleEncryptionEnabled).Select(g => g.DisplayName).ToArray();
            rev.GposEnablingReversibleEncryption = rev.GpoNamesEnablingReversibleEncryption.Length;

            PasswordSecuritySummary sum = new PasswordSecuritySummary();
            DateTime now = DateTime.UtcNow;

            List<String> userStoredNames = new List<String>();
            foreach (User user in this.Users ?? Array.Empty<User>())
            {
                ReversibleEncryptionStatus status = user.ReversibleEncryption;
                this.ResolveReversibleEncryption(status, true);
                user.EffectivePasswordPolicy = this.ResolveEffectivePolicy(status.ResultantPso);

                rev.NtdsChecked |= status.NtdsChecked;
                if (status.AccountFlagSet) rev.UsersWithAccountFlag++;
                if (status.EffectivelyEnabled) rev.UsersEffectivelyEnabled++;
                if (status.Status == ReversibleEncryptionState.EnabledNotStored) rev.UsersEnabledNotStored++;
                if (status.Status == ReversibleEncryptionState.StoredSettingDisabled) rev.UsersStoredSettingDisabled++;
                if (status.ClearTextPasswordStored)
                {
                    rev.UsersWithClearTextStored++;
                    userStoredNames.Add(user.SamAccountName);
                }

                bool enabled = !Has(user.UserAccountControl, UacFlags.ACCOUNT_DISABLED);
                sum.Users++;
                if (enabled) sum.UsersEnabled++;
                if (user.IsPrivileged) sum.UsersPrivileged++;
                if (user.IsProtectedUser) sum.UsersProtectedUsers++;
                if (user.EffectivePasswordPolicy.Source == "FineGrainedPolicy") sum.UsersUnderFineGrainedPolicy++;
                if (Has(user.UserAccountControl, UacFlags.DONT_EXPIRE_PASSWORD)) sum.UsersPasswordNeverExpires++;
                if (Has(user.UserAccountControl, UacFlags.PASSWD_NOTREQD)) sum.UsersPasswordNotRequired++;
                if (Has(user.UserAccountControl, UacFlags.SMARTCARD_REQUIRED)) sum.UsersSmartCardRequired++;
                if (user.PasswordExpired) sum.UsersPasswordExpired++;
                if (user.LockedOut) sum.UsersLockedOut++;
                if (enabled && !user.IsKrbtgt && user.ServicePrincipalNames.Length > 0) sum.UsersKerberoastable++;
                if (enabled && Has(user.UserAccountControl, UacFlags.DONT_REQ_PREAUTH)) sum.UsersAsRepRoastable++;
                if (user.StoredCredentials.HasLmHash) sum.UsersWithLmHash++;
                if (user.StoredCredentials.HasBlankNtHash) sum.UsersWithBlankNtHash++;
                if (user.StoredCredentials.NoAesKeys) sum.UsersNoAesKeys++;
                if (user.LegacyPasswordAttributes.Length > 0) sum.UsersWithLegacyPasswordAttributes++;

                long raw;
                if (user.SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) && this.userPwdLastSetRaw.TryGetValue(user.SamAccountName, out raw) && raw > 0)
                {
                    sum.KrbtgtPasswordAgeDays = Math.Round((now - DateTime.FromFileTimeUtc(raw)).TotalDays, 1);
                }
            }
            rev.UsersWithClearTextStoredNames = userStoredNames.Take(MaxStoredNamesListed).ToArray();

            List<String> computerStoredNames = new List<String>();
            foreach (Computer computer in this.Computers ?? Array.Empty<Computer>())
            {
                ReversibleEncryptionStatus status = computer.ReversibleEncryption;
                // PSOs apply to users and global security groups only, not to computer objects.
                this.ResolveReversibleEncryption(status, false);

                rev.NtdsChecked |= status.NtdsChecked;
                if (status.AccountFlagSet) rev.ComputersWithAccountFlag++;
                if (status.ClearTextPasswordStored)
                {
                    rev.ComputersWithClearTextStored++;
                    computerStoredNames.Add(computer.SamAccountName);
                }

                sum.Computers++;
                if (computer.IsDomainController) sum.ComputersDomainControllers++;
                if (computer.AccountType != "Computer") sum.ComputersManagedServiceAccounts++;
                if (computer.LapsManaged) sum.ComputersLapsManaged++;
                long raw;
                if (this.computerPwdLastSetRaw.TryGetValue(computer.SamAccountName, out raw) && raw > 0 && (now - DateTime.FromFileTimeUtc(raw)).TotalDays > 90)
                {
                    sum.ComputersPasswordOlderThan90Days++;
                }
            }
            rev.ComputersWithClearTextStoredNames = computerStoredNames.Take(MaxStoredNamesListed).ToArray();
            this.SecurityPosture.DomainControllerCount = sum.ComputersDomainControllers;

            this.ReversibleEncryption = rev;
            this.Summary = sum;
            this.Report.Record("Account analysis", "OK");

            Console.WriteLine($"[*] Domain functional level {this.SecurityPosture.DomainFunctionalLevel}; domain policy reversible encryption: {(rev.DomainPolicyEnabled ? "ENABLED" : "disabled")}");
            Console.WriteLine($"[*] Fine-grained policies enabling it: {rev.PsosEnablingReversibleEncryption} of {rev.PsoCount}; GPOs enabling it: {rev.GposEnablingReversibleEncryption} of {rev.GpoCount}");
            Console.WriteLine($"[*] Users with the account flag: {rev.UsersWithAccountFlag}; effectively enabled: {rev.UsersEffectivelyEnabled}; cleartext stored: {rev.UsersWithClearTextStored} (stored but setting now off: {rev.UsersStoredSettingDisabled})");
            Console.WriteLine($"[*] Users: {sum.Users} ({sum.UsersEnabled} enabled), privileged: {sum.UsersPrivileged}, under a PSO: {sum.UsersUnderFineGrainedPolicy}, never expires: {sum.UsersPasswordNeverExpires}, not required: {sum.UsersPasswordNotRequired}, expired: {sum.UsersPasswordExpired}, locked: {sum.UsersLockedOut}");
            Console.WriteLine($"[*] Kerberoastable: {sum.UsersKerberoastable}, AS-REP roastable: {sum.UsersAsRepRoastable}, LM hash: {sum.UsersWithLmHash}, blank NT hash: {sum.UsersWithBlankNtHash}, no AES keys: {sum.UsersNoAesKeys}, legacy password attributes: {sum.UsersWithLegacyPasswordAttributes}");
            Console.WriteLine($"[*] krbtgt password age: {sum.KrbtgtPasswordAgeDays} days");
            Console.WriteLine($"[*] Computers: {sum.Computers} ({sum.ComputersDomainControllers} DCs, {sum.ComputersManagedServiceAccounts} managed service accounts), LAPS managed: {sum.ComputersLapsManaged}, machine password older than 90 days: {sum.ComputersPasswordOlderThan90Days}");
        }

        /// <summary>Renders the run report, prints it, and writes collection_report.txt into the bundle.</summary>
        public void GenerateReport(String outputDir)
        {
            String report = this.Report.Render(this);
            Console.WriteLine();
            Console.Write(report);
            try
            {
                File.WriteAllText($"{outputDir}\\collection_report.txt", report);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not write collection_report.txt: {ex.Message}");
            }
        }

        public void GenerateFiles(String outputDir)
        {
            Console.WriteLine("[+] Generating JSON file");
            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\hm_domainoutput.json", false))
            {
                string jsonString = JsonSerializer.Serialize(this);
                writetext.WriteLine(jsonString);
            }
        }


        // ---- GPP cpassword (MS14-025) -----------------------------------------------------

        // The 32-byte AES key Microsoft published for Group Policy Preferences cpassword values.
        private static readonly byte[] GppAesKey = new byte[]
        {
            0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
            0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
        };

        /// <summary>Decrypts a GPP cpassword with the published key. Returns null on failure.</summary>
        public static string DecryptCpassword(string cpassword)
        {
            if (string.IsNullOrEmpty(cpassword))
            {
                return null;
            }
            try
            {
                string b64 = cpassword.Trim();
                switch (b64.Length % 4)
                {
                    case 2: b64 += "=="; break;
                    case 3: b64 += "="; break;
                }
                byte[] data = Convert.FromBase64String(b64);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = GppAesKey;
                    aes.IV = new byte[16];
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    {
                        byte[] plain = dec.TransformFinalBlock(data, 0, data.Length);
                        return Encoding.Unicode.GetString(plain).TrimEnd('\0');
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private static readonly string[] GppFiles = { "Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml" };

        /// <summary>
        /// Scans each GPO's SYSVOL folder for Group Policy Preferences files containing a cpassword
        /// attribute and decrypts them. Reuses the GPO list collected by GetGroupPolicyPasswordSettings.
        /// </summary>
        public void GetGroupPolicyPasswords()
        {
            Console.WriteLine("[+] Scanning Group Policy Preferences for stored passwords (cpassword)");
            try
            {
                foreach (GroupPolicyObject gpo in this.GroupPolicyObjects)
                {
                    if (string.IsNullOrEmpty(gpo.SysvolPath) || !Directory.Exists(gpo.SysvolPath))
                    {
                        continue;
                    }
                    string[] xmlFiles;
                    try
                    {
                        xmlFiles = Directory.GetFiles(gpo.SysvolPath, "*.xml", SearchOption.AllDirectories);
                    }
                    catch
                    {
                        continue;
                    }
                    foreach (string path in xmlFiles)
                    {
                        string fileName = Path.GetFileName(path);
                        if (!GppFiles.Any(f => string.Equals(f, fileName, StringComparison.OrdinalIgnoreCase)))
                        {
                            continue;
                        }
                        try
                        {
                            XmlDocument doc = new XmlDocument();
                            doc.XmlResolver = null;
                            doc.Load(path);
                            foreach (XmlNode node in doc.SelectNodes("//*[@cpassword]"))
                            {
                                string cpw = node.Attributes["cpassword"].Value;
                                if (string.IsNullOrEmpty(cpw))
                                {
                                    continue;
                                }
                                GppPassword gpp = new GppPassword
                                {
                                    Gpo = gpo.DisplayName,
                                    GpoGuid = gpo.Guid,
                                    FileType = Path.GetFileNameWithoutExtension(fileName),
                                    FilePath = path,
                                    CPassword = cpw
                                };
                                foreach (string attr in new[] { "userName", "accountName", "runAs", "username", "newName" })
                                {
                                    if (node.Attributes[attr] != null && !string.IsNullOrEmpty(node.Attributes[attr].Value))
                                    {
                                        gpp.UserName = node.Attributes[attr].Value;
                                        break;
                                    }
                                }
                                XmlNode changedNode = node.ParentNode != null && node.ParentNode.Attributes != null ? node.ParentNode.Attributes["changed"] : null;
                                if (changedNode != null)
                                {
                                    gpp.Changed = changedNode.Value;
                                }
                                string plain = DecryptCpassword(cpw);
                                gpp.Password = plain ?? string.Empty;
                                gpp.Decrypted = plain != null;
                                this.GroupPolicyPasswords.Add(gpp);
                                Console.WriteLine($"[!] GPP password found in '{gpo.DisplayName}' ({gpp.FileType}) for account '{gpp.UserName}'");
                            }
                        }
                        catch
                        {
                            // Skip unparsable files.
                        }
                    }
                }
                Console.WriteLine($"[*] Found {this.GroupPolicyPasswords.Count} Group Policy Preferences password(s)");
                this.Report.Record("Group Policy Preferences passwords", this.GroupPolicyPasswords.Count > 0 ? "OK" : "NONE", this.GroupPolicyPasswords.Count);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not scan Group Policy Preferences: {ex.Message}");
                this.Report.Record("Group Policy Preferences passwords", "FAILED", null, ex.Message);
            }
        }

        // ---- Access-control audit (DCSync / AdminSDHolder) --------------------------------

        private static readonly Guid RightGetChanges = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        private static readonly Guid RightGetChangesAll = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
        private static readonly Guid RightGetChangesFiltered = new Guid("89e95b76-444d-4c62-991a-0facbeda640c");

        private static string ResolvePrincipal(SecurityIdentifier sid)
        {
            try
            {
                return ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
            }
            catch
            {
                return sid.ToString();
            }
        }

        private bool IsDefaultDcSyncHolder(SecurityIdentifier sid)
        {
            string s = sid.ToString();
            if (s == "S-1-5-18" || s == "S-1-5-9" || s == "S-1-5-32-544")
            {
                return true;
            }
            foreach (int rid in new[] { 498, 512, 516, 519, 521 })
            {
                if (!string.IsNullOrEmpty(this.DomainSid) && s == $"{this.DomainSid}-{rid}")
                {
                    return true;
                }
            }
            return false;
        }

        private bool IsDefaultAdminSdHolder(SecurityIdentifier sid)
        {
            string s = sid.ToString();
            if (s == "S-1-5-18" || s == "S-1-5-10" || s == "S-1-5-32-544")
            {
                return true;
            }
            foreach (int rid in new[] { 512, 519 })
            {
                if (!string.IsNullOrEmpty(this.DomainSid) && s == $"{this.DomainSid}-{rid}")
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Reads the DACL of the domain head and of AdminSDHolder and records the principals holding
        /// directory-replication (DCSync) rights and AdminSDHolder control rights, flagging non-default holders.
        /// </summary>
        public void GetAccessControlAudit(string ldapString)
        {
            Console.WriteLine("[+] Auditing DCSync and AdminSDHolder access control");
            AccessControlAudit audit = new AccessControlAudit();

            try
            {
                using (DirectoryEntry de = new DirectoryEntry(ldapString))
                {
                    de.Options.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                    ActiveDirectorySecurity sec = de.ObjectSecurity;
                    foreach (ActiveDirectoryAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != AccessControlType.Allow)
                        {
                            continue;
                        }
                        string right = null;
                        bool extended = (rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0;
                        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) != 0)
                        {
                            right = "GenericAll";
                        }
                        else if (extended && rule.ObjectType == RightGetChangesAll)
                        {
                            right = "DS-Replication-Get-Changes-All";
                        }
                        else if (extended && rule.ObjectType == RightGetChanges)
                        {
                            right = "DS-Replication-Get-Changes";
                        }
                        else if (extended && rule.ObjectType == RightGetChangesFiltered)
                        {
                            right = "DS-Replication-Get-Changes-In-Filtered-Set";
                        }
                        else if (extended && rule.ObjectType == Guid.Empty)
                        {
                            right = "AllExtendedRights";
                        }
                        if (right == null)
                        {
                            continue;
                        }
                        SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                        bool def = this.IsDefaultDcSyncHolder(sid);
                        audit.DcSyncRights.Add(new AclRight
                        {
                            Object = "Domain",
                            ObjectDn = this.DomainDistinguishedName,
                            Principal = ResolvePrincipal(sid),
                            PrincipalSid = sid.ToString(),
                            Right = right,
                            AccessType = "Allow",
                            IsDefault = def
                        });
                        if (!def)
                        {
                            audit.NonDefaultDcSyncHolders++;
                            Console.WriteLine($"[!] Non-default DCSync right '{right}' held by {ResolvePrincipal(sid)}");
                        }
                    }
                    audit.DomainAclRead = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not read the domain DACL: {ex.Message}");
            }

            try
            {
                string asdhDn = "CN=AdminSDHolder,CN=System," + this.DomainDistinguishedName;
                using (DirectoryEntry de = new DirectoryEntry("LDAP://" + asdhDn))
                {
                    de.Options.SecurityMasks = SecurityMasks.Dacl;
                    ActiveDirectorySecurity sec = de.ObjectSecurity;
                    ActiveDirectoryRights control = ActiveDirectoryRights.GenericAll | ActiveDirectoryRights.WriteDacl |
                                                    ActiveDirectoryRights.WriteOwner | ActiveDirectoryRights.WriteProperty |
                                                    ActiveDirectoryRights.ExtendedRight;
                    foreach (ActiveDirectoryAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != AccessControlType.Allow)
                        {
                            continue;
                        }
                        if ((rule.ActiveDirectoryRights & control) == 0)
                        {
                            continue;
                        }
                        string right = (rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) != 0 ? "GenericAll"
                                     : (rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) != 0 ? "WriteDacl"
                                     : (rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) != 0 ? "WriteOwner"
                                     : (rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != 0 ? "AllExtendedRights"
                                     : "WriteProperty";
                        SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                        bool def = this.IsDefaultAdminSdHolder(sid);
                        audit.AdminSdHolderRights.Add(new AclRight
                        {
                            Object = "AdminSDHolder",
                            ObjectDn = asdhDn,
                            Principal = ResolvePrincipal(sid),
                            PrincipalSid = sid.ToString(),
                            Right = right,
                            AccessType = "Allow",
                            IsDefault = def
                        });
                        if (!def)
                        {
                            audit.NonDefaultAdminSdHolderHolders++;
                            Console.WriteLine($"[!] Non-default AdminSDHolder right '{right}' held by {ResolvePrincipal(sid)}");
                        }
                    }
                    audit.AdminSdHolderAclRead = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not read the AdminSDHolder DACL: {ex.Message}");
            }

            this.AccessControl = audit;
            Console.WriteLine($"[*] DCSync holders: {audit.DcSyncRights.Count} ({audit.NonDefaultDcSyncHolders} non-default); AdminSDHolder control: {audit.AdminSdHolderRights.Count} ({audit.NonDefaultAdminSdHolderHolders} non-default)");
            string status = (audit.DomainAclRead && audit.AdminSdHolderAclRead) ? "OK" : (audit.DomainAclRead || audit.AdminSdHolderAclRead) ? "PARTIAL" : "FAILED";
            this.Report.Record("Access control audit (DCSync/AdminSDHolder)", status, audit.NonDefaultDcSyncHolders + audit.NonDefaultAdminSdHolderHolders, "non-default holders");
        }

        public void GetDomainComputers(string ldapString)
        {
            DirectoryEntry directoryEntry = new DirectoryEntry(ldapString);
            directoryEntry.RefreshCache();

            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry, "(&(objectClass=computer)(objectClass=user))");
            directorySearcher.PageSize = 1000;

            String[] computerProperties = new string[] {
                "cn",
                "samaccountname",
                "dnshostname",
                "operatingsystem",
                "operatingsystemservicepack",
                "operatingsystemversion",
                "lastlogon",
                "useraccountcontrol",
                "whencreated",
                "objectsid",
                "description",
                "distinguishedname",
                "objectclass",
                "lastlogontimestamp",
                "pwdlastset",
                "ms-mcs-admpwdexpirationtime",
                "mslaps-passwordexpirationtime"
            };

            directorySearcher.PropertiesToLoad.AddRange(computerProperties);

            SearchResultCollection results = directorySearcher.FindAll();

            Console.WriteLine($"[*] Found {results.Count} computers!");
            this.Report.Record("Domain computers", "OK", results.Count);

            this.Computers = new Computer[results.Count];

            int count = 0;
            foreach (SearchResult result in results)
            {
                ResultPropertyCollection resultPropColl = result.Properties;

                String cn = GetString(resultPropColl, "cn");
                String samAccountName = GetString(resultPropColl, "samaccountname");
                String dnsHostName = GetString(resultPropColl, "dnshostname");
                String os = GetString(resultPropColl, "operatingsystem");
                String osServicePack = GetString(resultPropColl, "operatingsystemservicepack");
                String osVersion = GetString(resultPropColl, "operatingsystemversion");
                String lastLogon = resultPropColl["lastlogon"].Count > 0 ? this.ParseDateTime(GetLong(resultPropColl, "lastlogon")) : "";
                String rawUAC = GetString(resultPropColl, "useraccountcontrol");
                String[] uacFlags = Array.Empty<string>();

                if (!string.IsNullOrEmpty(rawUAC))
                {
                    uacFlags = this.ParseUacFlags(rawUAC);
                }
                String whenCreated = GetString(resultPropColl, "whencreated");
                String sid = GetSid(resultPropColl, "objectsid");
                String description = GetString(resultPropColl, "description");

                Computer computer = new Computer(
                    cn,
                    samAccountName,
                    dnsHostName,
                    os,
                    osServicePack,
                    osVersion,
                    lastLogon,
                    uacFlags,
                    whenCreated,
                    sid,
                    description
                );

                computer.DistinguishedName = GetString(resultPropColl, "distinguishedname");
                computer.LastLogonTimestamp = ToIso(GetLong(resultPropColl, "lastlogontimestamp"));
                long pwdLastSetRaw = GetLong(resultPropColl, "pwdlastset");
                computer.PwdLastSetUtc = ToIso(pwdLastSetRaw);
                if (!String.IsNullOrEmpty(samAccountName))
                {
                    this.computerPwdLastSetRaw[samAccountName] = pwdLastSetRaw;
                }

                String[] classes = this.GetDataValues(resultPropColl["objectclass"]);
                if (classes.Any(c => c.Equals("msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase)))
                {
                    computer.AccountType = "GroupManagedServiceAccount";
                }
                else if (classes.Any(c => c.Equals("msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)))
                {
                    computer.AccountType = "ManagedServiceAccount";
                }

                computer.LapsLegacyExpiration = ToIso(GetLong(resultPropColl, "ms-mcs-admpwdexpirationtime"));
                computer.LapsWindowsExpiration = ToIso(GetLong(resultPropColl, "mslaps-passwordexpirationtime"));
                computer.LapsManaged = computer.LapsLegacyExpiration.Length > 0 || computer.LapsWindowsExpiration.Length > 0;

                this.Computers[count] = computer;
                count++;
            }

            results.Dispose();
            directoryEntry.Dispose();
            directorySearcher.Dispose();
        }
    }
}
