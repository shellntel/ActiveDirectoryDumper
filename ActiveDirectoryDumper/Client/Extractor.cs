using DSInternals.Common.Data;
using DSInternals.Replication;
using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace ActiveDirectoryDumper.Client
{
    public class Extractor
    {
        private const string BlankLmHash = "aad3b435b51404eeaad3b435b51404ee";
        private const string BlankNtHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

        private String GetNamingContext(String domain)
        {
            string[] domainFqdn = domain.Split('.');

            String endString = $"dc={domainFqdn[domainFqdn.Length - 1]}";
            String contextString = "";

            for (int i = 0; i <= domainFqdn.Length - 2; i++)
            {
                contextString += $"dc={domainFqdn[i]},";
            }

            contextString += endString;

            return contextString;
        }

        private String GetAccountRID(DSAccount account)
        {
            SecurityIdentifier sid = account.Sid;
            if (sid == null)
            {
                return "";
            }
            String[] sidSplit = sid.ToString().Split('-');
            String rid = sidSplit[sidSplit.Length - 1];

            return rid;
        }

        /// <summary>Facts about the stored secrets of one replicated account. No key material is retained.</summary>
        private static StoredCredentials DescribeStoredCredentials(DSAccount account, String lmHash, String ntHash)
        {
            StoredCredentials sc = new StoredCredentials();
            sc.NtdsChecked = true;
            sc.HasLmHash = lmHash != BlankLmHash;
            sc.HasBlankNtHash = ntHash == BlankNtHash;
            sc.NtHashHistoryCount = account.NTHashHistory != null ? account.NTHashHistory.Length : 0;

            List<String> keyTypes = new List<String>();
            SupplementalCredentials sup = account.SupplementalCredentials;
            if (sup != null)
            {
                if (sup.KerberosNew != null && sup.KerberosNew.Credentials != null)
                {
                    foreach (KerberosKeyDataNew key in sup.KerberosNew.Credentials)
                    {
                        keyTypes.Add(key.KeyType.ToString());
                    }
                }
                else if (sup.Kerberos != null && sup.Kerberos.Credentials != null)
                {
                    foreach (KerberosKeyData key in sup.Kerberos.Credentials)
                    {
                        keyTypes.Add(key.KeyType.ToString());
                    }
                }
            }

            sc.KerberosKeyTypes = keyTypes.Distinct().ToArray();
            sc.HasKerberosKeys = sc.KerberosKeyTypes.Length > 0;
            sc.HasAesKeys = sc.KerberosKeyTypes.Any(k => k.StartsWith("AES", StringComparison.OrdinalIgnoreCase));
            sc.HasDesKeys = sc.KerberosKeyTypes.Any(k => k.StartsWith("DES", StringComparison.OrdinalIgnoreCase));
            sc.NoAesKeys = sc.HasKerberosKeys && !sc.HasAesKeys;
            return sc;
        }


        public void Extract(bool verbose, String outputDir, Customer customer)
        {
            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();

            String contextString = this.GetNamingContext(adDomain.Name);

            DirectoryReplicationClient replicator = new DirectoryReplicationClient(dc.ToString(), RpcProtocol.TCP);

            // Materialize in a single replication pass. GetAccounts is a lazy iterator that runs a
            // full DCSync replication on every enumeration, so iterating it twice (current hashes,
            // then history) replicated the whole domain twice; on a large domain the second pass
            // could fail or return incomplete, yielding current hashes but no history. One pass fixes that.
            List<DSAccount> accounts = replicator.GetAccounts(contextString).ToList();
            Console.WriteLine($"[*] Replicated {accounts.Count} accounts");

            // In --dumponly mode no LDAP enumeration has run, so these are null.
            List<User> users = new List<User>(customer.Users ?? Array.Empty<User>());
            List<Computer> computers = new List<Computer>(customer.Computers ?? Array.Empty<Computer>());
            Dictionary<String, User> usersBySam = new Dictionary<String, User>(StringComparer.OrdinalIgnoreCase);
            Dictionary<String, Computer> computersBySam = new Dictionary<String, Computer>(StringComparer.OrdinalIgnoreCase);
            foreach (User u in users) { if (!String.IsNullOrEmpty(u.SamAccountName)) usersBySam[u.SamAccountName] = u; }
            foreach (Computer c in computers) { if (!String.IsNullOrEmpty(c.SamAccountName)) computersBySam[c.SamAccountName] = c; }

            int clearTextCount = 0;
            int dumpedCount = 0;
            List<String> clearTextAccounts = new List<String>();

            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\hashes.pwdump", false))
            {
                foreach (var account in accounts)
                {
                    String lmHash = BlankLmHash;
                    String ntHash = "";
                    String rid = this.GetAccountRID(account);
                    String acctStatus = account.Enabled ? "Enabled" : "Disabled";

                    if (account.LMHash != null && account.LMHash.Length > 0)
                    {
                        lmHash = BitConverter.ToString(account.LMHash).Replace("-", "").ToLower();
                    }
                    if (account.NTHash != null && account.NTHash.Length > 0)
                    {
                        ntHash = BitConverter.ToString(account.NTHash).Replace("-", "").ToLower();
                    }
                    writetext.WriteLine($"{account.LogonName}:{rid}:{lmHash}:{ntHash}::: (status={acctStatus})");
                    dumpedCount++;

                    if (verbose)
                    {
                        Console.WriteLine($"{account.LogonName}:{rid}:{lmHash}:{ntHash}::: (status={acctStatus})");
                    }

                    // Reversible encryption ground truth: when it is in effect at the time a password is set,
                    // the DC stores a Primary:CLEARTEXT package inside supplementalCredentials.
                    String clearText = account.SupplementalCredentials?.ClearText;
                    bool clearTextStored = !String.IsNullOrEmpty(clearText);
                    int clearTextLength = clearTextStored ? clearText.Length : 0;

                    if (clearTextStored)
                    {
                        clearTextCount++;
                        clearTextAccounts.Add(account.LogonName);
                        if (verbose)
                        {
                            Console.WriteLine($"    [!] {account.LogonName} has a cleartext (reversibly encrypted) password stored, length {clearTextLength}");
                        }
                    }

                    StoredCredentials stored = DescribeStoredCredentials(account, lmHash, ntHash);

                    User user;
                    Computer computer;
                    String sam = account.SamAccountName ?? "";
                    usersBySam.TryGetValue(sam, out user);
                    computersBySam.TryGetValue(sam, out computer);

                    if (user != null)
                    {
                        user.NTLMHash = $"{lmHash}:{ntHash}";
                        user.LogonName = account.LogonName;
                        user.ReversibleEncryption.NtdsChecked = true;
                        user.ReversibleEncryption.ClearTextPasswordStored = clearTextStored;
                        user.ReversibleEncryption.ClearTextPasswordLength = clearTextLength;
                        user.StoredCredentials = stored;
                    }

                    if (computer != null)
                    {
                        computer.NTLMHash = $"{lmHash}:{ntHash}";
                        computer.ReversibleEncryption.NtdsChecked = true;
                        computer.ReversibleEncryption.ClearTextPasswordStored = clearTextStored;
                        computer.ReversibleEncryption.ClearTextPasswordLength = clearTextLength;
                        computer.StoredCredentials = stored;
                    }
                }
            }

            if (clearTextCount > 0)
            {
                Console.WriteLine($"[!] {clearTextCount} account(s) have a cleartext (reversibly encrypted) password stored in NTDS.dit: {String.Join(", ", clearTextAccounts)}");
            }
            else
            {
                Console.WriteLine("[*] No accounts have a cleartext (reversibly encrypted) password stored in NTDS.dit");
            }
            customer.Report.Record("Hash collection (NTDS)", "OK", dumpedCount);

            // password history
            Console.WriteLine("[+] Dumping historical hashes");
            int historyCount = 0;
            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\historical_hashes.pwdump", false))
            {
                foreach (var account in accounts)
                {
                    String lmHash = BlankLmHash;
                    String ntHash = "";
                    String rid = this.GetAccountRID(account);

                    if (account.LMHashHistory != null)
                    {
                        for (int i = 0; i < account.LMHashHistory.Length; i++)
                        {
                            lmHash = BitConverter.ToString(account.LMHashHistory[i]).Replace("-", "").ToLower();
                        }
                    }

                    if (account.NTHashHistory != null)
                    {
                        List<String> ntHistory = new List<String>();

                        for (int i = 0; i < account.NTHashHistory.Length; i++)
                        {
                            ntHash = BitConverter.ToString(account.NTHashHistory[i]).Replace("-", "").ToLower();

                            ntHistory.Add(ntHash);

                            writetext.WriteLine($"{account.LogonName}_{i}:{rid}:{lmHash}:{ntHash}:::");
                            historyCount++;
                        }

                        User user;
                        if (usersBySam.TryGetValue(account.SamAccountName ?? "", out user))
                        {
                            user.HistoricalNTHashes = ntHistory.ToArray();
                        }
                    }
                }
            }
            customer.Report.Record("Historical hashes", "OK", historyCount);
            replicator.Dispose();
        }
    }
}
