using DSInternals.Common.Data;
using DSInternals.Replication;
using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Security.Principal;

namespace ActiveDirectoryDumper.Client
{
    public class Extractor
    {
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


        public void Extract(bool verbose, String outputDir, Customer customer)
        {
            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();

            String contextString = this.GetNamingContext(adDomain.Name);

            DirectoryReplicationClient replicator = new DirectoryReplicationClient(dc.ToString(), RpcProtocol.TCP);

            var accounts = replicator.GetAccounts(contextString, (c, processed, total) =>
                Console.WriteLine($"[+] Progress: {processed}/{total}")
            );

            if (verbose)
            {
                accounts = replicator.GetAccounts(contextString);
            }

            List<User> users = new List<User>(customer.Users);

            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\hashes.pwdump", false))
            {
                foreach (var account in accounts)
                {
                    String lmHash = "aad3b435b51404eeaad3b435b51404ee";
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

                    if (verbose)
                    {
                        Console.WriteLine($"{account.LogonName}:{rid}:{lmHash}:{ntHash}::: (status={acctStatus})");
                    }

                    User user = users.Find(u => u.SamAccountName == account.SamAccountName);

                    if (user != null)
                    {
                        user.NTLMHash = $"{lmHash}:{ntHash}";
                        user.LogonName = account.LogonName;
                    }
                }
            }

            // password history
            Console.WriteLine("[+] Dumping historical hashes");
            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\historical_hashes.pwdump", false))
            {
                foreach (var account in accounts)
                {
                    String lmHash = "aad3b435b51404eeaad3b435b51404ee";
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
                            if (i == 0)
                            {
                                // skip first hash which is the current
                                continue;
                            }
                            ntHash = BitConverter.ToString(account.NTHashHistory[i]).Replace("-", "").ToLower();

                            ntHistory.Add(ntHash);

                            writetext.WriteLine($"{account.LogonName}_{i}:{rid}:{lmHash}:{ntHash}:::");
                            if (verbose)
                            {
                                Console.WriteLine($"{account.LogonName}_{i}:{rid}:{lmHash}:{ntHash}:::");
                            }
                        }

                        User user = users.Find(u => u.SamAccountName == account.SamAccountName);
                        if (user != null)
                        {
                            user.HistoricalNTHashes = ntHistory.ToArray();
                        }
                    }
                }
            }
            replicator.Dispose();
        }
    }
}
