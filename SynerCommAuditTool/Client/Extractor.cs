using DSInternals.Common.Data;
using DSInternals.Replication;
using System;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Runtime.Remoting.Messaging;
using System.Security.Principal;

namespace SynerCommAuditTool.Client
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


        public void Extract(bool verbose, String outputDir)
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

            using (StreamWriter writetext = new StreamWriter($"{outputDir}\\hashes.pwdump", false))
            {
                foreach (var account in accounts)
                {
                    String lmHash = "aad3b435b51404eeaad3b435b51404ee";
                    String ntHash = "";
                    String rid = this.GetAccountRID(account);

                    if (account.LMHash != null && account.LMHash.Length > 0)
                    {
                        lmHash = BitConverter.ToString(account.LMHash).Replace("-", "");
                    }
                    if (account.NTHash != null && account.NTHash.Length > 0)
                    {
                        ntHash = BitConverter.ToString(account.NTHash).Replace("-", "").ToLower();
                    }
                    writetext.WriteLine($"{account.LogonName}:{rid}:{lmHash}:{ntHash}:::");

                    if (verbose)
                    {
                        Console.WriteLine($"{account.LogonName}:{rid}:{lmHash}:{ntHash}:::");
                    }
                }
            }
            replicator.Dispose();
        }
    }
}
