using DSInternals.Replication;
using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SynerCommAuditTool.Client
{
    public class Extractor
    {
        private bool IsSuccess {  get; set; }

        public Extractor()
        {
            this.IsSuccess = false;
        }

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


        public void Extract()
        {

            DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain);
            Domain adDomain = Domain.GetDomain(domainContext);
            DomainController dc = adDomain.FindDomainController();

            Console.WriteLine($"Domain Name: {adDomain.Name}");
            Console.WriteLine($"DC: {dc}");

            String contextString = this.GetNamingContext(adDomain.Name);

            DirectoryReplicationClient replicator = new DirectoryReplicationClient(dc.ToString(), RpcProtocol.TCP);

            var accounts = replicator.GetAccounts(contextString);

            foreach (var account in accounts)
            {
                Console.WriteLine();
            }

        }
    }
}
