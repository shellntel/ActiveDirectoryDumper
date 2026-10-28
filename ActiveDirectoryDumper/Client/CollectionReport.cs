using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>One collection step's outcome for the run report.</summary>
    public class ReportStep
    {
        public string Name { get; set; }
        /// <summary>OK, PARTIAL, SKIPPED, NONE or FAILED.</summary>
        public string Status { get; set; }
        public int? Records { get; set; }
        public string Detail { get; set; } = String.Empty;
    }

    /// <summary>
    /// Accumulates per-step success/failure and record counts during a run, then renders a text
    /// report for the console and for collection_report.txt inside the output bundle.
    /// </summary>
    public class CollectionReport
    {
        private readonly List<ReportStep> steps = new List<ReportStep>();
        private readonly DateTime startUtc = DateTime.UtcNow;

        public IReadOnlyList<ReportStep> Steps { get { return steps; } }

        /// <summary>Record a step outcome; a later call for the same name replaces the earlier one.</summary>
        public void Record(string name, string status, int? records = null, string detail = "")
        {
            steps.RemoveAll(s => s.Name == name);
            steps.Add(new ReportStep { Name = name, Status = status, Records = records, Detail = detail ?? String.Empty });
        }

        private static string N(int n) { return n.ToString("N0"); }
        private static string Pct(int n, int total) { return total > 0 ? $"{N(n)} ({100L * n / total}%)" : "0"; }

        private static void Row(StringBuilder sb, string label, string value)
        {
            sb.AppendLine($" {label,-44}{value,14}");
        }

        public string Render(Customer c)
        {
            User[] users = c.Users ?? Array.Empty<User>();
            Computer[] comps = c.Computers ?? Array.Empty<Computer>();
            int nu = users.Length, nc = comps.Length;
            PasswordSecuritySummary s = c.Summary ?? new PasswordSecuritySummary();
            ReversibleEncryptionSummary rev = c.ReversibleEncryption ?? new ReversibleEncryptionSummary();

            string eq = new string('=', 60);
            string da = new string('-', 60);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(eq);
            sb.AppendLine(" ActiveDirectoryDumper - Collection Report");
            sb.AppendLine(eq);
            sb.AppendLine($" Domain:     {c.Name}");
            sb.AppendLine($" Completed:  {DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")}");
            sb.AppendLine($" Collector:  {c.CollectorVersion}   (schema {c.SchemaVersion})");
            sb.AppendLine($" Duration:   {(DateTime.UtcNow - startUtc).ToString("hh\\:mm\\:ss")}");

            int ok = steps.Count(x => x.Status == "OK");
            int bad = steps.Count(x => x.Status == "FAILED");
            int skip = steps.Count(x => x.Status == "SKIPPED");
            sb.AppendLine($" Steps:      {ok} ok, {bad} failed, {skip} skipped of {steps.Count}");

            sb.AppendLine(da);
            sb.AppendLine(" COLLECTION STEPS                         STATUS    RECORDS");
            sb.AppendLine(da);
            foreach (ReportStep st in steps)
            {
                string rec = st.Records.HasValue ? N(st.Records.Value) : "-";
                sb.AppendLine($" {st.Name,-40} {st.Status,-8} {rec,8}");
                if (!String.IsNullOrEmpty(st.Detail))
                {
                    sb.AppendLine($"     {st.Detail}");
                }
            }

            sb.AppendLine(da);
            sb.AppendLine(" RECORD COUNTS");
            sb.AppendLine(da);
            Row(sb, "Users", N(nu));
            Row(sb, "Computers", N(nc));
            Row(sb, "Groups", N((c.Groups ?? Array.Empty<Group>()).Length));
            Row(sb, "Domain trusts", N((c.DomainTrusts ?? new List<Dictionary<string, string>>()).Count));
            Row(sb, "Fine-grained password policies", N(c.PasswordSettingsObjects.Count));
            Row(sb, "Group Policy objects", N(c.GroupPolicyObjects.Count));
            Row(sb, "Privileged accounts (nested)", N(s.UsersPrivileged));
            Row(sb, "Domain controllers", N(s.ComputersDomainControllers));

            if (nu > 0)
            {
                sb.AppendLine(da);
                sb.AppendLine($" USER DATA POPULATION (of {N(nu)} users)");
                sb.AppendLine(da);
                int ntds = users.Count(u => u.StoredCredentials != null && u.StoredCredentials.NtdsChecked);
                int krb = users.Count(u => u.StoredCredentials != null && u.StoredCredentials.HasKerberosKeys);
                int llts = users.Count(u => !String.IsNullOrEmpty(u.LastLogonTimestamp));
                int pwdutc = users.Count(u => !String.IsNullOrEmpty(u.PwdLastSetUtc));
                int eff = users.Count(u => u.EffectivePasswordPolicy != null && !String.IsNullOrEmpty(u.EffectivePasswordPolicy.Source));
                Row(sb, "NT hash / stored credentials", Pct(ntds, nu));
                Row(sb, "Kerberos keys", Pct(krb, nu));
                Row(sb, "Effective password policy resolved", Pct(eff, nu));
                Row(sb, "Replicated last logon", Pct(llts, nu));
                Row(sb, "Password last set (precise)", Pct(pwdutc, nu));
                Row(sb, "Under a fine-grained policy", N(s.UsersUnderFineGrainedPolicy));
            }

            sb.AppendLine(da);
            sb.AppendLine(" FINDINGS SNAPSHOT");
            sb.AppendLine(da);
            Row(sb, "Domain functional level", c.SecurityPosture?.DomainFunctionalLevel ?? "");
            Row(sb, "Domain reversible encryption", rev.DomainPolicyEnabled ? "ENABLED" : "disabled");
            Row(sb, "Users with cleartext stored", N(rev.UsersWithClearTextStored));
            Row(sb, "  of those, setting now disabled", N(rev.UsersStoredSettingDisabled));
            Row(sb, "Computers with cleartext stored", N(rev.ComputersWithClearTextStored));
            Row(sb, "Kerberoastable users", N(s.UsersKerberoastable));
            Row(sb, "AS-REP roastable users", N(s.UsersAsRepRoastable));
            Row(sb, "Accounts with no AES keys", N(s.UsersNoAesKeys));
            Row(sb, "LM hashes stored", N(s.UsersWithLmHash));
            Row(sb, "Blank NT hashes", N(s.UsersWithBlankNtHash));
            Row(sb, "Password never expires", N(s.UsersPasswordNeverExpires));
            Row(sb, "Password not required", N(s.UsersPasswordNotRequired));
            Row(sb, "Legacy password attributes", N(s.UsersWithLegacyPasswordAttributes));
            Row(sb, "krbtgt password age (days)", s.KrbtgtPasswordAgeDays.ToString("N0"));
            Row(sb, "LAPS-managed computers", N(s.ComputersLapsManaged));
            Row(sb, "GPP passwords in SYSVOL", N((c.GroupPolicyPasswords ?? new List<GppPassword>()).Count));
            Row(sb, "Non-default DCSync holders", N((c.AccessControl ?? new AccessControlAudit()).NonDefaultDcSyncHolders));
            Row(sb, "Non-default AdminSDHolder control", N((c.AccessControl ?? new AccessControlAudit()).NonDefaultAdminSdHolderHolders));

            sb.AppendLine(eq);
            if (bad > 0)
            {
                sb.AppendLine($" RESULT: COMPLETED WITH {bad} FAILED STEP(S) - see above");
            }
            else if (skip > 0)
            {
                sb.AppendLine($" RESULT: COMPLETED ({skip} step(s) skipped)");
            }
            else
            {
                sb.AppendLine(" RESULT: COMPLETED - all steps succeeded");
            }
            sb.AppendLine(eq);
            return sb.ToString();
        }
    }
}
