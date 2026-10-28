#!/usr/bin/env python3
"""
validate_output.py - structural/coverage check for an ActiveDirectoryDumper dump.

Confirms that a hm_domainoutput.json (or the output .zip containing it) carries the
ADD 3.0 data points and that they were actually populated, WITHOUT printing any
sensitive content. The report contains only field names, booleans, aggregate counts
and non-identifying enum values (status names, Kerberos key types, functional level).
It never prints account names, SIDs, hashes, descriptions or distinguished names, so
the report itself is safe to share.

Usage:
    python3 validate_output.py <hm_domainoutput.json | ActiveDirectoryDumper_*.zip>

Exit code 0 if all key 3.0 components are present and populated, 1 otherwise.
Runs on stock Python 3, no dependencies. Read with -I on untrusted input:
    python3 -I validate_output.py <file>
"""
import sys, json, zipfile, io

RESET="\033[0m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"
def c(code,t):
    return f"{code}{t}{RESET}" if sys.stdout.isatty() else t

results=[]
def check(ok, label, detail=""):
    tag = c(GREEN,"PASS") if ok=="pass" else c(YELLOW,"WARN") if ok=="warn" else c(RED,"FAIL")
    results.append(ok)
    print(f"  [{tag}] {label}" + (f" - {detail}" if detail else ""))

def load(path):
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            names=[n for n in z.namelist() if n.lower().endswith("hm_domainoutput.json")]
            if not names:
                sys.exit("No hm_domainoutput.json inside the zip.")
            with z.open(names[0]) as f:
                return json.load(io.TextIOWrapper(f, encoding="utf-8"))
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def pct(n, total):
    return f"{n}/{total} ({100*n//total if total else 0}%)"

def main():
    if len(sys.argv)!=2:
        sys.exit(__doc__)
    d = load(sys.argv[1])
    users = d.get("Users") or []
    comps = d.get("Computers") or []
    nu, nc = len(users), len(comps)

    print("\n=== Identity / schema ===")
    sv = d.get("SchemaVersion")
    check("pass" if sv else "fail", "SchemaVersion present", str(sv))
    check("pass" if d.get("CollectorVersion") else "warn", "CollectorVersion present", str(d.get("CollectorVersion")))
    if not sv:
        cv = str(d.get("CollectorVersion") or "")
        if cv:
            print("\n  SchemaVersion absent but CollectorVersion is " + cv + ": a build from before"
                  "\n  SchemaVersion was added. Regenerate with the current release; a couple of checks below"
                  "\n  will fail by design on this older file.\n")
        else:
            print("\n  SchemaVersion absent: this looks like a pre-3.0 (schema 1) file. New-feature checks"
                  "\n  below will fail by design; that is expected for an older ADD or ADDHelper export.\n")

    print("=== New top-level blocks ===")
    for key, kind in [("PwdPropertiesFlags",list),("DomainReversibleEncryptionEnabled",bool),
                      ("DomainComplexityEnabled",bool),("DomainSid",str),("DomainDistinguishedName",str),
                      ("PasswordSettingsObjects",list),("GroupPolicyObjects",list),
                      ("SecurityPosture",dict),("ReversibleEncryption",dict),("Summary",dict),
                      ("PullTimeUtc",str)]:
        present = key in d and isinstance(d[key], kind)
        extra = (f"{len(d[key])} item(s)" if present and kind is list else "")
        check("pass" if present else "fail", f"{key}", extra)

    print("\n=== Password policy sources ===")
    psos = d.get("PasswordSettingsObjects") or []
    check("pass" if "PasswordSettingsObjects" in d else "fail", "Fine-grained policies collected", f"{len(psos)} PSO(s)")
    gpos = d.get("GroupPolicyObjects") or []
    gpo_tmpl = sum(1 for g in gpos if g.get("GptTmplFound"))
    check("pass" if gpos else "warn", "GPO security templates scanned", f"{len(gpos)} GPO(s), {gpo_tmpl} with template")
    sp = d.get("SecurityPosture") or {}
    check("pass" if sp.get("DomainFunctionalLevel") else "warn", "Domain functional level", str(sp.get("DomainFunctionalLevel")))
    check("pass" if sp.get("DomainControllerCount",0)>=1 else "warn", "Domain controllers counted", str(sp.get("DomainControllerCount")))
    dcs = sp.get("DomainControllerSettings") or []
    check("pass" if dcs else "warn", "DC security settings resolved", f"{len(dcs)} setting(s)")

    print("\n=== Per-user new fields (coverage) ===")
    if nu:
        def has(u,k): 
            v=u.get(k); 
            return v not in (None,"",[],{})
        eff = sum(1 for u in users if (u.get("EffectivePasswordPolicy") or {}).get("Source") in ("FineGrainedPolicy","DomainPolicy"))
        check("pass" if eff==nu else "warn", "EffectivePasswordPolicy resolved", pct(eff,nu))
        ntds = sum(1 for u in users if (u.get("StoredCredentials") or {}).get("NtdsChecked"))
        check("pass" if ntds>0 else "fail", "StoredCredentials from NTDS", pct(ntds,nu))
        statuses={}
        for u in users:
            st=(u.get("ReversibleEncryption") or {}).get("Status","(missing)")
            statuses[st]=statuses.get(st,0)+1
        valid={"NotEnabled","EnabledNotStored","Stored","StoredSettingDisabled","Unknown"}
        ok_status = set(statuses)<=valid and "(missing)" not in statuses
        check("pass" if ok_status else "fail", "ReversibleEncryption.Status on every user",
              ", ".join(f"{k}={v}" for k,v in sorted(statuses.items())))
        llts = sum(1 for u in users if has(u,"LastLogonTimestamp"))
        check("pass" if llts>0 else "warn", "LastLogonTimestamp (replicated)", pct(llts,nu))
        pwdutc = sum(1 for u in users if has(u,"PwdLastSetUtc"))
        check("pass" if pwdutc>0 else "warn", "PwdLastSetUtc", pct(pwdutc,nu))
        priv = sum(1 for u in users if u.get("IsPrivileged"))
        check("pass" if priv>0 else "warn", "Privileged accounts (nested) resolved", f"{priv} flagged")
        krb = sum(1 for u in users if u.get("IsKrbtgt"))
        check("pass" if krb>=1 else "warn", "krbtgt identified", f"{krb}")
        # Kerberos key types seen (non-identifying enum)
        kt=set()
        for u in users: kt.update((u.get("StoredCredentials") or {}).get("KerberosKeyTypes") or [])
        check("pass" if kt else "warn", "Kerberos key types captured", ", ".join(sorted(kt)) or "none")
        noaes = sum(1 for u in users if (u.get("StoredCredentials") or {}).get("NoAesKeys"))
        check("pass","Accounts with no AES keys (RC4/DES only)", f"{noaes}")
        # schema presence of the remaining fields (existence, not value)
        for k in ["AccountExpires","PasswordExpiryTime","UserAccountControlComputed","LockedOut",
                  "PasswordExpired","Info","Comment","LegacyPasswordAttributes","PrivilegedGroups","Rid"]:
            check("pass" if k in users[0] else "fail", f"field present: {k}")
    else:
        check("warn","No users in file (dump-only mode?)")

    print("\n=== Per-computer new fields ===")
    if nc:
        check("pass" if "AccountType" in comps[0] else "fail", "AccountType present")
        dc = sum(1 for cc in comps if cc.get("IsDomainController"))
        check("pass" if dc>=1 else "warn", "Domain controllers flagged", f"{dc}")
        msa = sum(1 for cc in comps if cc.get("AccountType")!="Computer")
        check("pass","Managed service accounts classified", f"{msa}")
        laps = sum(1 for cc in comps if cc.get("LapsManaged"))
        check("pass","LAPS-managed computers", f"{laps}")
        sidpop = sum(1 for cc in comps if cc.get("SID"))
        check("pass" if sidpop>0 else "warn", "Computer SID populated (2.3 bug fixed)", pct(sidpop,nc))
        check("pass" if "PwdLastSetUtc" in comps[0] else "fail", "field present: PwdLastSetUtc")
    else:
        check("warn","No computers in file")

    print("\n=== Summary cross-check (recompute vs reported) ===")
    s = d.get("Summary") or {}
    if nu and s:
        def rec(pred): return sum(1 for u in users if pred(u))
        checks = {
            "UsersEnabled": rec(lambda u:"ACCOUNT_DISABLED" not in (u.get("UserAccountControl") or [])),
            "UsersPrivileged": rec(lambda u:u.get("IsPrivileged")),
            "UsersKerberoastable": rec(lambda u:("ACCOUNT_DISABLED" not in (u.get("UserAccountControl") or [])) and not u.get("IsKrbtgt") and (u.get("ServicePrincipalNames") or [])),
        }
        for k,v in checks.items():
            rep=s.get(k)
            check("pass" if rep==v else "warn", f"Summary.{k}", f"reported {rep}, recomputed {v}")
    else:
        check("warn","Summary cross-check skipped")

    print("\n=== Audit blocks (schema 2.1) ===")
    major_minor = (d.get("SchemaVersion") or "")
    want21 = major_minor.startswith("2.1") or major_minor > "2.1"
    acl = d.get("AccessControl")
    gpp = d.get("GroupPolicyPasswords")
    if acl is None and gpp is None:
        check("warn" if want21 else "pass", "GroupPolicyPasswords / AccessControl (2.1 blocks)",
              "absent (expected on schema < 2.1)")
    else:
        if gpp is not None:
            dec = sum(1 for g in gpp if g.get("Decrypted"))
            check("pass", "GroupPolicyPasswords present", f"{len(gpp)} found, {dec} decrypted")
        else:
            check("warn" if want21 else "pass", "GroupPolicyPasswords", "absent")
        if acl is not None:
            check("pass", "AccessControl present",
                  f"{acl.get('NonDefaultDcSyncHolders',0)} non-default DCSync, {acl.get('NonDefaultAdminSdHolderHolders',0)} non-default AdminSDHolder")
            check("pass" if acl.get("DomainAclRead") else "warn", "Domain DACL read")
            check("pass" if acl.get("AdminSdHolderAclRead") else "warn", "AdminSDHolder DACL read")
        else:
            check("warn" if want21 else "pass", "AccessControl", "absent")

    nfail=results.count("fail"); nwarn=results.count("warn")
    print("\n"+"="*52)
    verdict = c(RED,"FAIL") if nfail else c(GREEN,"PASS") if not nwarn else c(YELLOW,"PASS (with warnings)")
    print(f"  Overall: {verdict}  |  {results.count('pass')} pass, {nwarn} warn, {nfail} fail")
    print("  (report contains no account names, SIDs, hashes or secrets)")
    print("="*52+"\n")
    sys.exit(1 if nfail else 0)

if __name__=="__main__":
    main()
