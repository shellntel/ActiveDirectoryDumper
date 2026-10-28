# Operating guide

Read this before running ADD in a production domain. It describes what the tool
needs, what it touches, and what defenders will see.

## Host requirements

* Windows 10, Windows 11 or Windows Server 2016 or later, 64-bit, joined to the domain being assessed. A domain controller is not required.
* .NET Framework 4.8 (included in current Windows versions).
* The Microsoft Visual C++ 2015-2022 x64 runtime. If it is missing, ADD launches the bundled `Redist\vc_redist.x64.exe` with an elevation prompt and installs it. This is the only change ADD makes to the host. Install the runtime beforehand if you would rather ADD never does.
* Free disk space in the working directory for the output zip (a few MB per thousand accounts).

## Account requirements

Run ADD as a domain account that has:

* Read access to the domain partition, which every domain user has, for the enumeration.
* The **Replicating Directory Changes** and **Replicating Directory Changes All** rights on the domain, for the hash extraction. Domain Admins and Enterprise Admins have these by default. A dedicated audit account can be granted just these two rights instead of full Domain Admin.
* Read access to the Password Settings Container (`CN=Password Settings Container,CN=System,...`), which by default only administrators have. Without it, fine-grained password policies are skipped with a warning.
* Read access to the SYSVOL share, which every domain user has.

ADD authenticates as the user running it and has no option to supply other credentials. **Run it from an elevated command prompt.** Under User Account Control a non-elevated process receives a filtered token with Domain Admins and Enterprise Admins removed, and the directory replication request is authorized by membership in those groups, so a non-elevated run fails with "Replication access was denied" even for a Domain Admin. To run as a dedicated audit account, start an elevated prompt as that account (`runas /user:DOMAIN\audituser cmd`, then launch ADD from it). To run it as a dedicated audit account, start it with `runas /user:DOMAIN\audituser ActiveDirectoryDumper.exe`.

## Network paths

All traffic goes to domain controllers of the current domain.

| Purpose | Protocol | Port |
| --- | --- | --- |
| Locate a DC, LDAP enumeration | LDAP | TCP 389 |
| Directory replication (hash extraction) | RPC endpoint mapper, then a dynamic RPC port | TCP 135, then TCP 49152-65535 by default |
| Read `GptTmpl.inf` from SYSVOL | SMB | TCP 445 |
| Locate domain controllers | DNS | UDP/TCP 53 |

## What defenders will see

ADD's hash extraction is the same directory replication request that security
products describe as "DCSync". Expect:

* Security event 4662 on the domain controller for the replication control access rights (`1131f6aa-...` and `1131f6ad-...`), attributed to the account running ADD.
* An alert from EDR, identity protection or SIEM rules that watch for replication requests from non-DC hosts.
* Possibly an EDR alert when ADD installs the VC++ runtime, because an unsigned console program launching an elevated installer is unusual.

Tell the client's security operations team the host, account and time window
before you run it, so the alerts can be confirmed as authorized activity
instead of investigated as an attack.

## Footprint

* Read-only against Active Directory. No objects, attributes or policies are changed.
* Writes only the staging folder `ActiveDirectoryDumper_DomainOutput\` (deleted after zipping) and the output zip `ActiveDirectoryDumper_<domain>_<yyyyMMdd-HHmmss>.zip` in the current directory.
* Installs the VC++ runtime if it is missing (see above). Nothing else is installed, no service or scheduled task is created, and nothing persists after the process exits.
* Does not contact any host outside the domain and does not phone home.

## Running

```
ActiveDirectoryDumper.exe              full enumeration plus hash dump, zipped
ActiveDirectoryDumper.exe --dumponly   hash dump only, no zip
ActiveDirectoryDumper.exe --verbose    also prints each hash line and reversible encryption detail to the console
```

Run from a folder you control, such as a dedicated engagement folder on an
encrypted volume, because the output is written to the current directory.

## After running

1. Read the collection report printed at the end of the run (also saved as `collection_report.txt` in the bundle). Confirm every step shows OK and the record counts look right for the domain; a FAILED step there is the first thing to investigate.
2. Verify the output zip `ActiveDirectoryDumper_<domain>_<timestamp>.zip` opened and contains `hm_domainoutput.json`, `hashes.pwdump`, `historical_hashes.pwdump` and `collection_report.txt`.
2. Transfer the zip to the analysis system over an encrypted channel.
3. Delete the zip from the collection host and empty the Recycle Bin. Do not leave it on a file share or in email.
4. If a dedicated audit account was used, consider disabling it until the next engagement.

## Troubleshooting

| Message | Meaning |
| --- | --- |
| `VC++ Redist not found` | The `Redist` folder is missing next to the exe. Re-extract the release zip. |
| `Error collecting hashes` | The account lacks the replication rights, or RPC to the DC is blocked. Check the rights above and TCP 135 plus the dynamic range. |
| `Replication access was denied` | The prompt is not elevated (UAC strips Domain Admins from the token) or the account truly lacks the replication rights. Launch ADD from an elevated command prompt. |
| `Could not load file or assembly 'DSInternals.Replication.Interop'` | `DSInternals.Replication.Interop.dll` is not beside the exe, or was blocked by Mark-of-the-Web. Re-extract so the DLL sits next to the exe, and unblock it (`Unblock-File`) if it came from a download. |
| `Could not read fine-grained password policies` | The account cannot read the Password Settings Container. Enumeration continues without PSO data. |
| `Could not scan Group Policy Objects` or `SYSVOL read errors` | SYSVOL is unreachable or a GPO folder is access-restricted. Enumeration continues; the GPO list notes which failed. |
| `Could not get password policy` | The domain object query failed. Usually a connectivity problem to the DC. |
