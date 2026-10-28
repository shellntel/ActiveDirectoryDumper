# ActiveDirectoryDumper

 <img width="1536" height="1024" alt="" src="https://github.com/user-attachments/assets/faa46f6f-5017-4601-8695-1384c121f1f0" />

## Data collection tool for use with [Hash Master 1000](https://github.com/shellntel/HashMaster1000)

Active Directory Dumper (ADD) gathers the information needed for a password and
account-hygiene audit of an Active Directory domain into one zip file: users,
computers, groups, trusts, password policies, a reversible encryption analysis,
and the password hashes from the directory for offline password analysis with
Hash Master 1000.

## Before you run this tool

ActiveDirectoryDumper extracts password hashes and sensitive configuration from
Active Directory. **Run it only against domains you own or are explicitly
authorized in writing to assess.** Download releases only from this
repository's [Releases](https://github.com/shellntel/ActiveDirectoryDumper/releases)
page and verify the published SHA-256 checksum, or review the source and build
it yourself; do not run binaries from any other source. The output contains
credential material for every account in the domain: protect it, transfer it
only over encrypted channels, and delete it when the engagement ends. This
software is provided as is, without warranty of any kind, and the authors
accept no liability for misuse.

## What it does

* Reads directory objects over LDAP and the password hashes through directory replication from one domain controller. The directory is never modified.
* Analyzes whether the domain, its password policies, or individual accounts store passwords with reversible encryption, and whether such passwords actually exist.
* Writes everything to a zip named for the domain and the date and time of the run (for example `ActiveDirectoryDumper_corp.example.com_20261022-103045.zip`) in the current directory.

[docs/DATA-COLLECTED.md](docs/DATA-COLLECTED.md) lists every attribute read and
every file written. [docs/OPERATING.md](docs/OPERATING.md) covers privileges,
network ports, what defenders will see, and cleanup.

## Requirements

* A 64-bit Windows host joined to the domain, with .NET Framework 4.8. It does not need to be a domain controller.
* A domain account with the **Replicating Directory Changes** and **Replicating Directory Changes All** rights (Domain Admins have these by default).
* The Visual C++ x64 runtime. If it is missing, ADD prompts for elevation and installs the bundled copy, which is the only change it makes to the host.

## Quick start

1. Download `ActiveDirectoryDumper.zip` from the latest release and check its hash:
   ```powershell
   Get-FileHash .\ActiveDirectoryDumper.zip -Algorithm SHA256
   ```
2. Extract it to a folder on the collection host and open a command prompt there.
3. Run the collection:
   ```
   .\ActiveDirectoryDumper.exe
   ```
4. Send the generated `ActiveDirectoryDumper_<domain>_<timestamp>.zip` to the analysis system over an encrypted channel, then delete it from the host.

```
.\ActiveDirectoryDumper.exe --help

  -d, --dumponly    (Default: false) Do not perform collection, only dump hashes
  -v, --verbose     (Default: false)
  --help            Display this help screen.
  --version         Display version information.
```

## Output

| File | Contents |
| --- | --- |
| `hm_domainoutput.json` | Domain, policies, Group Policy templates, posture, trusts, groups, users, computers, hashes and the per-account analysis, for Hash Master 1000. Field reference: [docs/JSON-FIELDS.md](docs/JSON-FIELDS.md) |
| `hashes.pwdump` | Current NT and LM hashes, one account per line |
| `historical_hashes.pwdump` | Password history hashes |
| `collection_report.txt` | Run report: per-step success/failure, record counts and a findings snapshot (also printed on screen) |

## Reversible encryption analysis

"Store passwords using reversible encryption" can be enabled by the domain
password policy, a fine-grained password policy, a Group Policy Object, or on
an individual account, and it only takes effect for passwords set while it is
on. ADD collects all of those sources plus what is actually stored in the
directory and reports a status for each account: `NotEnabled`,
`EnabledNotStored`, `Stored`, `StoredSettingDisabled` or `Unknown`. Stored
cleartext passwords are never written out; only their presence and length are
recorded. Details are in [docs/DATA-COLLECTED.md](docs/DATA-COLLECTED.md).

## Building from source

See [BUILDING.md](BUILDING.md). `build.cmd` builds it from the command line or
from VS Code with Visual Studio 2022 Build Tools.

## Verifying a dump
`tools/validate_output.py` checks that a dump carries the expected data points and that they
were populated, printing only field names, counts and non-identifying values (no account names,
SIDs, hashes or secrets), so it is safe to run on sensitive output and the report is safe to share:

```
python3 tools/validate_output.py ActiveDirectoryDumper_<domain>_<timestamp>.zip
```

It accepts the output zip or an extracted `hm_domainoutput.json`, and exits non-zero if a key
component is missing. Older dumps that predate these features intentionally fail the new-feature checks.

## Problems and security reports

Open an issue for bugs and questions. For security problems, including
sensitive data appearing in the output, follow [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## License

ActiveDirectoryDumper may be used, modified and shared at no charge for security
auditing, assessment and penetration testing, including paid engagements, by
anyone. It may not be sold or built into any product or service that is sold
or offered for profit. See [LICENSE](LICENSE) for the terms.
