# What ActiveDirectoryDumper collects and writes

This page lists everything ADD reads from Active Directory and every file it
writes, so a security team can review the tool before approving it. ADD is
read-only against the directory: it never modifies, creates or deletes any
directory object or setting.

## Directory data read over LDAP

ADD binds to the domain of the logged-on user and runs paged searches from the
domain root. Only the attributes listed are requested.

| Objects | Filter | Attributes |
| --- | --- | --- |
| Users | `(&(objectCategory=person)(objectClass=user))` | cn, name, sAMAccountName, memberOf, displayName, primaryGroupID, whenCreated, whenChanged, lastLogon, lastLogonTimestamp, userAccountControl, msDS-User-Account-Control-Computed, pwdLastSet, accountExpires, msDS-UserPasswordExpiryTimeComputed, lockoutTime, objectSid, description, info, comment, servicePrincipalName, adminCount, msDS-SupportedEncryptionTypes, msDS-AllowedToDelegateTo, distinguishedName, msDS-ResultantPSO, userPassword, unixUserPassword, msSFU30Password (presence only; values are discarded) |
| Computers | `(&(objectClass=computer)(objectClass=user))` | cn, sAMAccountName, dNSHostName, operatingSystem, operatingSystemServicePack, operatingSystemVersion, lastLogon, lastLogonTimestamp, pwdLastSet, userAccountControl, whenCreated, objectSid, description, distinguishedName, objectClass, ms-Mcs-AdmPwdExpirationTime, msLAPS-PasswordExpirationTime (LAPS expiry only; LAPS passwords are never requested) |
| Groups | `(objectClass=group)` | cn, description, groupType, member |
| Trusts | `(objectClass=trustedDomain)` | trustPartner, trustDirection, trustType |
| Domain password policy | `(objectClass=domainDNS)` on the domain object | maxPwdAge, minPwdAge, minPwdLength, pwdProperties, lockoutDuration, lockoutObservationWindow, lockoutThreshold, pwdHistoryLength, objectSid, msDS-Behavior-Version |
| Fine-grained password policies | `(objectClass=msDS-PasswordSettings)` | name, distinguishedName, msDS-PasswordSettingsPrecedence, msDS-PasswordReversibleEncryptionEnabled, msDS-PasswordComplexityEnabled, msDS-MinimumPasswordLength, msDS-PasswordHistoryLength, msDS-MinimumPasswordAge, msDS-MaximumPasswordAge, msDS-LockoutThreshold, msDS-LockoutDuration, msDS-LockoutObservationWindow, msDS-PSOAppliesTo |
| Group Policy Objects | `(objectClass=groupPolicyContainer)` | displayName, name, distinguishedName, gPCFileSysPath, flags |
| GPO links | `(gPLink=*)` | distinguishedName, gPLink, gPOptions |
| Privileged groups | bind by well-known SID (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Group Policy Creator Owners, Key Admins, Enterprise Key Admins, Protected Users) plus `(sAMAccountName=DnsAdmins)`; then one `memberOf:1.2.840.113556.1.4.1941:=` (nested membership) search per group | sAMAccountName of members |
| Entra Password Protection | `CN=Azure AD Password Protection,CN=Services,<configuration partition>` and `(&(objectClass=serviceConnectionPoint)(cn=AzureADPasswordProtection*))` | cn, existence and counts only |

Group membership is recorded as group names only. User first and last names
are derived by splitting the `name` attribute on the first space.

## Files read from SYSVOL

For each GPO, ADD reads one file from the `gPCFileSysPath` location on the
SYSVOL share:

```
MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

The `[System Access]`, `[Kerberos Policy]` and `[Registry Values]` sections are kept in full.
ADD also reads the Group Policy Preferences XML files (`Groups.xml`, `Services.xml`,
`ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml`) under each GPO and decrypts
any `cpassword` value with the key Microsoft published (MS14-025); the recovered account name and
password are reported in `GroupPolicyPasswords`. Nothing is written to SYSVOL.

## Secrets read by directory replication

ADD asks one domain controller to replicate the domain partition, the same
mechanism domain controllers use with each other. This requires the account
running ADD to hold the replication rights described in
[OPERATING.md](OPERATING.md). For every account object it receives:

| Data | What is kept |
| --- | --- |
| sAMAccountName, SID, enabled flag | written as-is |
| NT hash, LM hash | written as-is |
| NT and LM hash history | written as-is |
| supplementalCredentials | checked for a stored cleartext (reversibly encrypted) password; only whether one exists and its length are kept. The password itself is never written. The encryption types of the stored Kerberos keys are recorded; the keys themselves are never written. |

## Files written

ADD writes into a staging folder named `ActiveDirectoryDumper_DomainOutput` in the
current directory, zips its contents to `ActiveDirectoryDumper_<domain>_<yyyyMMdd-HHmmss>.zip`
(named for the domain and the run time so dumps do not collide), and deletes the
folder. The files below sit at the root of the zip.

| File | Contents |
| --- | --- |
| `hm_domainoutput.json` | The domain name, pull date, password policy, fine-grained policies, Group Policy security templates, posture, trusts, groups, users and computers, each user's and computer's current NT hash and hash history, and the per-account analysis. Every property is listed in [JSON-FIELDS.md](JSON-FIELDS.md). **Contains credential material.** |
| `hashes.pwdump` | One line per account: `logonname:RID:LMhash:NThash::: (status=Enabled\|Disabled)`. **Contains credential material.** |
| `historical_hashes.pwdump` | One line per historical hash: `logonname_N:RID:LMhash:NThash:::`. **Contains credential material.** |
| `hm_domainoutput.json` (2.1) | Also carries any Group Policy Preferences passwords recovered from SYSVOL (`GroupPolicyPasswords`, **plaintext credential material**) and the DCSync/AdminSDHolder access-control findings (`AccessControl`). |
| `collection_report.txt` | Human-readable run report: the success/failure of each collection step, record counts, data-point population, and a findings snapshot. No credential material. Also printed to the console at the end of the run. |

With `--dumponly`, only the two `.pwdump` files are written and the folder is
left unzipped.

## Reversible encryption analysis

The JSON reports, for the domain and for each account, whether reversible
encryption is configured and whether a cleartext password is actually stored.

| Source | Where it comes from | JSON property |
| --- | --- | --- |
| Domain password policy | `pwdProperties` bit `0x10` | `DomainReversibleEncryptionEnabled`, `PwdPropertiesFlags` |
| Fine-grained password policies | `msDS-PasswordReversibleEncryptionEnabled`, precedence and `msDS-PSOAppliesTo` | `PasswordSettingsObjects[]` |
| Group Policy | `ClearTextPassword` in each GPO's `GptTmpl.inf` plus where the GPO is linked | `GroupPolicyObjects[]` |
| Per-account flag | `userAccountControl` bit `0x80` | `Users[].ReversibleEncryption.AccountFlagSet` (also on computers) |
| Resultant policy | `msDS-ResultantPSO`, with a direct-match fallback when the DC does not return it | `Users[].ReversibleEncryption.ResultantPso` |
| What is actually stored | A cleartext package in `supplementalCredentials` | `Users[].ReversibleEncryption.ClearTextPasswordStored` |

Each user and computer carries a `ReversibleEncryption` object with
`EffectivelyEnabled`, `EffectiveSource` (`Account`, `FineGrainedPolicy`,
`DomainPolicy`, `None`) and a `Status`:

* `NotEnabled`: not enabled by any source and nothing stored.
* `EnabledNotStored`: enabled, but the password has not been changed since; it will be stored in cleartext at the next change.
* `Stored`: a cleartext password is stored in the directory.
* `StoredSettingDisabled`: a cleartext password is still stored although the setting has been turned off; it remains until the password is changed.
* `Unknown`: the hash dump did not cover this account.

A domain-wide roll-up, with counts and the names of accounts that have a stored
cleartext password, is in the top-level `ReversibleEncryption` object.

## Handling the output

The zip holds the password hashes of every account in the domain. Treat it as
you would the domain's credentials: keep it on encrypted storage, transfer it
only over encrypted channels to the party performing the analysis, limit who
can open it, and delete all copies when the engagement is complete.
