# hm_domainoutput.json field reference (ADD 3.0)

Every property ADD writes, for the Hash Master 1000 developers. Properties marked **new** did not
exist in 2.3. Existing property names, casing and formats are unchanged so a 2.3 parser keeps
working; new timestamp fields use ISO 8601 UTC (`2026-10-21T03:15:42Z`), the sentinel `Never`,
or an empty string when the attribute is absent. Booleans are JSON booleans, nullable booleans may
be `null`.

## Top level

| Property | Type | Notes |
| --- | --- | --- |
| `Name` | string | Domain DNS name |
| `PullDate` | string | `MM/dd/yyyy`, local time (unchanged) |
| `PullTimeUtc` | string | **new** ISO 8601 |
| `CollectorVersion` | string | **new** ADD assembly version, e.g. `3.0.0.0` |
| `SchemaVersion` | string | **new** data-contract version, independent of the tool, e.g. `2.1`. Absent in 2.3 (treat as schema 1). Dispatch on the **major** component; `2.1` adds the optional `GroupPolicyPasswords` and `AccessControl` blocks over `2.0`. ADDHelper emits the same value for the same structure. |
| `UserCount` | int | |
| `MinPwdAge`, `MaxPwdAge` | double | days; `MaxPwdAge` 0 means never |
| `MinPasswordLength`, `PwdHistoryLength`, `LockoutThreshold` | int | |
| `LockoutDuration`, `LockoutObservationWindow` | double | minutes |
| `PwdProperties` | int | raw bitmask |
| `PwdPropertiesFlags` | string[] | **new** decoded names: `DOMAIN_PASSWORD_COMPLEX`, `DOMAIN_PASSWORD_NO_ANON_CHANGE`, `DOMAIN_PASSWORD_NO_CLEAR_CHANGE`, `DOMAIN_LOCKOUT_ADMINS`, `DOMAIN_PASSWORD_STORE_CLEARTEXT`, `DOMAIN_REFUSE_PASSWORD_CHANGE` |
| `DomainReversibleEncryptionEnabled` | bool | **new** |
| `DomainComplexityEnabled` | bool | **new** |
| `DomainSid` | string | **new** |
| `DomainDistinguishedName` | string | **new** |
| `PasswordSettingsObjects` | PasswordSettingsObject[] | **new** fine-grained password policies |
| `GroupPolicyObjects` | GroupPolicyObject[] | **new** |
| `SecurityPosture` | SecurityPosture | **new** |
| `GroupPolicyPasswords` | GppPassword[] | **new in 2.1** passwords recovered from Group Policy Preferences in SYSVOL (MS14-025) |
| `AccessControl` | AccessControlAudit | **new in 2.1** DCSync and AdminSDHolder access-control findings |
| `ReversibleEncryption` | ReversibleEncryptionSummary | **new** |
| `Summary` | PasswordSecuritySummary | **new** counts computed by ADD |
| `DomainTrusts` | object[] | `Trust`, `TrustDirection`, `TrustType`. Always an array; empty when the domain has no trusts |
| `Users` | User[] | |
| `Groups` | Group[] | `Cn`, `Description`, `GroupType`, `MemberCount`, `Members` (unchanged) |
| `Computers` | Computer[] | |

## User

Unchanged from 2.3: `Cn`, `Name`, `First`, `Last`, `SamAccountName`, `GroupMemberCount`,
`MemberOf`, `DisplayName`, `PrimaryGroupId`, `WhenCreated`, `WhenChanged`, `LastLogon`,
`UserAccountControl`, `RawUACValue`, `PwdLastSet`, `LockoutTime`, `ObjectSid`, `Description`,
`NTLMHash`, `HistoricalNTHashes`, `LogonName`, `ServicePrincipalNames`, `adminCount`,
`supportedEncryptionTypes`, `allowedToDelegateTo`. `adminCount` and `GroupMemberCount` remain JSON strings (`"1"`, `"5"`), not integers.

| Property | Type | Notes |
| --- | --- | --- |
| `DistinguishedName` | string | **new** |
| `LastLogonTimestamp` | string | **new** ISO. Replicated value, accurate to about 14 days. Prefer this over `LastLogon`, which is per-DC and often stale or `0`. |
| `PwdLastSetUtc` | string | **new** ISO, full precision; `PwdLastSet` stays `M/D/YYYY` |
| `AccountExpires` | string | **new** ISO or `Never` |
| `PasswordExpiryTime` | string | **new** DC-computed, PSO-aware. ISO expiry timestamp, which may be in the **past** when the password is already expired by age; `Never` when it never expires; `Expired` when the account must change at next logon (computed value 0); `` when unavailable. `PasswordExpired` is the authoritative current-state boolean. |
| `UserAccountControlComputed` | string[] | **new** flags from `msDS-User-Account-Control-Computed`; the live view, may include `ACCOUNT_LOCKED`, `PASSWORD_EXPIRED`, `USE_AES_KEYS` |
| `LockedOut` | bool | **new** |
| `PasswordExpired` | bool | **new** |
| `Info`, `Comment` | string | **new** free-text fields; scan with `Description` for passwords |
| `LegacyPasswordAttributes` | string[] | **new** any of `userPassword`, `unixUserPassword`, `msSFU30Password` present on the object. Values are not collected. |
| `PrivilegedGroups` | string[] | **new** effective membership (nested and primary group) in Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Group Policy Creator Owners, Key Admins, Enterprise Key Admins, DnsAdmins |
| `IsPrivileged` | bool | **new** `PrivilegedGroups` non-empty |
| `IsProtectedUser` | bool | **new** effective member of Protected Users |
| `IsKrbtgt` | bool | **new** `krbtgt` or RODC `krbtgt_*` |
| `Rid` | int | **new** last SID component; 500 Administrator, 501 Guest, 502 krbtgt |
| `EffectivePasswordPolicy` | EffectivePasswordPolicy | **new** |
| `StoredCredentials` | StoredCredentials | **new** |
| `ReversibleEncryption` | ReversibleEncryptionStatus | **new** |

### EffectivePasswordPolicy

The policy that governs the account: its resultant PSO, else the domain policy. GPOs below the
domain root never change a domain account's policy.

| Property | Type | Notes |
| --- | --- | --- |
| `Source` | string | `FineGrainedPolicy` or `DomainPolicy` |
| `PolicyName` | string | PSO name or domain name |
| `MinPasswordLength`, `PwdHistoryLength`, `LockoutThreshold` | int | |
| `ComplexityEnabled`, `ReversibleEncryptionEnabled` | bool | |
| `MinPwdAge`, `MaxPwdAge` | double | days; `MaxPwdAge` 0 means never |
| `LockoutDuration`, `LockoutObservationWindow` | double | minutes |

### StoredCredentials

From NTDS.dit during hash extraction. All false/empty with `NtdsChecked` false when the account
was not seen in replication.

| Property | Type | Notes |
| --- | --- | --- |
| `NtdsChecked` | bool | |
| `HasLmHash` | bool | LM hash other than the empty-password value is stored |
| `HasBlankNtHash` | bool | NT hash equals the empty-password hash |
| `NtHashHistoryCount` | int | |
| `HasKerberosKeys` | bool | |
| `KerberosKeyTypes` | string[] | current keys, e.g. `AES256_CTS_HMAC_SHA1_96`, `AES128_CTS_HMAC_SHA1_96`, `RC4_HMAC_NT`, `DES_CBC_MD5` |
| `HasAesKeys`, `HasDesKeys` | bool | |
| `NoAesKeys` | bool | keys exist but none is AES: the password predates AES being enabled |

### ReversibleEncryptionStatus

| Property | Type | Notes |
| --- | --- | --- |
| `AccountFlagSet` | bool | `userAccountControl` 0x80 |
| `DomainPolicyEnabled` | bool | |
| `ResultantPso` | string | PSO name or empty |
| `ResultantPsoSource` | string | `msDS-ResultantPSO`, `DirectMatch`, or empty |
| `PsoEnabled` | bool or null | null when no PSO applies |
| `EffectivelyEnabled` | bool | |
| `EffectiveSource` | string | `Account`, `FineGrainedPolicy`, `DomainPolicy`, `None` |
| `NtdsChecked` | bool | |
| `ClearTextPasswordStored` | bool | |
| `ClearTextPasswordLength` | int | |
| `Status` | string | `NotEnabled`, `EnabledNotStored`, `Stored`, `StoredSettingDisabled`, `Unknown` |

## Computer

Unchanged from 2.3: `Cn`, `SamAccountName`, `DNSHostName`, `OperatingSystem`,
`OperatingSystemServicePack`, `OperatingSystemVersion`, `LastLogon`, `UserAccountControl`,
`WhenCreated`, `SID`, `Description`, `NTLMHash`. Note `SID` was always empty in 2.3 because of
a bug; it is populated now.

| Property | Type | Notes |
| --- | --- | --- |
| `DistinguishedName` | string | **new** |
| `AccountType` | string | **new** `Computer`, `GroupManagedServiceAccount`, `ManagedServiceAccount`. Exclude managed service accounts from weak-password statistics; their passwords are random and rotated. |
| `IsDomainController` | bool | **new** |
| `LastLogonTimestamp` | string | **new** ISO |
| `PwdLastSetUtc` | string | **new** ISO. Member computers rotate every 30 days by default. (Named to match the user field; computers had no `PwdLastSet` in 2.3.) |
| `LapsLegacyExpiration`, `LapsWindowsExpiration` | string | **new** ISO when the computer is LAPS-managed; passwords are never read |
| `LapsManaged` | bool | **new** |
| `StoredCredentials` | StoredCredentials | **new** as for users |
| `ReversibleEncryption` | ReversibleEncryptionStatus | **new** as for users; `ResultantPso` is always empty |

## PasswordSettingsObject

| Property | Type | Notes |
| --- | --- | --- |
| `Name`, `DistinguishedName` | string | |
| `Precedence` | int | lower wins |
| `ReversibleEncryptionEnabled`, `ComplexityEnabled` | bool | |
| `MinPasswordLength`, `PwdHistoryLength`, `LockoutThreshold` | int | |
| `MinPwdAge`, `MaxPwdAge` | double | days |
| `LockoutDuration`, `LockoutObservationWindow` | double | minutes |
| `AppliesTo` | string[] | DNs of users and groups |

## GroupPolicyObject

| Property | Type | Notes |
| --- | --- | --- |
| `DisplayName`, `Guid`, `DistinguishedName`, `SysvolPath` | string | |
| `GptTmplFound` | bool | security template existed in SYSVOL |
| `SystemAccess` | object | `[System Access]` key/value strings: `MinimumPasswordLength`, `PasswordComplexity`, `PasswordHistorySize`, `MaximumPasswordAge`, `MinimumPasswordAge`, `LockoutBadCount`, `ResetLockoutCount`, `LockoutDuration`, `ClearTextPassword`, `RequireLogonToChangePassword`, `ForceLogoffWhenHourExpire`, `NewAdministratorName`, `NewGuestName`, `EnableAdminAccount`, `EnableGuestAccount`, `LSAAnonymousNameLookup` |
| `KerberosPolicy` | object | `MaxTicketAge`, `MaxRenewAge`, `MaxServiceAge`, `MaxClockSkew`, `TicketValidateClient` |
| `RegistryValues` | object | key is the registry path, value is `type,data` (4 = DWORD). Password-relevant paths: `...\Control\Lsa\NoLMHash`, `...\Control\Lsa\LmCompatibilityLevel`, `...\Control\Lsa\RestrictAnonymous`, `...\Control\Lsa\RestrictAnonymousSAM`, `...\Control\Lsa\EveryoneIncludesAnonymous`, `...\Control\Lsa\DisableDomainCreds`, `...\Winlogon\CachedLogonsCount`, `...\Services\Netlogon\Parameters\MaximumPasswordAge`, `...\Netlogon\Parameters\DisablePasswordChange`, `...\Netlogon\Parameters\RequireStrongKey`, `...\Winlogon\ScRemoveOption` |
| `ClearTextPassword` | int or null | from `SystemAccess` |
| `ReversibleEncryptionEnabled` | bool | `ClearTextPassword == 1` |
| `ComputerSettingsDisabled`, `UserSettingsDisabled` | bool | GPO flags |
| `Links` | GpoLink[] | `Container` (DN), `LinkOrder` (1 = highest precedence), `Enabled`, `Enforced` |
| `LinkedToDomainRoot` | bool | enabled link at the domain root |
| `Error` | string | SYSVOL read error, if any |

## SecurityPosture

| Property | Type | Notes |
| --- | --- | --- |
| `DomainFunctionalLevel` | string | `Windows2016` etc. |
| `DomainFunctionalLevelRaw` | int | `msDS-Behavior-Version` |
| `EntraPasswordProtectionContainerPresent` | bool | proxy registered in the forest |
| `EntraPasswordProtectionProxyCount` | int | SCPs under the container |
| `EntraPasswordProtectionDcAgentCount` | int | `AzureADPasswordProtection*` SCPs in the domain (heuristic) |
| `DomainControllerCount` | int | |
| `DomainAccountPolicySources` | PolicySetting[] | `[System Access]` and `[Kerberos Policy]` resolved across domain-root GPOs by link order. Explains where the domain policy values come from. |
| `DomainControllerSettings` | PolicySetting[] | all three sections resolved for the Domain Controllers OU (domain GPOs, then OU GPOs, then enforced domain GPOs; block inheritance honoured). This is where `NoLMHash`, `LmCompatibilityLevel`, cached logons and Netlogon settings as applied on DCs come from. |

`PolicySetting`: `Section`, `Name`, `Value`, `SourceGpo`.

## GppPassword (schema 2.1)

A password recovered from a Group Policy Preferences XML file in SYSVOL. The `cpassword` value is
encrypted with a key Microsoft published, so any authenticated user who can read SYSVOL can
recover it. **`Password` is plaintext credential material.**

| Property | Type | Notes |
| --- | --- | --- |
| `Gpo`, `GpoGuid` | string | owning GPO |
| `FileType` | string | Groups, Services, ScheduledTasks, DataSources, Printers or Drives |
| `FilePath` | string | SYSVOL path of the XML file |
| `UserName` | string | the account the password is for |
| `CPassword` | string | the stored ciphertext |
| `Password` | string | decrypted plaintext (the exposure) |
| `Decrypted` | bool | decryption succeeded |
| `Changed` | string | the preference `changed` timestamp, if present |

## AccessControlAudit (schema 2.1)

Access-control findings on the objects that govern domain security.

| Property | Type | Notes |
| --- | --- | --- |
| `DcSyncRights` | AclRight[] | principals granted directory-replication rights on the domain head |
| `AdminSdHolderRights` | AclRight[] | principals granted control rights on AdminSDHolder |
| `DomainAclRead`, `AdminSdHolderAclRead` | bool | whether each DACL was read |
| `NonDefaultDcSyncHolders` | int | DCSync holders that are not well-known defaults (the finding) |
| `NonDefaultAdminSdHolderHolders` | int | non-default AdminSDHolder control holders |

`AclRight`: `Object` ("Domain" or "AdminSDHolder"), `ObjectDn`, `Principal` (resolved name or SID),
`PrincipalSid`, `Right` (e.g. `DS-Replication-Get-Changes-All`, `GenericAll`, `WriteDacl`,
`AllExtendedRights`), `AccessType` (`Allow`/`Deny`), `IsDefault` (true for legitimate well-known
holders; **a false here with a replication or control right is the finding**).

## ReversibleEncryptionSummary

`DomainPolicyEnabled`, `PsoCount`, `PsosEnablingReversibleEncryption`,
`PsoNamesEnablingReversibleEncryption`, `GpoCount`, `GposEnablingReversibleEncryption`,
`GpoNamesEnablingReversibleEncryption`, `UsersWithAccountFlag`, `UsersEffectivelyEnabled`,
`UsersEnabledNotStored`, `UsersWithClearTextStored`, `UsersStoredSettingDisabled`,
`UsersWithClearTextStoredNames`, `ComputersWithAccountFlag`, `ComputersWithClearTextStored`,
`ComputersWithClearTextStoredNames`, `NtdsChecked`.

The two `*Names` arrays are capped at the first 100 entries to bound file size where reversible encryption is domain-wide; the `*Count` fields are authoritative totals and per-account `ReversibleEncryption.Status` is the complete list.

## PasswordSecuritySummary

Counts ADD prints on the console; Hash Master should recompute them from the per-account data
and may use these as a cross-check.

`Users`, `UsersEnabled`, `UsersPrivileged`, `UsersProtectedUsers`, `UsersUnderFineGrainedPolicy`,
`UsersPasswordNeverExpires`, `UsersPasswordNotRequired`, `UsersPasswordExpired`, `UsersLockedOut`,
`UsersKerberoastable` (enabled, has an SPN, not krbtgt), `UsersAsRepRoastable` (enabled,
`DONT_REQ_PREAUTH`), `UsersWithLmHash`, `UsersWithBlankNtHash`, `UsersNoAesKeys`,
`UsersWithLegacyPasswordAttributes`, `UsersSmartCardRequired`, `KrbtgtPasswordAgeDays`,
`Computers`, `ComputersDomainControllers`, `ComputersManagedServiceAccounts`,
`ComputersLapsManaged`, `ComputersPasswordOlderThan90Days`.

## Suggested Hash Master analyses enabled by 3.0

* Cracked password versus the policy that governed it (`EffectivePasswordPolicy`).
* Privileged accounts: crack rate, shared hashes between a person's admin and standard accounts, admin accounts without Protected Users.
* Stale accounts and stale passwords from `LastLogonTimestamp`, `PwdLastSetUtc`, `PasswordExpiryTime`, `MaxPwdAge` and `DONT_EXPIRE_PASSWORD`.
* krbtgt rotation (`KrbtgtPasswordAgeDays`, or `PwdLastSetUtc` where `IsKrbtgt`).
* Kerberoast and AS-REP roast exposure weighted by `NoAesKeys`, `IsPrivileged` and password age.
* LM hashes, blank passwords, `PASSWD_NOTREQD`, legacy password attributes.
* Reversible encryption exposure (`ReversibleEncryption`).
* Group Policy Preferences passwords (`GroupPolicyPasswords`): a standing exposure; report the account, GPO and whether the credential is still valid/reused.
* Dangerous access control (`AccessControl`): non-default DCSync rights and AdminSDHolder control are high-severity privilege-escalation/persistence findings.
* LAPS coverage and machine-password rotation on computers; exclude managed service accounts.
* Posture: `NoLMHash`, `LmCompatibilityLevel`, cached logons, Entra Password Protection, functional level, Kerberos ticket lifetimes.
