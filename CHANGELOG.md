# Changelog

All notable changes to ActiveDirectoryDumper. Dates are release dates.

## 3.0.0 (2026-10-28)

### Added
* Group Policy Preferences password recovery (`GroupPolicyPasswords`): scans SYSVOL for `cpassword` values and decrypts them (MS14-025), reporting the account, GPO and plaintext. Schema 2.1.
* Access-control audit (`AccessControl`): principals holding directory-replication (DCSync) rights on the domain head and control rights on AdminSDHolder, with non-default holders flagged. Schema 2.1.
* `SchemaVersion` becomes `2.1` when these optional blocks are present; the major version is unchanged, so 2.0 consumers are unaffected.
* A collection report printed at the end of a run and saved as `collection_report.txt` in the bundle: per-step success/failure, record counts, user data-point population and a findings snapshot. Hash-collection failure is now non-fatal, so the enumeration data and the report are still produced.
* Reversible encryption analysis: domain policy, fine-grained password policies, Group Policy templates in SYSVOL, per-account flags, resultant policy per user, and whether a cleartext password is actually stored, combined into a per-account status and a domain summary in `hm_domainoutput.json`. See [docs/DATA-COLLECTED.md](docs/DATA-COLLECTED.md).
* `PwdPropertiesFlags` decoding of the domain password policy.
* `build.cmd` and VS Code build tasks; [BUILDING.md](BUILDING.md).
* License, security policy, operating guide, data-collected reference and release checklist.
* Per-user effective password policy (resultant PSO or domain policy) with the DC-computed password expiry and live lockout/expired state.
* Replicated `lastLogonTimestamp`, `accountExpires`, full-precision `PwdLastSetUtc` on users; `pwdLastSet` and `lastLogonTimestamp` on computers.
* Effective (nested) membership of the well-known privileged groups and Protected Users per user, resolved by SID.
* Stored-credential facts from NTDS.dit: LM hash present, blank NT hash, history depth, Kerberos key encryption types and AES/DES presence.
* Presence of legacy password attributes (`userPassword`, `unixUserPassword`, `msSFU30Password`), `info` and `comment` fields.
* LAPS coverage and managed-service-account classification on computers.
* Full Group Policy security templates (System Access, Kerberos Policy, Registry Values) with link order, plus resolved settings for the domain root and the Domain Controllers OU.
* Security posture: domain functional level, Entra Password Protection registration, domain controller count.
* `Summary` counts and `docs/JSON-FIELDS.md` field reference for Hash Master 1000.

### Fixed
* Historical NTLM hashes could be missing on large domains: ADD replicated the whole domain twice (once for current hashes, once for history), and a failed or incomplete second DCSync pass left the history file empty. ADD now replicates once and reuses the result, which also halves replication load.
* `--dumponly` crashed because the extractor assumed enumeration had run.
* Computer `SID` was always empty (the wrong attribute name was requested).
* `DomainTrusts` serialized as `null` when a domain had no trusts; it is now always an array.
* Computer password-change time renamed `PwdLastSet` to `PwdLastSetUtc` for a consistent ISO format across users and computers.
* Added top-level `SchemaVersion` (data-contract version, independent of the collector tool).
* Capped the reversible-encryption summary name arrays at 100 entries; counts and per-account status remain complete.
* `ParseUacFlags` no longer throws on a non-numeric userAccountControl value.

### Changed
* Output zip is now named `ActiveDirectoryDumper_<domain>_<yyyyMMdd-HHmmss>.zip` instead of a fixed `ActiveDirectoryDumper_DomainOutput.zip`, so dumps from different domains or runs no longer collide. The files inside the zip are unchanged.
* Assembly version now matches the release version.

## 2.3 (2026-02-10)
* Minor bug fixes and output cleanup.

## 2.2 (2026-02-04)
* Added computer accounts to the JSON file.
* Removed CSV generation.
* Verbosity cleanup and other refactors.

## 2.1 (2026-01-22)
* Bug fixes and improvements.

## 2.0 (2025-12-29)
* Renamed project and solution from SynerCommAuditTool. Finalized JSON output for Hash Master 1000.

## 1.1 (2025-12-16)
* Added JSON output file containing domain data. Added `(status=Enabled|Disabled)` to the hash dump.

## 1.0 (2025-03-17)
* Initial release as SynerCommAuditTool.
