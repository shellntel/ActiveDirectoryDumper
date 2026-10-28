# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
vulnerability reporting for this repository (**Security** tab, **Report a
vulnerability**). Include the version, how to reproduce the problem, and its
impact. We aim to acknowledge reports within five business days.

Problems in the data ADD produces, such as sensitive values that should not be
in the output, count as security reports.

## Supported versions

Only the latest release on the Releases page receives fixes.

## Verifying what you downloaded

Each release lists the SHA-256 checksum of its zip file. Verify it before
running the tool:

```powershell
Get-FileHash .\ActiveDirectoryDumper.zip -Algorithm SHA256
```

If the hash does not match, do not run the download. Report it to us through
the channel above.
