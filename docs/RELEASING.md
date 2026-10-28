# Release checklist

1. Update the version in `ActiveDirectoryDumper\Properties\AssemblyInfo.cs` (`AssemblyVersion` and `AssemblyFileVersion`). The `--help` and `--version` output print it.
2. Move the **Unreleased** entries in `CHANGELOG.md` under a new heading with the version and date.
3. Build a clean release: `build.cmd Release x64` from a fresh clone, so no stale `packages` or `obj` content is included.
4. Smoke test the exe with `--help` and, in a lab domain, a full run. Confirm the zip contains the three output files and that `hm_domainoutput.json` loads in Hash Master 1000.
5. Package `ActiveDirectoryDumper.zip` with a top-level `ActiveDirectoryDumper\` folder containing exactly:
   * `ActiveDirectoryDumper.exe`
   * `ActiveDirectoryDumper.exe.config`
   * `DSInternals.Replication.Interop.dll`
   * `Redist\vc_redist.x64.exe`
   Leave out the `.pdb` and `.xml` files.
   Build the zip with `[System.IO.Compression.ZipFile]::CreateFromDirectory` (forward-slash paths), not PowerShell 5.1 `Compress-Archive`, which writes backslash separators that Windows `tar` mishandles on extraction.
6. If a code-signing certificate is available, sign the exe before zipping (`signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a ActiveDirectoryDumper.exe`). A signed binary is the strongest answer to "how do I know this is yours".
7. Compute the checksum: `Get-FileHash .\ActiveDirectoryDumper.zip -Algorithm SHA256`.
8. Tag the commit (`git tag -a vX.Y -m "ActiveDirectoryDumper vX.Y"`, `git push --tags`).
9. Create the GitHub release from the tag. Paste the changelog entry and the SHA-256 line into the release notes and attach the zip.
10. Download the published zip on another machine and confirm the hash matches.
