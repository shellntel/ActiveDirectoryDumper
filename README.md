# ActiveDirectoryDumper

 Gathers AD Domain users, groups, and policy for auditing. Also performs hash extraction for password analysis.

```
.\SynerCommAuditTool.exe --help
SynerCommAuditTool 1.0.0.0
Copyright c  2025

  -d, --dumponly    (Default: false) Do not perform collection, only dump hashes

  -v, --verbose     (Default: false)

  --help            Display this help screen.

  --version         Display version information.
```

# Usage
Extract the contents from the zip file and run the executable from the commandline. By default, it will perform domain enumeration and a hashdump and save to a zip file `ActiveDirectoryDumper_DomainOutput.zip` in the same directory as the executable.<br>
The hashdump can also be performed by itself by passing the `--dumponly` flag.

