# ActiveDirectoryDumper

 <img width="1536" height="1024" alt="" src="https://github.com/user-attachments/assets/faa46f6f-5017-4601-8695-1384c121f1f0" />

 ## Data collection tool for use with [HashMaster1000](https://github.com/shellntel/HashMaster1000).
 
 Active Directory Dumper (ADD) gathers Active Directory information, including domain users, computers, groups, trusts, and policies, into a JSON file for auditing with HashMaster1000. It also extracts password hashes from `NTDS.dit` for password analysis. 

```
.\ActiveDirectoryDumper.exe --help
ActiveDirectoryDumper v2.0
Copyright c  2025

  -d, --dumponly    (Default: false) Do not perform collection, only dump hashes

  -v, --verbose     (Default: false)

  --help            Display this help screen.

  --version         Display version information.
```

# Installation
* The quickest way to get up and running is to grab the [latest release](https://github.com/shellntel/ActiveDirectoryDumper/releases).
* It relies on [VC_Redist](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#latest-supported-redistributable-version) being installed on the system on which the tool is run. If it's not installed, ADD will attempt to install it, which may trigger an AV/EDR alert; however, your mileage may vary. 
 
# Usage
Extract the contents of the ZIP file, then run the executable from the command line. By default, it will perform domain enumeration and a hashdump and save to a zip file `ActiveDirectoryDumper_DomainOutput.zip` in the same directory as the executable.<br>
The hashdump can also be performed by itself by passing the `--dumponly` flag.



