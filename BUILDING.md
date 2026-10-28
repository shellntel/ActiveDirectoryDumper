# Building ActiveDirectoryDumper on Windows with VS Code

ADD is a .NET Framework 4.8 console application using the legacy `packages.config` project
format, with [Costura.Fody](https://github.com/Fody/Costura) merging the managed dependencies into
the exe at build time. It builds with MSBuild from Visual Studio 2022 or the free
Visual Studio 2022 Build Tools; the `dotnet` CLI alone cannot build it.

## 1. Prerequisites

| Tool | Why | Install |
| --- | --- | --- |
| Git | clone the repo | `winget install Git.Git` |
| Visual Studio 2022 Build Tools with the **.NET desktop build tools** workload | MSBuild, Roslyn C# compiler, .NET Framework 4.8 targeting pack, NuGet targets | see below |
| VS Code | editor and build task runner | `winget install Microsoft.VisualStudioCode` |
| VS Code **C#** extension (`ms-dotnettools.csharp`) | IntelliSense and error squiggles for the legacy project | `code --install-extension ms-dotnettools.csharp` |

Install the Build Tools from an elevated PowerShell:

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --norestart --wait --add Microsoft.VisualStudio.Workload.ManagedDesktopBuildTools --add Microsoft.Net.Component.4.8.TargetingPack --add Microsoft.Net.Component.4.8.SDK"
```

If Build Tools (or full Visual Studio) is already installed, add the components instead of reinstalling.
Replace `C:\BuildTools` with your install path (`vswhere -all -products *` prints it):

```powershell
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe" modify --installPath C:\BuildTools --add Microsoft.Net.Component.4.8.TargetingPack --add Microsoft.Net.Component.4.8.SDK --add Microsoft.VisualStudio.Component.NuGet.BuildTools --quiet --norestart
```

Or use the GUI: Start menu, **Visual Studio Installer**, **Modify**, tick **.NET desktop build tools**
(Build Tools) or **.NET desktop development** (full Visual Studio), then **Modify**.

The C# Dev Kit extension is not required and does not understand `packages.config` projects well;
the plain C# extension is enough. NuGet (`nuget.exe`) is downloaded automatically by `build.cmd`
into `.tools\` on first use, so it does not need to be installed.

## 2. Get the source

```powershell
git clone https://github.com/shellntel/ActiveDirectoryDumper.git
cd ActiveDirectoryDumper
```

## 3. Build from VS Code

1. Run `code .` in the repository folder (or **File, Open Folder**).
2. Press **Ctrl+Shift+B**. The default task **Build ADD (Release x64)** runs.
3. Watch the terminal panel. The last line names the output exe. Compiler errors appear in the
   **Problems** view and are clickable.

Other tasks (**Terminal, Run Task...**):

* **Build ADD (Debug x64)** produces a non-optimized build with full symbols in `bin\x64\Debug`.
* **Clean ADD** removes `bin` and `obj`.

The tasks are defined in `.vscode/tasks.json` and simply call `build.cmd`, so the editor and the
command line build the same way.

## 4. Build from the command line

```cmd
build.cmd                 :: Release x64 (what releases ship)
build.cmd Debug x64
build.cmd Release AnyCPU
```

`build.cmd` locates MSBuild with `vswhere`, downloads `nuget.exe` if needed, runs
`nuget restore ActiveDirectoryDumper.sln`, then runs MSBuild. Nothing needs to be on `PATH`.

## 5. Output

`ActiveDirectoryDumper\bin\x64\Release\` contains:

* `ActiveDirectoryDumper.exe` (about 1.5 MB, managed dependencies embedded by Costura)
* `ActiveDirectoryDumper.exe.config`
* `DSInternals.Replication.Interop.dll` (native, deliberately not embedded; must ship beside the exe)
* `Redist\vc_redist.x64.exe` (installed by ADD on hosts missing the VC++ runtime)
* `*.xml` IntelliSense files that can be ignored

Ship the exe, its `.config`, the Interop DLL and the `Redist` folder together, as the existing
GitHub releases do. Use the x64 build: the Interop DLL is x64 only.

## 6. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `vswhere.exe not found` | Build Tools or Visual Studio 2022 is not installed. |
| `MSBuild.exe not found` | The install lacks the MSBuild component; add the **.NET desktop build tools** workload. |
| `MSB3644: The reference assemblies for .NETFramework,Version=v4.8 were not found` | Add **Microsoft.Net.Component.4.8.TargetingPack** (section 1). |
| `This project references NuGet package(s) that are missing` or Fody errors | Restore did not run. Run `build.cmd` again and check the restore output, or run `.tools\nuget.exe restore ActiveDirectoryDumper.sln -Verbosity normal`. |
| `nuget.exe` download fails | The machine cannot reach `dist.nuget.org`. Download it manually to `.tools\nuget.exe`, or set `HTTPS_PROXY`. |
| C# extension shows errors the build does not | Reload the window after the first successful build so it picks up `packages\`. |
| Running the exe says `vcruntime140.dll` missing | ADD installs `Redist\vc_redist.x64.exe` automatically; install it manually if that fails. |
