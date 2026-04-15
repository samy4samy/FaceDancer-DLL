#![allow(non_snake_case)]

use goblin::pe::PE;
use rand::prelude::SliceRandom;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

fn random_word() -> &'static str {
    let words = ["Windows", "Excel", "Word", "OneDrive", "Azure", "SharePoint", "OneNote", "Edge", "Xbox", "Surface", "Bing", "Skype", "Dynamics", "Old", "Yammer"];
    words.choose(&mut rand::thread_rng()).unwrap_or(&"default")
}

pub fn GenerateExports(path: &str, custom_dll_name: Option<&str>, word_at_end: bool) {
    let path = Path::new(&path);
    let mut file = File::open(&path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    match PE::parse(&buffer) {
        Ok(pe) => {
            let exports = pe.exports;
            let dll_name = path.file_stem().unwrap().to_str().unwrap();
            let mut def_content = String::new();
            def_content.push_str(&format!("LIBRARY \"{}\"\n", dll_name));
            def_content.push_str("EXPORTS\n");

            // Use custom DLL name if provided, otherwise generate random word format
            let (export_dll_name, generated_word) = if let Some(custom_name) = custom_dll_name {
                (custom_name.to_string(), None)
            } else {
                let word = random_word();
                // Format based on word_at_end flag
                let formatted_name = if word_at_end {
                    format!("{}-{}", dll_name, word)
                } else {
                    format!("{}-{}", word, dll_name)
                };
                (formatted_name, Some(word))
            };

            for (i, export) in exports.iter().enumerate() {
                if let Some(name) = &export.name {
                    def_content.push_str(&format!("    {}={}.{} @{}\n", name, export_dll_name, name, i + 1));
                }
            }
            let def_path = format!("{}.def", dll_name);
            let mut def_file = File::create(&def_path).expect("Failed to create .def file");
            def_file.write_all(def_content.as_bytes()).expect("Failed to write to .def file");
            
            println!("[+] DLL Name: {}", dll_name);
            println!("[+] Renamed DLL Name: {}.dll", export_dll_name);
            if let Some(word) = generated_word {
                println!("[*] Random word used: {}", word);
                if word_at_end {
                    println!("[*] Word position: at end (e.g., {}-{})", dll_name, word);
                } else {
                    println!("[*] Word position: at front (e.g., {}-{})", word, dll_name);
                }
            }
            println!("[+] Number of Exports: {}", exports.len());
            println!("[+] DEF file generated at: {}", def_path);
            println!("[!] Important: Rename the original '{}.dll' to '{}.dll'", dll_name, export_dll_name);
        },
        Err(err) => eprintln!("Failed to parse PE file: {:?}", err),
    }
}
pub fn ListExports(path: &str) {
    let path = Path::new(path);
    let mut file = File::open(path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    match PE::parse(&buffer) {
        Ok(pe) => {
            let dll_name = path.file_stem().unwrap().to_str().unwrap();
            println!("DLL Name: {}", dll_name);
            println!("Exports:");

            for export in pe.exports.iter() {
                println!("- {}", export.name.unwrap_or("Unnamed"));
            }

            println!("Total Exports: {}", pe.exports.len());
        },
        Err(err) => eprintln!("Failed to parse PE file: {:?}", err),
    }
}
