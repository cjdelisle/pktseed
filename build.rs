// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::Path;
use std::fs;
use std::env;

fn languages() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut languages = vec![];
    let mut out = vec![];

    for entry in walkdir::WalkDir::new("./languages")
        .into_iter()
        .filter_map(|me| if let Ok(e) = me { Some(e) } else { None })
    {
        //println!("e: {}", entry.path())
        let path = entry.path();
        let md = path.metadata().expect("could not get path metadata");
        if !md.is_file() { continue; }
        if let Some(ext) = path.extension() {
            if ext != "txt" {
                continue;
            }
        } else {
            continue;
        }
        println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
        let name = path.file_stem().unwrap().to_str().unwrap();

        if env::var(format!("CARGO_FEATURE_LANG_{}", name.to_uppercase())).is_err() {
            continue;
        }

        let mut word_for_num = vec![
            format!("const WORDS_{}: [&'static str; 2048] = [", name),
        ];
        let mut num_for_word = vec![
            format!("fn num_for_word_{}(word: &str) -> Option<u16> {{", name)
        ];
        num_for_word.push("\tmatch word {".to_owned());

        let content = fs::read_to_string(path).unwrap();
        for (l, i) in content.lines().zip(0..) {
            if l.is_empty() { continue; }
            word_for_num.push(format!("\t\"{}\",", l));
            num_for_word.push(format!("\t\t\"{}\" => Some({}),", l, i));
        }

        num_for_word.push("\t\t_ => None\n\t}\n}".to_owned());
        word_for_num.push("];".to_owned());
        out.extend_from_slice(&num_for_word[..]);
        out.extend_from_slice(&word_for_num[..]);
        out.push(format!("const LANGUAGE_{}: Language = Language{{", name));
        out.push(format!("\tname: \"{}\",", name));
        out.push(format!("\twords: WORDS_{},", name));
        out.push(format!("\tnum_for_word: num_for_word_{},", name));
        out.push(format!("}};"));
        languages.push(format!("\t&LANGUAGE_{},", name));
    }

    let mut languages_x = vec![format!("pub const LANGUAGES: [&'static Language; {}] = [", languages.len())];
    languages_x.extend_from_slice(&languages[..]);
    languages_x.push("];".to_owned());
    out.extend_from_slice(&languages_x[..]);

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("languages.incl.rs");
    fs::write(&dest, out.join("\n")).unwrap();
}

#[cfg(feature = "generate-capi")]
fn bindgen() {
    println!("cargo:rerun-if-changed=./src/capi.rs");
    println!("Generating capi");
    let mut conf = cbindgen::Config::default();
    conf.language = cbindgen::Language::C;
    conf.autogen_warning =
        Some("// This file is generated from src/capi.rs using cbindgen".to_owned());
    conf.style = cbindgen::Style::Type;
    conf.include_guard = Some("PKTSEED_H".to_owned());
    cbindgen::Builder::new()
        .with_src("./src/capi.rs")
        .with_config(conf)
        .generate()
        .expect("Unable to generate capi")
        .write_to_file("pktseed.h");
    println!("Generating capi done");
}
#[cfg(not(feature = "generate-capi"))]
fn bindgen() {
    println!("Skipping capi");
}

fn main() {
    languages();
    bindgen();
}