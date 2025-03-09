use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let hooks_path = Path::new("src/hooks");

    let reserved_keywords = [
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ];

    let mut init_calls = String::new();

    for entry in fs::read_dir(hooks_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|ext| ext == "rs").unwrap_or(false) {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                // skip mod.rs
                if stem == "mod" {
                    continue;
                }

                let ident = if reserved_keywords.contains(&stem) {
                    format!("r#{}", stem)
                } else {
                    stem.to_string()
                };

                init_calls.push_str(&format!("        crate::hooks::{}::init();\n", ident));
            }
        }
    }

    let output = format!(
        r#"
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init() {{
    INIT.call_once(|| unsafe {{
{init_calls}    }});
}}
"#,
        init_calls = init_calls
    );

    let out_path = Path::new(&out_dir).join("hooks_gen.rs");
    fs::write(&out_path, output).unwrap();

    println!("cargo:rerun-if-changed=src/hooks");
}