use std::{fs::File, io::Read};
use crate::logd;
use goblin::elf::Elf;

pub fn find_got_entry_for_symbol(path: &str, symbol: &str) -> Option<u64> {
    let mut file = File::open(path).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;

    let elf = Elf::parse(&buffer).ok()?;

    // Handle both REL and RELA
    for rel in elf.dynrels.iter().chain(elf.pltrelocs.iter()) {
        let sym_idx = rel.r_sym;
        if let Some(sym) = elf.dynsyms.get(sym_idx) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name).map(|r| r) {
                if name == symbol {
                    return Some(rel.r_offset);
                }
            }
        }
    }

    None
}

/// Reads /proc/self/maps to determine the load base address of the main executable
pub fn find_module_base(name: &str) -> Option<usize> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let f = File::open("/proc/self/maps").ok()?;
    let reader = BufReader::new(f);

    for line in reader.lines().flatten() {
        if line.contains(name) {
            logd!("[*] match for {} -> {}", name, line);
            let addr = line.split('-').next()?;
            return usize::from_str_radix(addr, 16).ok();
        }
    }

    logd!("[-] Could not find module base for {}", name);
    None
}
