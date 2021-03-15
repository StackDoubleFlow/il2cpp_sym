#![deny(warnings, rust_2018_idioms)]

mod elf;
mod inspector_metadata;

use elfkit::section::Section;
use elfkit::symbol::SymbolSectionIndex;
use elfkit::types::{SectionFlags, SectionType, SymbolType};
use elfkit::{elf::Elf, SectionContent, Strtab, Symbol};
use inspector_metadata::MDFile;
use std::fs::File;
use std::io::Read;

fn main() {
    let mut orig_file = File::open("libil2cpp.so").unwrap();
    let mut elf = Elf::from_reader(&mut orig_file).unwrap();

    elf::load_all_sections(orig_file, &mut elf);

    println!("Finished reading ELF");

    let mut sym_table = Vec::new();

    let mut md_str = String::new();
    File::open("metadata.json")
        .unwrap()
        .read_to_string(&mut md_str)
        .unwrap();
    let md: MDFile = serde_json::from_str(&md_str).unwrap();

    for method in md.addr_map.methods {
        let addr = u64::from_str_radix(&method.virtual_addr[2..], 16).unwrap();
        let sym = Symbol {
            name: method.sig.as_bytes().to_vec(),
            stype: SymbolType::FUNC,
            value: addr,
            shndx: SymbolSectionIndex::Section(11),
            ..Default::default()
        };
        sym_table.push(sym);
    }

    for method in md.addr_map.apis {
        let addr = u64::from_str_radix(&method.virtual_addr[2..], 16).unwrap();
        let sym = Symbol {
            name: method.sig.as_bytes().to_vec(),
            stype: SymbolType::FUNC,
            value: addr,
            shndx: SymbolSectionIndex::Section(11),
            ..Default::default()
        };
        sym_table.push(sym);
    }

    for method in md.addr_map.method_invokers {
        let addr = u64::from_str_radix(&method.virtual_addr[2..], 16).unwrap();
        let sym = Symbol {
            name: method.sig.as_bytes().to_vec(),
            stype: SymbolType::FUNC,
            value: addr,
            shndx: SymbolSectionIndex::Section(11),
            ..Default::default()
        };
        sym_table.push(sym);
    }

    let sym_table_len = sym_table.len();

    println!("Finished reading metadata: {} methods found", sym_table_len);
    println!("Creating symbol table");

    let sym_table_cont = SectionContent::Symbols(sym_table);
    let mut sym_table_sec = Section::new(
        ".symtab".as_bytes().to_vec(),
        SectionType::SYMTAB,
        SectionFlags::empty(),
        sym_table_cont,
        elf.sections.len() as u32 + 1, // The string table comes next
        sym_table_len as u32,
    );
    sym_table_sec.header.addralign = 8;

    println!("Creating string table");

    let str_table = Strtab::default();
    let str_table_cont = SectionContent::Strtab(str_table);
    let mut str_table_sec = Section::new(
        ".strtab".as_bytes().to_vec(),
        SectionType::STRTAB,
        SectionFlags::empty(),
        str_table_cont,
        0,
        0,
    );
    str_table_sec.header.addralign = 1;

    println!("Syncing sections");

    // Give an extra 500 bytes of space just in case (The string table behind us is going to grow)
    elf::append_section_with_padding(&mut elf, sym_table_sec, 500);
    elf::append_section(&mut elf, str_table_sec);
    elf.sync_all().unwrap();

    println!("Writing modified ELF");

    let output_file = File::create("libil2cpp.sym.so").unwrap();
    elf.to_writer(output_file).unwrap();

    println!("Done!");
}
