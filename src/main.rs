use elfkit::section::Section;
use elfkit::symbol::SymbolSectionIndex;
use elfkit::types::{SectionFlags, SectionType, SymbolType};
use elfkit::{elf::Elf, SectionContent, Strtab, Symbol};
use serde::Deserialize;
use std::io::{Read, Seek, SeekFrom};
use std::fs::File;

#[derive(Deserialize, Debug)]
struct MDFile {
    #[serde(rename = "addressMap")]
    addr_map: MDAddrMap,
}

#[derive(Deserialize, Debug)]
struct MDAddrMap {
    #[serde(rename = "methodDefinitions")]
    methods: Vec<MDMethod>,
    apis: Vec<MDApiMethod>
}

#[derive(Deserialize, Debug)]
struct MDMethod {
    #[serde(rename = "virtualAddress")]
    virtual_addr: String,
    name: String,
    #[serde(rename = "signature")]
    sig: String,
    #[serde(rename = "dotNetSignature")]
    dot_net_sig: String,
}

#[derive(Deserialize, Debug)]
struct MDApiMethod {
    #[serde(rename = "virtualAddress")]
    virtual_addr: String,
    name: String,
    #[serde(rename = "signature")]
    sig: String
}

fn main() {
    let mut orig_file = File::open("libil2cpp.so").unwrap();
    let mut elf = Elf::from_reader(&mut orig_file).unwrap();

    for section in &mut elf.sections {
        match section.header.shtype {
            // Workaround because the lib doesn't support aarch64 so we treat as raw
            SectionType::RELA => {
                orig_file
                    .seek(SeekFrom::Start(section.header.offset))
                    .unwrap();
                let mut bb = vec![0; section.header.size as usize];
                orig_file.read_exact(&mut bb).unwrap();
                section.content = SectionContent::Raw(bb);
            }
            _ => {
                section.from_reader(&orig_file, None, &elf.header).unwrap();
            }
        }
    }

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
            name:  method.sig.as_bytes().to_vec(),
            stype: SymbolType::FUNC,
            value: addr,
            shndx: SymbolSectionIndex::Section(10),
            ..Default::default()
        };
        sym_table.push(sym);
    }

    for method in md.addr_map.apis {
        let addr = u64::from_str_radix(&method.virtual_addr[2..], 16).unwrap();
        let sym = Symbol {
            name:  method.sig.as_bytes().to_vec(),
            stype: SymbolType::FUNC,
            value: addr,
            shndx: SymbolSectionIndex::Section(10),
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
    sym_table_sec.header.offset = 0x3180000;


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
    sym_table_sec.header.addralign = 1;
    str_table_sec.header.offset = 0x6180000;
    println!("Syncing sections... (This will take some time)");

    elf.sections.push(sym_table_sec);
    elf.sections.push(str_table_sec);
    elf.sync_all().unwrap();

    println!("Sections synced");

    let output_file = File::create("libil2cpp.sym.so").unwrap();
    elf.to_writer(output_file).unwrap();

    println!("Done!");
}
