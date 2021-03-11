use elfkit::symbol::SymbolSectionIndex;
use elfkit::types::{SectionFlags, SectionType, SymbolType};
use elfkit::{elf::Elf, SectionContent, Strtab, Symbol};
use elfkit::{section::Section, types::SymbolBind};
use goblin::elf32::section_header;
use serde::Deserialize;
use std::cmp;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Deserialize, Debug)]
struct MDFile {
    #[serde(rename = "addressMap")]
    addr_map: MDAddrMap,
}

#[derive(Deserialize, Debug)]
struct MDAddrMap {
    #[serde(rename = "methodDefinitions")]
    methods: Vec<MDMethod>,
    apis: Vec<MDApiMethod>,
    #[serde(rename = "methodInvokers")]
    method_invokers: Vec<MDApiMethod>,
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
    sig: String,
}

fn elf_load_all_sections<R>(mut io: R, elf: &mut Elf)
where
    R: Read + Seek,
{
    for section in &mut elf.sections {
        let sec_type = match section.header.shtype.clone() {
            // Workaround because the lib doesn't support aarch64 so we treat as raw
            SectionType::RELA => SectionType::NULL,
            s => s,
        };
        section.header.shtype = sec_type;
        section.from_reader(&mut io, None, &elf.header).unwrap();
    }
}

fn read_il2cpp_symbols() -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut file = File::open("libil2cpp.dummy.so").unwrap();
    let mut elf = Elf::from_reader(&mut file).unwrap();
    elf_load_all_sections(file, &mut elf);

    let strtab_sec = elf
        .sections
        .iter()
        .find(|s| String::from_utf8_lossy(&s.name) == ".strtab")
        .expect("Cound not find string table in dummy");
    let strtab = match &strtab_sec.content {
        SectionContent::Strtab(strtab) => strtab,
        _ => panic!("The string table in the dummy was not a string table"),
    };

    let symtab_sec = elf
        .sections
        .iter()
        .find(|s| String::from_utf8_lossy(&s.name) == ".symtab")
        .expect("Cound not find symbol table in dummy");
    let symtab = match &symtab_sec.content {
        SectionContent::Symbols(symtab) => symtab,
        _ => panic!("The symbol table in the dummy was not a symbol table"),
    };

    for symbol in symtab {
        if symbol.shndx == SymbolSectionIndex::Section(10)
            && symbol.bind == SymbolBind::LOCAL
            && symbol.stype == SymbolType::FUNC
        {
            let mut sym = symbol.clone();
            sym.name = strtab.get(symbol._name as usize);
            symbols.push(sym);
        }
    }

    symbols
}

fn elf_append_section(elf: &mut Elf, mut section: Section) {
    if elf.sections.is_empty() {
        elf.sections.push(section);
        return;
    }

    let last_section = elf.sections.last().unwrap();
    let last_section_size = cmp::max(
        last_section.content.size(&elf.header) as u64,
        last_section.header.size,
    );
    // Give an extra 500 bytes of space just in case (The string table behind us is going to grow)
    section.header.offset = last_section.header.offset + last_section_size + 500;
    elf.sections.push(section);
}

fn main() {
    let mut orig_file = File::open("libil2cpp.so").unwrap();
    let mut elf = Elf::from_reader(&mut orig_file).unwrap();

    elf_load_all_sections(orig_file, &mut elf);

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

    // sym_table.append(&mut read_il2cpp_symbols());

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

    elf_append_section(&mut elf, sym_table_sec);
    elf_append_section(&mut elf, str_table_sec);
    elf.sync_all().unwrap();

    println!("Writing modified ELF");

    let output_file = File::create("libil2cpp.sym.so").unwrap();
    elf.to_writer(output_file).unwrap();

    println!("Done!");
}
