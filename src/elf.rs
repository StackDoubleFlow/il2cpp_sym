//! Utilities for elf modification

use anyhow::{Context, Result};
use elfkit::elf::Elf;
use elfkit::section::Section;
use elfkit::types::SectionType;
use std::cmp;
use std::io::{Read, Seek};

pub fn load_all_sections<R>(mut io: R, elf: &mut Elf) -> Result<()>
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
    Ok(())
}

pub fn append_section(elf: &mut Elf, section: Section) -> Result<()> {
    append_section_with_padding(elf, section, 0)
}

pub fn append_section_with_padding(
    elf: &mut Elf,
    mut section: Section,
    padding: u64,
) -> Result<()> {
    if elf.sections.is_empty() {
        elf.sections.push(section);
        return Ok(());
    }

    let last_section = elf.sections.last().context("Elf sections empty")?;
    let last_section_size = cmp::max(
        last_section.content.size(&elf.header) as u64,
        last_section.header.size,
    );
    section.header.offset = last_section.header.offset + last_section_size + padding;
    elf.sections.push(section);
    Ok(())
}
