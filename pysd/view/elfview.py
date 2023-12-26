from capstone import CsInsn
from pysd.view.base import ViewBase
from pysd.parser.elf import Elf


class ElfView(ViewBase):

    parser = Elf

    def read_bytes(self, addr: int, length: int) -> bytes | None:
        start = addr
        end = addr + length
        for phdr in self.parsed.header.program_headers:
            if phdr.type != Elf.PhType.load:
                continue
            if not (phdr.vaddr <= start < phdr.vaddr + phdr.memsz):
                continue
            if not (phdr.vaddr <= end < phdr.vaddr + phdr.memsz):
                continue
            offset = start - phdr.vaddr
            return self.read_bytes_from_file(phdr.offset + offset, length)

    def get_section_include(self, addr: int) -> Elf.EndianElf.SectionHeader:
        for shdr in self.parsed.header.section_headers:
            if shdr.addr <= addr < shdr.addr + shdr.len_body:
                return shdr

    def disasm_entry(self):
        shdr = self.get_section_include(self.parsed.header.entry_point)
        self.disasm_push(shdr.addr, shdr.len_body)
    
    def disasm_step(self, code: CsInsn) -> bool:
        return True
