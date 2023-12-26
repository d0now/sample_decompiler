from typing import Tuple, Dict, Any
from abc import ABC, abstractmethod
from pathlib import Path
from io import RawIOBase
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from kaitaistruct import KaitaiStruct
from loguru import logger


class ViewBase(ABC):

    parser = KaitaiStruct

    @classmethod
    def from_file(cls, file: Path):
        f = file.open('rb')
        obj = cls.parser.from_io(f)
        return cls(f, obj)

    def __init__(self, io: RawIOBase, parsed: KaitaiStruct):
        self.io = io
        self.parsed = parsed
        self.dq: Tuple[int, int] = []
        self.dd: Dict[int, Any] = {}
        self.disassemble()
    
    def read_bytes_from_file(self, offset: int, length: int) -> bytes | None:
        self.io.seek(offset, 0)
        return self.io.read(length)

    @abstractmethod
    def read_bytes(self, addr: int, length: int) -> bytes | None:
        ...

    def disasm_push(self, addr: int, length: int):
        self.dq.append((addr, length))

    def disasm_pop(self) -> Tuple[int, int] | None:
        if self.dq:
            return self.dq.pop(0)
    
    @abstractmethod
    def disasm_entry(self):
        ...

    @abstractmethod
    def disasm_step(self, code: CsInsn) -> bool:
        ...

    def disassemble(self, pop=-1):

        # TODO: add support for 64-bit
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        self.disasm_entry()

        logger.debug(f"disasm start with initial queue count: {len(self.dq)}")

        while pop:

            popd = self.disasm_pop()
            if not popd:
                break
            else:
                addr, length = popd

            target = self.read_bytes(addr, length)
            if not target:
                raise RuntimeError
            else:
                logger.debug(f"disasm target: 0x{addr:x} (~{length:x})")

            for code in md.disasm(target, addr):
                logger.trace(f"STEP: {code.address:08x}  {code.mnemonic} {code.op_str}")
                if self.disasm_step(code):
                    self.dd[code.address] = (code.mnemonic, code.op_str)

            if pop > 0:
                pop -= 1

        logger.debug("disasm done.")