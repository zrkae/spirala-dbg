#include "disassembly.hpp"

#include <capstone/capstone.h>
#include <algorithm>

namespace disas {

void disas_print(void *file_addr, size_t size, uint64_t offset)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    count = cs_disasm(handle, (uint8_t*)file_addr, size, offset, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++)
            std::cout << std::format("{:x}  {} {}\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        cs_free(insn, count);
    } else {
        std::cout << "Couldn't dissassemble code!\n";
    }

    cs_close(&handle);
}

void disas_function(const elf::Elf& elf, std::string_view name)
{
    auto symbols = elf.symbols();
    auto it = std::find_if(symbols.begin(), symbols.end(), [&elf, &name](const auto& symbol){
        return symbol.str_name(elf) == name;
    });

    if (it == symbols.end()) {
        std::cout << std::format("Couldn't find symbol '{}' in the file. Maybe try 'symbols' or 'functions'?\n", name);
        return;
    }

    disas_print(elf.vaddr_to_fileptr((void*)it->value), it->size, it->value);
}

} // namespace disas
