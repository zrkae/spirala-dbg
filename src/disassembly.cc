#include "disassembly.hpp"

#include <capstone/capstone.h>
#include <algorithm>

namespace disas {

void disas_print(const Tracee& tracee, void *file_addr, size_t size, uint64_t offset)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    uint64_t curr_rip = tracee.is_running() ? tracee.get_reg(reg::Register::rip) : 0;

    count = cs_disasm(handle, static_cast<uint8_t*>(file_addr), size, offset, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            if (j != count-1 && insn[j].address == curr_rip-1)
                std::cout << " ==>";
            std::cout << std::format("\t{:x}  {} {}\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        std::cout << "Couldn't dissassemble code!\n";
    }

    cs_close(&handle);
}

void disas_function(const Tracee& tracee, std::string_view name)
{
    auto symbols = tracee.elf.symbols;
    auto it = std::find_if(symbols.begin(), symbols.end(), [&tracee, &name](const auto& symbol){
        return symbol.str_name(tracee.elf) == name;
    });

    if (it == symbols.end()) {
        std::cout << std::format("Couldn't find symbol '{}' in the file. Maybe try 'symbols' or 'functions'?\n", name);
        return;
    }

    disas_print(tracee, tracee.elf.vaddr_to_fileptr(reinterpret_cast<void*>(it->value)), it->size, it->value + tracee.base_addr());
}

} // namespace disas
