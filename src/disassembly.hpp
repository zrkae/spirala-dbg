#pragma once
#include "../zep/src/zep.hpp"

namespace disas {
    
void disas_function(const elf::Elf& elf, std::string_view name);

}
