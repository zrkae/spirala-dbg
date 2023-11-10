#pragma once
#include "../zep/src/zep.hpp"
#include "tracee.hpp"

namespace disas {
    
void disas_function(const Tracee& elf, std::string_view name);

}
