#include "backtrace.hpp"
#include <libunwind-ptrace.h>

namespace bt {
    
// not a huge fan of using libunwind to do all the hard work. 
// might replace with a custom implementation one day.
void print_backtrace(const Tracee& tracee)
{
    // create a libunwind addr space with ptrace accessor functions
    unw_addr_space_t unw_as = unw_create_addr_space(&_UPT_accessors, 0);

    void *unw_ctx = _UPT_create(tracee.pid());
    unw_cursor_t unw_cursor;
    if (unw_init_remote(&unw_cursor, unw_as, unw_ctx))
        throw std::runtime_error("libunwind: couldn't initialize remote cursor");

    do {
        unw_word_t pc, offset;
        if (unw_get_reg(&unw_cursor, UNW_REG_IP, &pc))
            throw std::runtime_error("libunwind: couldn't get program counter from remote cursor");

        char sym_buff[512];
        std::string_view function_name = unw_get_proc_name(&unw_cursor, sym_buff, sizeof(sym_buff), &offset) ?
                                         "???" :
                                         sym_buff;

        std::cout << std::format("0x{:<16x} in {} + {:x}\n", pc, function_name, offset);

    } while(unw_step(&unw_cursor) > 0);

    _UPT_destroy(unw_ctx);
}

}; // namespace bt
