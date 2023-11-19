#include "repl.hpp"

#include <cstdint>
#include <functional>
#include <set>
#include <algorithm>
#include <vector>
#include <sstream>

#include <linenoise.h>
#include <sys/user.h>

#include "disassembly.hpp"
#include "backtrace.hpp"

namespace repl {

namespace utils {

std::optional<std::string_view> 
nth_arg(std::string_view line, size_t n, std::string_view delim = " ")
{
    size_t lbound = 0, ubound = 0;
    for (size_t i = 0; i < n+1; i++) {
        if (ubound == std::string_view::npos)
            return {};

        lbound = ubound;
        ubound = line.find(delim, ubound + 1);
    }

    // uhhh... it works!! (I think)
    return line.substr(lbound + (n != 0), ubound - lbound - (n != 0 && ubound != std::string_view::npos));
}

} // namespace utils

static bool run; 

bool ask_confirmation(const char *msg = "Are you sure? [Y/N]: ")
{
    char *ans_ptr = nullptr;
    bool ret;

    for (;;) {
        char *ans_ptr = linenoise(msg);
        if (!ans_ptr)
            continue;
        std::string_view ans { ans_ptr };
        if (ans.starts_with('Y') || ans.starts_with('y')) {
            ret = true;
            break;
        } else if (ans.starts_with('N') || ans.starts_with('n')) {
            ret = false;
            break;
        }
        linenoiseFree(ans_ptr);
    }

    linenoiseFree(ans_ptr);
    return ret;
}

std::ostream& operator<<(std::ostream& stream, const user_regs_struct& regs)
{
    return stream << std::format("\
RIP {: <22x}\n\
RBP {: <22x} RSP {:x}\n\n\
RAX {: <22x} RDI {:x}\n\
RSI {: <22x} RDX {:x}\n\
RCX {: <22x} R8  {:x}\n\
R9  {: <22x} R10 {:x}\n\
R11 {: <22x} R12 {:x}\n\
R13 {: <22x} R14 {:x}\n\
R15 {: <22x}\n\
", 
            regs.rip,
            regs.rbp, regs.rbp,
            regs.rax, regs.rdi, 
            regs.rsi, regs.rdx,
            regs.rcx, regs.r8,
            regs.r9, regs.r10, 
            regs.r11, regs.r12, 
            regs.r13, regs.r14, 
            regs.r15);
}

struct Command {
    std::set<std::string_view> keywords;
    std::string_view description;
    std::function<void(Tracee&, std::string_view)> callback = nullptr;
};

const std::vector<Command> CommandTable = {
    { .keywords = { "help", "h", "?" }, .description = "show this menu",
        .callback = [](Tracee&, std::string_view) {
            // TODO: nice formatting
            std::cout << "Available commands:\n";
            for (const auto &cmd : CommandTable) {
            std::stringstream keywords;
                for (const auto &kw : cmd.keywords)
                    keywords << kw << " ";
                std::cout << std::format("{:<20} {}\n", keywords.str(), cmd.description);
            }
        }
    }, // doesn't need a function, this is just so it shows up
    { .keywords = { "exit" }, .description = "exit the debugger",
        .callback = [](Tracee&, std::string_view) {
            repl::run = false;
        }
    },
    { .keywords = { "run", "r" }, .description = "run currently loaded executable",
        .callback = [](Tracee& tracee, std::string_view) {
            if (tracee.is_running()) {
                std::cout << "The process is already running. This will restart it.\n";
                if (!ask_confirmation())
                    return;
            }

            tracee.spawn();
            tracee.cont();
        }
    },
    { .keywords = { "continue", "cont" }, .description = "continue execution",
        .callback = [](Tracee& tracee,  std::string_view) {
            std::cout << "Continuing..\n";
            tracee.cont();
        }
    },
    { .keywords = { "regs", }, .description = "print current register values",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (!tracee.is_running()) {
                std::cout << "No process is currently running, cannot get registers.\n";
                return;
            }
            std::cout << tracee.regs();
        }
    },
    { .keywords = { "reginfo", }, .description = "print all recognized registers",
        .callback = [](Tracee&,  std::string_view) {
            std::cout << "Recognized registers: ([user_regs_struct offset] name)\n";
            for (const auto &e : reg::RegInfo)
                std::cout << std::format("[0x{:x}] {}\n", e.offset, e.str);
        }
    },
    { .keywords = { "getreg", "gr" }, .description = "get register value",
        .callback = [](Tracee& tracee,  std::string_view line) {
            if (!tracee.is_running()) {
                std::cout << "No process is currently running, cannot get register.\n";
                return;
            }
            
            auto arg_reg = utils::nth_arg(line, 1);
            if (!arg_reg) {
                std::cout << "No register name supplied. Usage: getreg [REGISTER NAME]\n";
                return;
            }

            auto reg_enum = reg::from_string(arg_reg.value());
            if (!reg_enum) {
                std::cout << std::format("Invalid register name '{}'. Try the command 'reginfo'", arg_reg.value());
                return;
            }

            std::cout << std::format("{}: {:x}\n", arg_reg.value(), tracee.get_reg(reg_enum.value()));
        }
    },
    { .keywords = { "setreg", "sr" }, .description = "set register value",
        .callback = [](Tracee& tracee,  std::string_view line) {
            if (!tracee.is_running()) {
                std::cout << "No process is currently running, cannot get register.\n";
                return;
            }
            
            auto arg_reg = utils::nth_arg(line, 1);
            if (!arg_reg) {
                std::cout << "No register name supplied. Usage: setreg [REGISTER NAME] [DATA]\n";
                return;
            }

            auto reg_enum = reg::from_string(arg_reg.value());
            if (!reg_enum) {
                std::cout << std::format("Invalid register name '{}'. Try the command 'reginfo'\n", arg_reg.value());
                return;
            }

            auto arg_data = utils::nth_arg(line, 2);
            if (!arg_reg) {
                std::cout << "No data to set supplied. Usage: setreg [REGISTER NAME] [DATA]\n";
                return;
            }

            uint64_t data_int;
            auto result = std::from_chars(arg_data->data(), arg_data->data() + arg_data->size(), 
                                          data_int, 16);

            if (result.ec == std::errc::invalid_argument) {
                std::cout << std::format("Invalid data '{}' supplied.\n", arg_data.value());
                return;
            }

            tracee.set_reg(reg_enum.value(), data_int);
        }
    },
    { .keywords = { "kill" }, .description = "kill the tracee process",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (!tracee.is_running()) {
                std::cout << "No process currently running. Start it with 'run'\n";
                return;
            }
            tracee.kill();
        }
    },
    { .keywords = { "break", "b" }, .description = "break at specified address",
        .callback = [](Tracee& tracee,  std::string_view line) {
            auto arg_target = utils::nth_arg(line, 1);
            if (!arg_target.has_value()) {
                std::cout << "No address supplied. Usage: break [FUNCTION/0x(ADDRESS IN HEX)]\n";
                return;
            }

            if (arg_target->starts_with("0x")) {
                arg_target->remove_prefix(2);
            } else {
                auto symbols = tracee.elf.symbols;
                auto it = std::find_if(symbols.begin(), symbols.end(), 
                                       [&arg_target, &tracee](elf::Symbol& sym) { return sym.str_name(tracee.elf) == arg_target; });

                if (it != symbols.end()) {
                    // symbol found
                    tracee.breakpoint_add(it->value);
                    std::cout << std::format("Added breakpoint at '{}' = 0x{:x}.\n", *it->str_name(tracee.elf), it->value);
                    return;
                }

                // symbol not found, try to interpret as address
                // TODO: check if PIE and if so break on future shared library?
            }

            intptr_t addr;
            auto result = std::from_chars(arg_target->data(), arg_target->data() + arg_target->size(), 
                                          addr, 16);
            if (result.ec == std::errc::invalid_argument) {
                if (arg_target.value() == "_start") {
                    if (ask_confirmation("No '_start' symbol present, would you want to break at the entry point? [Y/N]: ")) {
                        addr = tracee.elf.header->entry;
                    } else {
                        return;
                    }
                } else {
                    std::cout << std::format("'{}' is neither a valid function name nor a valid address.\n", arg_target.value());
                    return;
                }
            }
            tracee.breakpoint_add(addr);
            std::cout << std::format("Added breakpoint at 0x{:x}.\n", addr);
        }
    },
    { .keywords = { "breaklist", "bl" }, .description = "show currently set breakpoints",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (tracee.breakpoints().empty()) {
                std::cout << "No breakpoints set.\n";
                return;
            }

            std::cout << "Currently set breakpoints:\n";
            int i = 0;
            for (const auto& [addr, bp] : tracee.breakpoints())  {
                i++;
                std::cout << std::format("[{}] address: 0x{:x}", i, addr);
                if (tracee.elf.is_pie() && tracee.is_running())
                    std::cout << std::format(" (0x{:x})", addr + tracee.base_addr());
                std::cout << std::format(", enabled: {}\n", bp.enabled());
            }
        }
    },
    { .keywords = { "breakclear", "bc" }, .description = "clear currently set breakpoints",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (tracee.breakpoints().empty()) {
                std::cout << "No breakpoints set.\n";
                return;
            }

            tracee.breakpoint_clear();
            std::cout << "Cleared all breakpoints\n";
        }
    },
    { .keywords = { "symbols", "sym" }, .description = "show symbols present in the executable (globals, functions)",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (!tracee.elf.has_symbols()) {
                std::cout << "No symbols present in the binary.\n";
                return;
            }

            for (const auto& sym : tracee.elf.symbols) {
                auto str_name = sym.str_name(tracee.elf);
                if (str_name && !str_name.value().empty())
                    std::cout << std::format("{:x}\t{}\n", sym.value, *str_name);
            }
        }
    },
    { .keywords = { "functions", "func" }, .description = "show exported function symbols",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (!tracee.elf.has_symbols()) {
                std::cout << "No symbols present in the binary (thus unable to locate functions).\n";
                return;
            }

            for (const auto& sym : tracee.elf.symbols) {
                if (sym.type() != elf::SymbolType::STT_FUNC)
                    continue;
                auto str_name = sym.str_name(tracee.elf);
                if (str_name && !str_name.value().empty())
                    std::cout << std::format("{:x}\t{}\n", sym.value, *str_name);
            }
        }
    },
    { .keywords = { "disassemble", "disas" }, .description = "disassemble symbol",
        .callback = [](Tracee& tracee,  std::string_view line) {
            auto symbol_name = utils::nth_arg(line, 1);
            if (!symbol_name) {
                std::cout << "No symbol name provided! format: disassemble [SYMBOL]\n";
                return;
            }

            disas::disas_function(tracee, symbol_name.value());
        }
    },
    { .keywords = { "backtrace", "bt" }, .description = "display backtrace of the stack",
        .callback = [](Tracee& tracee,  std::string_view) {
            if (!tracee.is_running()) {
                std::cout << "No process is currently running, cannot display backtrace.\n";
                return;
            }

            bt::backtrace_print(tracee);
        }
    },
};

// interpret user command
static void handle_command(Tracee& tracee, std::string_view line) 
{
    if (line.empty())
        return;

    std::string_view keyword = utils::nth_arg(line, 0).value();
    auto it = std::find_if(CommandTable.begin(), CommandTable.end(), 
                           [&](const Command& e) { return e.keywords.contains(keyword); });

    if (it == CommandTable.end()) {
        std::cout << std::format("Unknown keyword '{}'. Maybe try 'help'?\n", keyword);
        return;
    }

    it->callback(tracee, line);
}
// start a read-eval-print loop attached to the given tracee
void start(Tracee& tracee) 
{
    char *line;
    linenoiseHistorySetMaxLen(32);
    run = true;

    while (run)  {
        line = linenoise("[sprl] $ ");
        if (!line)
            continue;
        linenoiseHistoryAdd(line);

        repl::handle_command(tracee, line);

        linenoiseFree(line);
    }
}

} // namespace repl
