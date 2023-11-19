#include "tracee.hpp"
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>

#include "../zep/src/zep.hpp"

constexpr int WORD_SIZE = 8;

namespace reg {

uint64_t to_offset(Register reg)
{
    return RegInfo[static_cast<size_t>(reg)].offset;
}

std::string_view to_str(Register reg)
{
    return RegInfo[static_cast<size_t>(reg)].str;
}

std::optional<Register> from_string(std::string_view str)
{
    auto it = std::find_if(RegInfo.begin(), RegInfo.end(), [&](auto e) {
        return e.str == str;
    });

    if (it != RegInfo.end())
        return static_cast<Register>(it - RegInfo.begin());

    return {};
}

std::optional<Register> from_offset(uint64_t offset)
{
    auto it = std::find_if(RegInfo.begin(), RegInfo.end(), [&](auto e) {
        return e.offset == offset;
    });

    if (it != RegInfo.end())
        return static_cast<Register>(it - RegInfo.begin());

    return {};
}

} // namespace reg

Tracee::Tracee(const std::string& path) 
    :elf(path), m_path(path)
{
    std::cout << std::format("Loaded executable '{}'!\n", path);
}

void Tracee::spawn() 
{
    if (m_pid)
        kill();

    int frk = fork();
    if (frk < 0)
        throw std::runtime_error(std::format("Failed to fork: {}", strerror(errno)));

    if (frk == 0) { // child process
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            throw std::runtime_error(std::format("Failed to PTRACE_TRACEME: {}", strerror(errno)));
        personality(ADDR_NO_RANDOMIZE);
        execl(m_path.c_str(), m_path.c_str(), nullptr);
        // exec never returns when successfull
        throw std::runtime_error(std::format("Failed to exec: {}", strerror(errno)));
    }
    // parent process
    m_pid = frk;
    waitpid(m_pid, &m_wstatus, 0);
    // ensure that if the tracer process dies we will take the tracee with us
    if (ptrace(PTRACE_SETOPTIONS, m_pid, 0, PTRACE_O_EXITKILL) < 0) {
        kill();
        throw std::runtime_error(std::format("Failed to set PTRACE_O_EXITKILL: {}", strerror(errno)));
    }

    if (elf.is_pie()) {
        std::ifstream maps_file(std::format("/proc/{}/maps", frk));
        std::streambuf *rbuff = maps_file.rdbuf();

        char buff[16];
        rbuff->sgetn(buff, sizeof(buff));
        buff[sizeof(buff) - 1] = 0;

        auto result = std::from_chars(buff, buff + sizeof(buff), m_base_addr, 16);
        if (result.ec == std::errc::invalid_argument)
            throw std::runtime_error("failed to retrieve base address.");
    }

    for (auto& [_, bp] : m_breakpoints)
        bp.reset();

    std::cout << std::format("[{}] Process spawned.\n", m_pid);
}

void Tracee::kill() 
{
    if (!m_pid)
        return;
    // kinda awkward, maybe I'll change the function name later
    if (::kill(m_pid, SIGKILL) < 0)
        throw std::runtime_error(std::format("Failed to kill: {}", strerror(errno)));
    std::cout << std::format("[{}]: killed\n", m_pid);

    cleanup();
}

void Tracee::cont() 
{
    user_regs_struct user_regs = regs();
    if (WIFSTOPPED(m_wstatus))
        user_regs.rip--;

    uint64_t file_addr = user_regs.rip;

    if (elf.is_pie()) {
        // breakpoints are set on the address found for the symbol in the elf file on disk,
        // here we are getting the virtual address that the kernel has mapped us at because 
        // this is a position independent executable. (thankfully no ASLR because we disable it,
        // so section layout is still fine) Thus we need to offset it by the base address of our mapping :)
        file_addr -= m_base_addr;
    }

    bool at_breakpoint = m_breakpoints.contains(file_addr);
    
    if (at_breakpoint) {
        m_breakpoints.at(file_addr).unset();
        if (ptrace(PTRACE_SETREGS, m_pid, nullptr, &user_regs) < 0)
            throw std::runtime_error(std::format("Failed to SETREGS: {}", strerror(errno)));
    }

    if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) < 0)
        throw std::runtime_error(std::format("Failed to continue: {}", strerror(errno)));

    // re-enable after we step over it
    if (at_breakpoint) {
        try { // this might fail due to tracee process exiting before us reaching this point.
            m_breakpoints.at(file_addr).set();
        } catch (std::exception& e) {
            // nop
        }
    }

    waitsig();
}

user_regs_struct Tracee::regs() 
{
    struct user_regs_struct regs_struct;
    if (ptrace(PTRACE_GETREGS, m_pid, 0, &regs_struct) < 0)
        throw std::runtime_error("failed to get registers.");
    return regs_struct;
}

uint64_t Tracee::get_reg(reg::Register reg) const
{
    uint64_t offset = reg::to_offset(reg);

    errno = 0;
    uint64_t value = ptrace(PTRACE_PEEKUSER, m_pid, offset, nullptr);
    if (errno)
        throw std::runtime_error(std::format("Failed to PTRACE_PEEKUSER: {}", strerror(errno)));

    return value;
}

void Tracee::set_reg(reg::Register reg, uint64_t value)
{
    uint64_t offset = reg::to_offset(reg);

    errno = 0;
    ptrace(PTRACE_POKEUSER, m_pid, offset, value);
    if (errno)
        throw std::runtime_error(std::format("Failed to PTRACE_POKEUSER: {}", strerror(errno)));
}

bool Tracee::is_running() const
{
    return m_pid;
}

pid_t Tracee::pid() const
{
    return m_pid;
}

uint64_t Tracee::base_addr() const
{
    return m_base_addr;
}

void Tracee::waitsig() 
{
    waitpid(m_pid, &m_wstatus, 0);
    if (WIFSTOPPED(m_wstatus)) {
        std::cout << std::format("Tracee stopped by: {} ({}) at address 0x{:x}\n", 
                                 strsignal(WSTOPSIG(m_wstatus)), m_wstatus, regs().rip);
    } else if (WIFEXITED(m_wstatus)) {
        std::cout << std::format("[{}] Process exited with: {}\n", m_pid, WEXITSTATUS(m_wstatus));
        cleanup();
    }
}

// cleans up after a process exits
void Tracee::cleanup()
{
    // m_breakpoints.clear();
    m_pid = 0;
    m_base_addr = 0;

    for (auto& [_, bp] : m_breakpoints)
        bp.m_set = false;
}

// -----------
// BreakPoint related

const Tracee::BreakPointMap_t& Tracee::breakpoints()
{
    return m_breakpoints;
}

void Tracee::breakpoint_add(intptr_t address)
{
    m_breakpoints.insert_or_assign(address, BreakPoint {address, this});
}

void Tracee::breakpoint_clear()
{
    m_breakpoints.clear();
}

void BreakPoint::reset()
{
    if (m_enabled)
        set();
}

void BreakPoint::set()
{
    if (m_set)
        return;

    uint64_t vaddr = m_addr + m_tracee->base_addr();
    
    // ptrace returns _word aligned_ data, so we just move it to the lower boundary and adjust the mask
    int mod = vaddr % WORD_SIZE;
    vaddr -= mod;
    uint64_t mask = 0xffUL << mod*8;

    long data = ptrace(PTRACE_PEEKDATA, m_tracee->pid(), vaddr, nullptr);
    if (data == -1)
        throw std::runtime_error(std::format("Failed to PTRACE_PEEKDATA: {}", strerror(errno)));

    m_saved = data & mask;

    data = (data & ~mask) | (BreakPoint::INT3 << mod*8);
    if (ptrace(PTRACE_POKEDATA, m_tracee->pid(), vaddr, data) == -1)
        throw std::runtime_error(std::format("Failed to PTRACE_POKEDATA: {}", strerror(errno)));

    m_set = true;
}

void BreakPoint::unset()
{
    if (!m_set)
        return;

    // ptrace returns _word aligned_ data, so we just move it to the lower boundary and adjust the mask
    uint64_t vaddr = m_addr + m_tracee->base_addr();
    int mod = vaddr % WORD_SIZE;
    vaddr -= mod;
    uint64_t mask = 0xffUL << mod*8;

    long data = ptrace(PTRACE_PEEKDATA, m_tracee->pid(), vaddr, nullptr);
    if (data == -1)
        throw std::runtime_error(std::format("Failed to PTRACE_PEEKDATA: {}", strerror(errno)));

    data = (data & ~mask) | m_saved;

    if (ptrace(PTRACE_POKEDATA, m_tracee->pid(), vaddr, data) == -1)
        throw std::runtime_error(std::format("Failed to PTRACE_POKEDATA: {}", strerror(errno)));

    m_set = false;
}
