#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <stdexcept>

#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unordered_map>

#include <zep.hpp>

namespace addr {

// convert between virtual address of the running tracee and the offset in the on-disk elf file
uint64_t vaddr_to_fileoffset(void *addr);
void *fileoffset_to_vaddr(uint64_t offset);

}

namespace reg {

enum class Register {
    r15 = 0,
    r14, r13, r12, rbp,
    rbx, r11, r10, r9, r8,
    rax, rcx, rdx, rsi, rdi,
    orig_rax, rip, cs, eflags,
    rsp, ss, fs_base, gs_base,
    ds, es, fs, gs, REGISTER_COUNT
};

struct RegDesc {
    uint64_t offset; // offset into struct user_regs_struct
    std::string_view str; // string representation
};

using RegInfo_t = std::array<RegDesc, static_cast<size_t>(Register::REGISTER_COUNT)>;
#define REGINFO_INIT(reg) {.offset = offsetof(struct user_regs_struct, reg), .str = #reg}
constexpr RegInfo_t RegInfo {{
    REGINFO_INIT(r15), 
    REGINFO_INIT(r14), REGINFO_INIT(r13), REGINFO_INIT(r12), REGINFO_INIT(rbp), 
    REGINFO_INIT(rbx), REGINFO_INIT(r11), REGINFO_INIT(r10), REGINFO_INIT(r9), REGINFO_INIT(r8), 
    REGINFO_INIT(rax), REGINFO_INIT(rcx), REGINFO_INIT(rdx), REGINFO_INIT(rsi), REGINFO_INIT(rdi), 
    REGINFO_INIT(orig_rax), REGINFO_INIT(rip), REGINFO_INIT(cs), REGINFO_INIT(eflags), 
    REGINFO_INIT(rsp), REGINFO_INIT(ss), REGINFO_INIT(fs_base), REGINFO_INIT(gs_base), 
    REGINFO_INIT(ds), REGINFO_INIT(es), REGINFO_INIT(fs), REGINFO_INIT(gs)
}};
#undef REGINFO_INIT

uint64_t to_offset(Register reg);
std::string_view to_str(Register reg);
std::optional<Register> from_string(std::string_view str);
std::optional<Register> from_offset(uint64_t offset);

} // namespace reg

class Tracee;

class BreakPoint {
public:
    static_assert(sizeof(uint64_t) == sizeof(long) && "are you compiling for 64bits?");
    static constexpr uint64_t INT3 = 0xcc; // int 3 x86 instruction opcode

    BreakPoint(intptr_t addr, const Tracee* tracee)
    : m_tracee(tracee), m_addr(addr) {}
    
    void reset();
    void enable() { m_enabled = true; }
    void disable() { m_enabled = false; }
    bool enabled() const { return m_enabled; };

    friend class Tracee;
private:
    const Tracee *m_tracee;
    intptr_t m_addr;
    bool m_enabled { true };
    bool m_set { false };
    uint64_t m_saved {}; // previous instruction that was replaced by the breakpoint
    
    void set();
    void unset();
};

class Tracee {
private:
    using BreakPointMap_t = std::unordered_map<intptr_t, BreakPoint>;
public:
    Tracee() = delete;
    Tracee(const Tracee&) = delete;

    explicit Tracee(const std::string& path);

    void spawn();
    void kill();
    void cont();

    user_regs_struct regs();
    uint64_t get_reg(reg::Register reg) const;
    void set_reg(reg::Register reg, uint64_t value);

    [[nodiscard]] bool is_running() const;
    [[nodiscard]] pid_t pid() const;
    [[nodiscard]] uint64_t base_addr() const;

    const BreakPointMap_t& breakpoints();
    void breakpoint_clear();
    void breakpoint_add(intptr_t addr);

    elf::Elf elf;
private:
    void waitsig();
    void cleanup();

    std::string m_path;

    pid_t m_pid = 0;
    int m_wstatus = 0;
    BreakPointMap_t m_breakpoints;
    uint64_t m_base_addr = 0;
};
