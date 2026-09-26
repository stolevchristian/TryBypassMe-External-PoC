#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include <cstring>
#include <string>
#include <thread>
#include "memcheck/memcheck.h"

#define rebase(x) (memory::baseAddr + ((x) - IDA_BASE))

namespace offsets
{
    /* anti-tamper related offsets */
    inline uint dll_enumerator() { return rebase(0x140017160); }
    inline uint proc_enumerator() { return rebase(0x14000B020); }
    inline uint hndl_enumerator() { return rebase(0x140019560); }

    /* anti-cheat related offsets */
    inline uint health_sanity_1()           { return rebase(0x14001222D); }
    inline uint health_sanity_1_target()    { return rebase(0x1400126D3); }
    inline uint health_sanity_2()           { return rebase(0x140022C77); }
    inline uint health_sanity_2_target()    { return rebase(0x1400230C3); }
    inline uint health_sanity_3()           { return rebase(0x140022362); }
    inline uint health_sanity_3_target()    { return rebase(0x1400227B3); }

    inline uint health_freeze_check()       { return rebase(0x140020680); }
    inline uint health_override_1()         { return rebase(0x14002D44B); } // 14002BF63
    inline uint health_override_2()         { return rebase(0x14002BF63); }

    /* game related offsets */
    inline uint bullet_damage() { return rebase(0x14002BAF9); }
    inline uint ammo() { return rebase(0x140044950); }
    inline uint health() { return rebase(0x1400449D0); }

    struct Entry { const char* name; uint(*fn)(); };

    inline const std::vector<Entry>& table()
    {
        static const std::vector<Entry> t = {
            { "dll_enumerator",        dll_enumerator        },
            { "proc_enumerator",       proc_enumerator       },
            { "hndl_enumerator",       hndl_enumerator       },
            { "health_sanity_1",       health_sanity_1       },
            { "health_sanity_1_target",health_sanity_1_target},
            { "health_sanity_2",       health_sanity_2       },
            { "health_sanity_2_target",health_sanity_2_target},
            { "health_sanity_3",       health_sanity_3       },
            { "health_sanity_3_target",health_sanity_3_target},
            { "health_freeze_check",   health_freeze_check   },
            { "health_override_1",     health_override_1     },
            { "health_override_2",     health_override_2     },
            { "bullet_damage",         bullet_damage         },
            { "ammo",                  ammo                  },
            { "health",                health                },
        };
        return t;
    }

    inline void dump()
    {
        // widest name, for column alignment
        size_t w = 0;
        for (const auto& e : table())
            w = (std::max)(w, std::string_view(e.name).size());

        for (const auto& e : table())
        {
            std::string name = e.name;
            name.append(w - name.size(), ' ');   // pad to column width
            console::println(
                console::tag("OFFSETS"), " ",
                name, "  ",
                console::col("->", console::Color::BrightCyan), " ",
                console::col(console::hex(e.fn()), console::Color::BrightYellow));
        }
    }
}

#include "xbyak/xbyak.h"

namespace assembly
{
    std::vector<uint8_t> ret()
    {
        struct Gen : Xbyak::CodeGenerator {
            Gen() {
                xor_(eax, eax);
                ret();
            }
        };
        Gen g;
        return { g.getCode(), g.getCode() + g.getSize() };
    }
    
    std::vector<uint8_t> mov_dword_rbx()
    {
        struct Gen : Xbyak::CodeGenerator {
            Gen() {
                mov(dword[rbx + 0x18], 9999);
            }
        };
        Gen g;
        return { g.getCode(), g.getCode() + g.getSize() };
    }
    std::vector<uint8_t> jmp_rel32(uint patchAddr, uint target, size_t origLen)
    {
        std::vector<uint8_t> out;
        out.push_back(0xE9);
        int32_t rel = static_cast<int32_t>(target - (patchAddr + 5));
        out.insert(out.end(),
            reinterpret_cast<uint8_t*>(&rel),
            reinterpret_cast<uint8_t*>(&rel) + 4);
        while (out.size() < origLen)      // pad to match what we overwrote
            out.push_back(0x90);          // nop
        return out;
    }

    std::vector<uint8_t> mov_edx(int value)
    {
        struct Gen : Xbyak::CodeGenerator {
            Gen(int v) { mov(edx, v); }
        };
        Gen g(value);
        return { g.getCode(), g.getCode() + g.getSize() };
    }

    std::vector<uint8_t> jmp(uintptr_t to) {
        std::vector<uint8_t> out(14);
        out[0] = 0xFF; out[1] = 0x25;                 // jmp qword ptr [rip+0]
        std::memset(&out[2], 0, 4);                   // disp32 = 0
        std::memcpy(&out[6], &to, sizeof(to));        // 8-byte absolute target
        return out;
    }
}
namespace obf
{
    constexpr uint IDA_K0 = 0x1400448C0;
    constexpr uint IDA_K1 = 0x1400447B8;

    struct Keys { uint32_t k0, k1; };

    bool read_keys(Keys& out)
    {
        uintptr_t p0 = 0, p1 = 0;
        if (!memory::read(rebase(IDA_K0), &p0, sizeof(p0))) return false;
        if (!memory::read(rebase(IDA_K1), &p1, sizeof(p1))) return false;
        if (!memory::read(p0, &out.k0, sizeof(out.k0)))     return false;
        if (!memory::read(p1, &out.k1, sizeof(out.k1)))     return false;
        return true;
    }

    int32_t read_value(uint block, bool verify = true)
    {
        Keys k;
        if (!read_keys(k)) return false;

        uint32_t s0 = 0;
        if (!memory::read(block + 0 * 4, &s0, sizeof(s0))) return false;
        int32_t v0 = static_cast<int32_t>(s0 ^ k.k0);

        if (verify) {
            uint32_t s26 = 0;
            if (!memory::read(block + 26 * 4, &s26, sizeof(s26))) return false;
            int32_t v1 = static_cast<int32_t>(s26 ^ k.k1);
            if (v0 != v1) return NULL;
        }
        return v0;
    }

    bool write_value(uint block, int32_t value)
    {
        Keys k;
        if (!read_keys(k)) return false;

        uint32_t s0 = static_cast<uint32_t>(value) ^ k.k0;
        uint32_t s26 = static_cast<uint32_t>(value) ^ k.k1;

        if (!memory::write(block + 0 * 4, s0))  return false;
        if (!memory::write(block + 26 * 4, s26)) return false;
        return true;
    }
}

inline std::string to_hex_string(const std::vector<uint8_t>& data,
    const char* sep = " ")
{
    std::string out;
    out.reserve(data.size() * 3);
    char buf[4];
    for (size_t i = 0; i < data.size(); ++i) {
        std::snprintf(buf, sizeof(buf), "%02X", data[i]);
        if (i) out += sep;
        out += buf;
    }
    return out;
}

int main()
{
    println(tag("INIT"), " Attempting to launch target process..");
    if (!memory::launch(L"Level3.exe")) {
        println(tag("INIT"), col(" Failed to launch process, make sure you're running as admin.", Color::BrightRed));
    }
    offsets::dump();
    /* bypassing DLL, handle and proc enumeration in case you want to go internal for some reason */
    {
        auto shellcode = assembly::ret();
        memory::write(offsets::dll_enumerator(), shellcode);
        memory::write(offsets::proc_enumerator(), shellcode);
        memory::write(offsets::hndl_enumerator(), shellcode);

        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(shellcode), Color::BrightCyan));
        println(tag("BYPASS"), " DLLs, processes and handles are now invisible.");
    }
    memory::resume();
    std::thread(memcheck::spoof).detach();
    Sleep(2000);

    /* hp and ammo bypasses overcomplicated but just for educational purposes */
    {
        /* literally just skipping the detection´*/
        memory::write(offsets::health_sanity_1(), assembly::jmp_rel32(offsets::health_sanity_1(), offsets::health_sanity_1_target(), 6));
        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(assembly::jmp_rel32(offsets::health_sanity_1(), offsets::health_sanity_1_target(), 6)), Color::BrightCyan));
        memory::write(offsets::health_sanity_2(), assembly::jmp_rel32(offsets::health_sanity_2(), offsets::health_sanity_2_target(), 6));
        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(assembly::jmp_rel32(offsets::health_sanity_2(), offsets::health_sanity_2_target(), 6)), Color::BrightCyan));
        memory::write(offsets::health_sanity_3(), assembly::jmp_rel32(offsets::health_sanity_3(), offsets::health_sanity_3_target(), 6));
        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(assembly::jmp_rel32(offsets::health_sanity_3(), offsets::health_sanity_3_target(), 6)), Color::BrightCyan));

        /* couldn't bother finding a viable spot for spoofing the value, etc */
        memory::write(offsets::health_freeze_check(), assembly::ret());
        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(assembly::ret()), Color::BrightCyan));

        /* fixes override issues when you pick up health after rounds or on map (cap resets it to 100) */
        memory::write(offsets::health_override_1(), { 0x90, 0x90, 0x90 });
        memory::write(offsets::health_override_2(), { 0x90, 0x90, 0x90, 0x90 });
    }

    /* one shot kill with base gun, does not affect other weapons (too lazy to add proper handling) */
    {
        memory::write(offsets::bullet_damage(), assembly::mov_dword_rbx());
        println(tag("BYPASS"), " shellcode -> ", col(to_hex_string(assembly::mov_dword_rbx()), Color::BrightCyan));
    }

    while (true)
    {
        obf::write_value(offsets::ammo(), 99999);
        obf::write_value(offsets::health(), 99999);
        Sleep(10);
    }
}