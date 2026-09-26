// typed read to match write<T>
#include "../memory/memory.h"
#include "console/console.hpp"
using namespace console;

template <typename T>
bool read_t(uint src, T& out) { return memory::read(src, &out, sizeof(T)); }

// follow a global that holds a pointer: base+rva -> ptr
static bool deref_ptr(uint global_rva_addr, uint& out_ptr)
{
    return read_t<uint>(global_rva_addr, out_ptr) && out_ptr != 0;
}
#define SPOOF_MEMORY        1     
#define SYNC_CLEAN_COPY     1  
#define MEM_INTERVAL_MS     40 
#define DISK_INTERVAL_MS    1000
namespace memcheck
{
    // RVAs unchanged
    constexpr uint RVA_NONCE_MEM = 0x44AE0, RVA_EXP0 = 0x44AD0, RVA_EXP1 = 0x447A8,
        RVA_EXP2 = 0x44A48, RVA_SEC_BASE = 0x44C48, RVA_SEC_SIZE = 0x44C40,
        RVA_CLEAN = 0x44C50;
    constexpr uint RVA_NONCE_DISK = 0x447F0, RVA_DISK0 = 0x44820,
        RVA_DISK1 = 0x44AD8, RVA_BE8 = 0x44BE8;

    static uint32_t g_tab[256];
    static void crc32_init() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            g_tab[i] = c;
        }
    }
    static uint32_t crc32_buf(const uint8_t* p, size_t n) {
        uint32_t c = 0xFFFFFFFFu;
        for (size_t i = 0; i < n; ++i) c = g_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
        return ~c;
    }

    static bool once = false;

    static int bless_memory()
    {
        uint base = memory::baseAddr;

        uint pNonce, pE0, pE1, pE2, pSec, pClean, secSize;
        if (!deref_ptr(base + RVA_NONCE_MEM, pNonce)) return 0;
        if (!deref_ptr(base + RVA_EXP0, pE0))    return 0;
        if (!deref_ptr(base + RVA_EXP1, pE1))    return 0;
        if (!deref_ptr(base + RVA_EXP2, pE2))    return 0;
        if (!deref_ptr(base + RVA_SEC_BASE, pSec))   return 0;
        if (!read_t<uint>(base + RVA_SEC_SIZE, secSize) || secSize == 0) return 0;
        deref_ptr(base + RVA_CLEAN, pClean); // optional, may be null

        uint32_t nonce = 0;
        if (!read_t<uint32_t>(pNonce, nonce) || nonce == 0) return 0;

        // pull the protected section across and CRC it locally
        std::vector<uint8_t> sec(secSize);
        if (!memory::read(pSec, sec.data(), secSize)) return 0;
        uint32_t crc = crc32_buf(sec.data(), secSize);

        uint32_t e0 = nonce ^ (crc >> 22) ^ 0x13375EEDu;
        uint32_t e1 = (3u * nonce) ^ ((crc >> 11) & 0x7FF) ^ 0xFEEDF00Du;
        uint32_t e2 = (crc & 0x7FF) ^ (7u * nonce) ^ 0xC001C0DEu;

        if (!memory::write<uint32_t>(pE0, e0)) return 0;
        if (!memory::write<uint32_t>(pE1, e1)) return 0;
        if (!memory::write<uint32_t>(pE2, e2)) return 0;

        if (!once) {
            println(tag("MEMCHECK"), " nonce  -> ", col(console::hex(nonce), Color::Gray));
            println(tag("MEMCHECK"), " pE0    -> ", col(console::hex(pE0), Color::Gray));
            once = true;
        }

#if SYNC_CLEAN_COPY
        if (pClean) memory::write(pClean, sec.data(), secSize); // raw-buffer overload
#endif
        return 1;
    }

    void spoof()
    {
        crc32_init();
        println(tag("MEMCHECK"), " Waiting for original memcheck to cache pages..");
        while (!bless_memory()) Sleep(20);
        println(tag("MEMCHECK"), col(" DONE", Color::BrightGreen));

        DWORD acc = 0;
        for (;;) {
#if SPOOF_MEMORY
            bless_memory();
#endif
            Sleep(MEM_INTERVAL_MS);
        }
    }
}