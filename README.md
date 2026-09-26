# TryBypassMe Level 3 Bypassed

External bypass PoC for **TryBypassMe**, the anti-cheat crackme series by [ali123x](https://www.unknowncheats.me/forum/anti-cheat-research/743802-trybypassme-bypass-anti-cheat.html) on UnknownCheats. 

![Screenshot of the bypass running.](/images/image.png)

This targets **Level 3**, the hardest of the three, which per the author's own writeup ships with:
- External watchdog process with HMAC-authenticated named pipe
- Watchdog CRC32 disk hash verification
- AcToken 3-word commit (no single detection flag)
- AC checks inlined directly in the game's render loop
- Code CRC split across 3 independent checkers, re-keyed every 30s
- Dual-key encrypted memory with shadow copies and canaries
- Encrypted damage/heal counters
- DLL injection detection with Authenticode verification
- Compile-time string encryption via [skCrypter](https://www.unknowncheats.me/forum/anti-cheat-bypass/374040-skcrypter-compile-time-um-km-safe-string-crypter-library-11-a.html)
- Cookie echo thread liveness check
- `CREATE_SUSPENDED` loader detection
- VEH + PAGE_GUARD detection
- Triple-kill termination
- Mandatory splash screen with a 12s watchdog deadline
- Randomized AC check dispatch order (shuffled every iteration via `GetTickCount64`)
- Hardware breakpoint detection (`Dr0`-`Dr3` via `GetThreadContext`)
- `NtQueryInformationProcess` dual-check (`ProcessDebugPort` + `ProcessDebugObjectHandle`)
- `NtGlobalFlag` heap flag check (survives usermode debugger patches)
- RDTSC timing-attack detection
- Dynamically resolved kill functions (XOR-decoded strings, bypasses IAT hooks)
- Frequency-gated checks (some only run every 2nd/5th/6th/10th loop)
- Runs as admin
- Decentralized detection, no single point of failure

This is not my crackme, no credit for the target is claimed — all credit for the protection goes to ali123x. This repo is just my solution.

## What this actually does

Everything here is **external** — no code runs inside the target process, no DLL is injected, nothing is dropped on disk for the game to find. The PoC is a separate .exe that launches `Level3.exe` suspended, reads its own image base out of the PEB, and patches/pokes memory purely through `ReadProcessMemory`/`WriteProcessMemory`.

At a high level, on launch it:

1. Spawns `Level3.exe` with `CREATE_SUSPENDED` and reads the image base before resuming the main thread — see [memory.h](memory/memory.h).
2. Patches the DLL, process and handle enumerator routines with a `xor eax,eax; ret` stub, so all three enumeration checks come back empty. This also covers you if you'd rather run internal for some reason.
3. Kicks off a background thread that keeps the integrity/memory check honest — see [memcheck.h](memcheck/memcheck.h) below.
4. Redirects the three health "sanity" checks past their detection logic with relative jumps, NOPs out the two spots that reset your HP back to 100 on pickup/round change, and patches the base weapon's damage write for a one-shot.
5. Loops forever, writing spoofed ammo/health values through the game's own dual-key XOR+canary encoding so the values look legitimate to anything reading them back.

### The memcheck bypass (the actual interesting part)

Level 3 validates a chunk of its own memory by CRC32'ing a protected section and comparing the result against three expected values, refreshed off a rotating nonce. Instead of patching out that check or freezing the CRC, this PoC:

- Reads the same nonce and protected section the game itself uses
- Computes the CRC32 locally, the same way the game does
- Derives the three expected values from that CRC + nonce using the game's own formula
- Writes those values back into the three expected-value slots

In other words the "integrity check" gets fed a hash that's actually correct for the (patched) memory it's checking — no assembly is patched to skip it, no flag is flipped, the check just passes because the math checks out. It also keeps a shadow "clean" copy of the section in sync (`SYNC_CLEAN_COPY`) so canary/shadow comparisons made against that clean copy don't desync either. This loop runs continuously (every ~40ms) since the CRC and nonce get re-derived periodically.

The `CREATE_SUSPENDED` loader-detection check is sidestepped as a side effect of how the process is launched and resumed here — the base is read from the PEB before any thread runs, then the check that watches for suspended-launch injection never gets to fire in a way that matters for an external, non-injecting tool.

### What this does *not* bypass

This is a PoC for the parts that were interesting to solve, not a full clean run of every check listed above. Things it doesn't touch: the external watchdog/HMAC pipe, disk hash verification, Authenticode checks, VEH/PAGE_GUARD detection, hardware breakpoints, RDTSC timing checks, or the splash screen deadline. The one-shot patch also only affects the base weapon — other weapons weren't wired up, this was written for the "does the concept work" part, not to be a full cheat.

## Third-party code

- Uses [xbyak](https://github.com/herumi/xbyak) for runtime shellcode generation (vendored in [xbyak/](xbyak))

## Running

1. Grab Level 3 from ali123x's [UnknownCheats thread](https://www.unknowncheats.me/forum/anti-cheat-research/743802-trybypassme-bypass-anti-cheat.html)
2. Place `Level3.exe` where the PoC expects it (same working directory, or adjust the path in [ExternalPoC.cpp](ExternalPoC.cpp))
3. Run `ExternalPoC.exe` **as administrator** (the target requires it)

Console output logs every resolved offset and every patch it writes, so you can follow along with what's happening.

## Disclaimer

Written for educational purposes, to study and document anti-cheat/anti-tamper techniques against a crackme built specifically for this kind of research. Not intended for use against any real anti-cheat or live game.
