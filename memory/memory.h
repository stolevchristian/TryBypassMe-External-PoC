#define IDA_BASE 0x140000000ULL
using uint = uintptr_t;


namespace memory
{
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    uint   baseAddr = 0;

    static uint read_image_base(HANDLE proc)
    {
        auto NtQIP = reinterpret_cast<NTSTATUS(NTAPI*)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                    "NtQueryInformationProcess"));
        if (!NtQIP)
            return 0;

        PROCESS_BASIC_INFORMATION pbi{};
        if (NtQIP(proc, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0)
            return 0;

        uint imageBase = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x10,
            &imageBase, sizeof(imageBase), &got) || got != sizeof(imageBase))
            return 0;

        return imageBase;
    }

    bool launch(const wchar_t* exePath, const wchar_t* args = nullptr)
    {
        std::wstring cmd;
        LPWSTR cmdPtr = nullptr;
        if (args) {
            cmd = L"\"";
            cmd += exePath;
            cmd += L"\" ";
            cmd += args;
            cmdPtr = cmd.data();
        }

        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};

        if (!CreateProcessW(exePath, cmdPtr, nullptr, nullptr, FALSE,
            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
            return false;

        hProcess = pi.hProcess;
        hThread = pi.hThread;

        baseAddr = read_image_base(hProcess);
        if (baseAddr == 0) {
            TerminateProcess(hProcess, 1);
            CloseHandle(hThread);  hThread = nullptr;
            CloseHandle(hProcess); hProcess = nullptr;
            return false;
        }
        return true;
    }

    void resume()
    {
        if (hThread) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            hThread = nullptr;
        }
    }

    void detach()
    {
        if (hThread) { CloseHandle(hThread);  hThread = nullptr; }
        if (hProcess) { CloseHandle(hProcess); hProcess = nullptr; }
    }

    bool write(uint dest, const uint8_t* src, SIZE_T size)
    {
        if (hProcess == nullptr || dest == 0 || src == nullptr || size == 0)
            return false;

        void* address = reinterpret_cast<void*>(dest);

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProcess, address, size,
            PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        SIZE_T written = 0;
        bool ok = WriteProcessMemory(hProcess, address, src, size, &written)
            && written == size;

        DWORD tmp = 0;
        VirtualProtectEx(hProcess, address, size, oldProtect, &tmp);
        FlushInstructionCache(hProcess, address, size);
        return ok;
    }

    bool write(uint dest, const std::vector<uint8_t>& data)
    {
        return write(dest, data.data(), data.size());
    }

    template <typename T>
    bool write(uint dest, const T& value)
    {
        static_assert(std::is_trivially_copyable_v<T>,
            "memory::write<T> requires a trivially-copyable type");
        return write(dest, reinterpret_cast<const uint8_t*>(&value), sizeof(T));
    }

    bool read(uint src, void* out, SIZE_T size)
    {
        if (hProcess == nullptr || src == 0)
            return false;
        SIZE_T got = 0;
        return ReadProcessMemory(hProcess, reinterpret_cast<void*>(src),
            out, size, &got)
            && got == size;
    }
}