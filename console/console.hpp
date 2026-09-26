#pragma once

#include <string>
#include <iostream>
#include <utility>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

namespace console
{
    enum class Color {
        Default = 39,
        Black = 30, Red = 31, Green = 32, Yellow = 33,
        Blue = 34, Magenta = 35, Cyan = 36, White = 37,
        Gray = 90, BrightRed = 91, BrightGreen = 92, BrightYellow = 93,
        BrightBlue = 94, BrightMagenta = 95, BrightCyan = 96, BrightWhite = 97
    };

    // A styled piece of text.
    struct Seg {
        std::string text;
        Color color = Color::Default;
        bool  bold = false;
        bool  underline = false;
    };

    inline std::string hex(uintptr_t v)
    {
        char buf[2 + sizeof(uintptr_t) * 2 + 1];   // "0x" + 16 hex digits + NUL
        std::snprintf(buf, sizeof(buf), "0x%llX",
            static_cast<unsigned long long>(v));
        return buf;
    }

    namespace detail
    {
        inline bool enable_vt()
        {
#ifdef _WIN32
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD mode = 0;
            if (!GetConsoleMode(h, &mode)) return false;
            return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
            return true;
#endif
        }
        inline const bool vt_ready = enable_vt();   // runs once at load

        inline std::string render(const Seg& s)
        {
            std::string out = "\x1b[";
            bool first = true;
            auto add = [&](int code) {
                if (!first) out += ';';
                out += std::to_string(code);
                first = false;
                };
            if (s.bold)      add(1);
            if (s.underline) add(4);
            add(static_cast<int>(s.color));
            out += 'm';
            out += s.text;
            out += "\x1b[0m";
            return out;
        }

        // accept Seg, std::string, or const char* as a print argument
        inline Seg to_seg(Seg s) { return s; }
        inline Seg to_seg(std::string s) { return { std::move(s) }; }
        inline Seg to_seg(const char* s) { return { std::string(s) }; }
    }

    // ---- segment builders ----
    inline Seg col(std::string t, Color c) { return { std::move(t), c, false }; }
    inline Seg bold(std::string t, Color c = Color::Default) { return { std::move(t), c, true }; }
    inline Seg tag(std::string name, Color c = Color::BrightWhite)
    {
        return { "[" + std::move(name) + "]", c, true };   // always bold
    }

    // ---- output ----
    template <typename... Ts>
    void print(Ts&&... parts)
    {
        (void)detail::vt_ready;
        std::string line;
        ((line += detail::render(detail::to_seg(std::forward<Ts>(parts)))), ...);
        std::cout << line;
    }

    template <typename... Ts>
    void println(Ts&&... parts)
    {
        print(std::forward<Ts>(parts)...);
        std::cout << '\n';
    }

    // ---- ready-made leveled logs (bold colored tag + space) ----
    template <typename... Ts> void info(Ts&&... p) { println(tag("INFO", Color::BrightCyan), " ", std::forward<Ts>(p)...); }
    template <typename... Ts> void ok(Ts&&... p) { println(tag("OK", Color::BrightGreen), " ", std::forward<Ts>(p)...); }
    template <typename... Ts> void warn(Ts&&... p) { println(tag("WARN", Color::BrightYellow), " ", std::forward<Ts>(p)...); }
    template <typename... Ts> void err(Ts&&... p) { println(tag("ERR", Color::BrightRed), " ", std::forward<Ts>(p)...); }
}