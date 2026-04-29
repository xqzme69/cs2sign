#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

class Console {
public:
    enum Color {
        BLACK = 0,
        DARK_BLUE = 1,
        DARK_GREEN = 2,
        DARK_CYAN = 3,
        DARK_RED = 4,
        DARK_MAGENTA = 5,
        DARK_YELLOW = 6,
        LIGHT_GRAY = 7,
        DARK_GRAY = 8,
        BLUE = 9,
        GREEN = 10,
        CYAN = 11,
        RED = 12,
        MAGENTA = 13,
        YELLOW = 14,
        WHITE = 15
    };

    static void Init();
    static void SetColor(Color foreground, Color background = BLACK);
    static void ResetColor();
    static bool IsInteractiveOutput();

    static void SetLogOutputEnabled(bool enabled);
    static bool IsLogOutputEnabled();

    static std::string CenterText(const std::string& text, size_t width);
    static void AnimateLine(const std::string& line, Color color, int delayMs = 8);
    static void PrintColoredLine(const std::string& line, Color color, int delayMs = 0);
    static void PrintBoxLine(const std::string& text, Color color, int delayMs = 0);
    static Color SelectBreathingColor(size_t row, size_t column, int frame);
    static void PrintBreathingBoxLine(const std::string& text, size_t row, int frame, int letterDelayMs = 0);
    static void PulseBreathingArtBlock(const std::string* lines, int lineCount);
    static void AnimateScanBar();
    static void PrintBanner();

    static std::string WStringToString(const std::wstring& wstr);
    static void PrintHeader(const std::wstring& text);
    static void PrintFooter();
    static void PrintSuccess(const std::wstring& text);
    static void PrintError(const std::wstring& text);
    static void PrintInfo(const std::wstring& text);
    static void PrintWarning(const std::wstring& text);
    static void PrintProgress(size_t current, size_t total, const std::wstring& name);
    static void PrintFound(const std::wstring& name, uintptr_t address, size_t regions, size_t bytes);
    static void PrintNotFound(const std::wstring& name, const std::string& error);
    static void PrintErrorMsg(const std::wstring& name, const std::string& error);
    static void ClearLine();

private:
    static HANDLE hConsole;
    static WORD originalAttributes;
    static bool logOutputEnabled;
};
