#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <iomanip>

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

    static void Init() {
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        originalAttributes = csbi.wAttributes;
    }

    static void SetColor(Color foreground, Color background = BLACK) {
        if (hConsole == INVALID_HANDLE_VALUE) Init();
        WORD color = (background << 4) | foreground;
        SetConsoleTextAttribute(hConsole, color);
    }

    static void ResetColor() {
        if (hConsole == INVALID_HANDLE_VALUE) Init();
        SetConsoleTextAttribute(hConsole, originalAttributes);
    }

    static bool IsInteractiveOutput() {
        if (hConsole == INVALID_HANDLE_VALUE) Init();

        DWORD mode = 0;
        return GetConsoleMode(hConsole, &mode) != 0;
    }

    static void SetLogOutputEnabled(bool enabled) {
        logOutputEnabled = enabled;
    }

    static bool IsLogOutputEnabled() {
        return logOutputEnabled;
    }

    static std::string CenterText(const std::string& text, size_t width) {
        if (text.size() >= width) {
            return text.substr(0, width);
        }

        const size_t left = (width - text.size()) / 2;
        const size_t right = width - text.size() - left;
        return std::string(left, ' ') + text + std::string(right, ' ');
    }

    static void AnimateLine(const std::string& line, Color color, int delayMs = 8) {
        if (!logOutputEnabled) return;

        SetColor(color);
        if (delayMs <= 0 || !IsInteractiveOutput()) {
            std::cout << line << "\n";
            ResetColor();
            return;
        }

        for (char c : line) {
            std::cout << c;
            std::cout.flush();
            Sleep(delayMs);
        }
        std::cout << "\n";
    }

    static void PrintColoredLine(const std::string& line, Color color, int delayMs = 0) {
        if (!logOutputEnabled) return;

        SetColor(color);
        std::cout << line << "\n";
        ResetColor();
        if (delayMs > 0) {
            Sleep(delayMs);
        }
    }

    static void PrintBoxLine(const std::string& text, Color color, int delayMs = 0) {
        if (!logOutputEnabled) return;

        constexpr size_t contentWidth = 58;
        std::string content = text;
        if (content.size() > contentWidth) {
            content = content.substr(0, contentWidth);
        }

        SetColor(DARK_MAGENTA);
        std::cout << "  |  ";
        SetColor(color);
        std::cout << content << std::string(contentWidth - content.size(), ' ');
        SetColor(DARK_MAGENTA);
        std::cout << "  |\n";
        ResetColor();

        if (delayMs > 0 && IsInteractiveOutput()) {
            Sleep(delayMs);
        }
    }

    static Color SelectBreathingColor(size_t row, size_t column, int frame) {
        static constexpr Color palette[] = {
            DARK_MAGENTA,
            MAGENTA,
            WHITE,
            CYAN,
            WHITE,
            MAGENTA
        };

        const int wave = static_cast<int>((column / 3 + row + frame) % 6);
        return palette[wave];
    }

    static void PrintBreathingBoxLine(
        const std::string& text,
        size_t row,
        int frame,
        int letterDelayMs = 0
    ) {
        if (!logOutputEnabled) return;

        if (!IsInteractiveOutput()) {
            PrintBoxLine(text, WHITE, 0);
            return;
        }

        constexpr size_t contentWidth = 58;
        std::string content = text;
        if (content.size() > contentWidth) {
            content = content.substr(0, contentWidth);
        }

        SetColor(DARK_MAGENTA);
        std::cout << "  |  ";

        for (size_t column = 0; column < contentWidth; ++column) {
            const char character = column < content.size() ? content[column] : ' ';
            if (character == ' ') {
                SetColor(DARK_GRAY);
            } else {
                SetColor(SelectBreathingColor(row, column, frame));
            }

            std::cout << character;
            if (letterDelayMs > 0 && character != ' ') {
                std::cout.flush();
                Sleep(letterDelayMs);
            }
        }

        SetColor(DARK_MAGENTA);
        std::cout << "  |\n";
        ResetColor();
    }

    static void PulseBreathingArtBlock(const std::string* lines, int lineCount) {
        if (!IsInteractiveOutput() || hConsole == INVALID_HANDLE_VALUE) {
            return;
        }

        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            return;
        }

        const SHORT topRow = static_cast<SHORT>(csbi.dwCursorPosition.Y - lineCount);
        for (int frame = 1; frame <= 10; ++frame) {
            SetConsoleCursorPosition(hConsole, {0, topRow});
            for (int row = 0; row < lineCount; ++row) {
                PrintBreathingBoxLine(lines[row], static_cast<size_t>(row), frame, 0);
            }
            std::cout.flush();
            Sleep(55);
        }

        SetConsoleCursorPosition(hConsole, {0, static_cast<SHORT>(topRow + lineCount)});
    }

    static void AnimateScanBar() {
        if (!logOutputEnabled) return;

        if (!IsInteractiveOutput()) {
            PrintBoxLine("ready: signatures / schemas / offsets / sdk", CYAN, 0);
            return;
        }

        constexpr int barWidth = 30;
        for (int frame = 0; frame < 34; ++frame) {
            SetColor(DARK_MAGENTA);
            std::cout << "\r  |  ";
            SetColor(CYAN);
            std::cout << "[";

            for (int index = 0; index < barWidth; ++index) {
                const int phase = (index + frame) % 9;
                if (phase < 3) {
                    SetColor(WHITE);
                    std::cout << "#";
                } else if (phase < 5) {
                    SetColor(CYAN);
                    std::cout << "=";
                } else {
                    SetColor(DARK_GRAY);
                    std::cout << ".";
                }
            }

            SetColor(CYAN);
            std::cout << "]  ";
            SetColor(DARK_GRAY);
            std::cout << "warming schema output";
            SetColor(DARK_MAGENTA);
            std::cout << "  |";
            std::cout.flush();
            Sleep(28);
        }

        std::cout << "\r" << std::string(66, ' ') << "\r";
        PrintBoxLine("ready: signatures / schemas / offsets / sdk", CYAN, 0);
    }

    static void PrintBanner() {
        if (!logOutputEnabled) return;

        std::cout << "\n";

        PrintColoredLine("  +--------------------------------------------------------------+", DARK_MAGENTA, 30);

        const char* art[] = {
            R"(XX   XX   QQQQ   ZZZZZZZ  MM   MM  EEEEEE)",
            R"( XX XX   QQ  QQ      ZZ   MMM MMM  EE    )",
            R"(  XXX    QQ  QQ     ZZ    MM M MM  EEEEE )",
            R"( XX XX   QQ QQQ    ZZ     MM   MM  EE    )",
            R"(XX   XX   QQQ QQ ZZZZZZZ  MM   MM  EEEEEE)",
        };

        size_t artWidth = 0;
        for (int i = 0; i < 5; i++) {
            const size_t lineWidth = std::string(art[i]).size();
            if (lineWidth > artWidth) {
                artWidth = lineWidth;
            }
        }

        std::string renderedArt[5];
        for (int i = 0; i < 5; i++) {
            renderedArt[i] = art[i];
            if (renderedArt[i].size() < artWidth) {
                renderedArt[i] += std::string(artWidth - renderedArt[i].size(), ' ');
            }
            renderedArt[i] = CenterText(renderedArt[i], 58);
            PrintBreathingBoxLine(renderedArt[i], static_cast<size_t>(i), i * 2, 1);
        }
        PulseBreathingArtBlock(renderedArt, 5);

        PrintBoxLine("", DARK_MAGENTA, 0);
        AnimateScanBar();
        PrintBoxLine("CS2 Signature Scanner  |  by xqzme", WHITE, 0);
        PrintColoredLine("  +--------------------------------------------------------------+", DARK_MAGENTA, 0);
        if (IsInteractiveOutput()) {
            Sleep(160);
        }

        ResetColor();
        std::cout << "\n";
    }

    static std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    static void PrintHeader(const std::wstring& text) {
        if (!logOutputEnabled) return;

        std::string textStr = WStringToString(text);
        SetColor(CYAN);
        std::cout << "\n[ " << textStr;
        int padding = 60 - (int)textStr.length();
        for (int i = 0; i < padding; i++) std::cout << " ";
        std::cout << " ]\n";
        ResetColor();
    }

    static void PrintFooter() {
        if (!logOutputEnabled) return;

        SetColor(CYAN);
        std::cout << std::string(65, '=') << "\n";
        ResetColor();
    }

    static void PrintSuccess(const std::wstring& text) {
        if (!logOutputEnabled) return;

        std::string textStr = WStringToString(text);
        SetColor(GREEN);
        std::cout << "  [+] " << textStr << "\n";
        ResetColor();
    }

    static void PrintError(const std::wstring& text) {
        if (!logOutputEnabled) return;

        std::string textStr = WStringToString(text);
        SetColor(RED);
        std::cout << "  [-] " << textStr << "\n";
        ResetColor();
    }

    static void PrintInfo(const std::wstring& text) {
        if (!logOutputEnabled) return;

        std::string textStr = WStringToString(text);
        SetColor(CYAN);
        std::cout << "  [*] " << textStr << "\n";
        ResetColor();
    }

    static void PrintWarning(const std::wstring& text) {
        if (!logOutputEnabled) return;

        std::string textStr = WStringToString(text);
        SetColor(YELLOW);
        std::cout << "  [!] " << textStr << "\n";
        ResetColor();
    }

    static void PrintProgress(size_t current, size_t total, const std::wstring& name) {
        if (!logOutputEnabled) return;

        double percent = (double)current / total * 100.0;
        int barWidth = 40;
        int filled = (int)(barWidth * percent / 100.0);
        std::string nameStr = WStringToString(name);
        if (nameStr.length() > 25) nameStr = nameStr.substr(0, 22) + "...";
        
        SetColor(CYAN);
        std::cout << "\r  [";
        ResetColor();
        
        SetColor(GREEN);
        for (int i = 0; i < filled; i++) std::cout << "=";
        ResetColor();
        
        SetColor(DARK_GRAY);
        for (int i = filled; i < barWidth; i++) std::cout << "-";
        ResetColor();
        
        SetColor(CYAN);
        std::cout << "] " << std::fixed << std::setprecision(1) << std::setw(5) << percent << "% ";
        std::cout << "(" << std::setw(3) << current << "/" << total << ") ";
        ResetColor();
        
        SetColor(WHITE);
        std::cout << std::setw(25) << std::left << nameStr;
        ResetColor();
        std::cout << std::right << std::setfill(' ');
        
        std::cout.flush();
    }

    static void PrintFound(const std::wstring& name, uintptr_t address, size_t regions, size_t bytes) {
        if (!logOutputEnabled) return;

        std::string nameStr = WStringToString(name);
        ClearLine();
        SetColor(GREEN);
        std::cout << "  [+] FOUND: ";
        ResetColor();
        SetColor(WHITE);
        std::cout << nameStr;
        ResetColor();
        SetColor(CYAN);
        std::cout << " -> ";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "0x" << std::right << std::hex << std::uppercase << address
                  << std::dec << std::nouppercase << std::setfill(' ');
        ResetColor();
        SetColor(DARK_GRAY);
        std::cout << " [" << regions << " regions, " << bytes << " bytes]";
        ResetColor();
        std::cout << "\n";
    }

    static void PrintNotFound(const std::wstring& name, const std::string& error) {
        if (!logOutputEnabled) return;

        std::string nameStr = WStringToString(name);
        ClearLine();
        SetColor(RED);
        std::cout << "  [-] NOT FOUND: ";
        ResetColor();
        SetColor(WHITE);
        std::cout << nameStr;
        ResetColor();
        SetColor(DARK_GRAY);
        std::cout << " - " << error;
        ResetColor();
        std::cout << "\n";
    }

    static void PrintErrorMsg(const std::wstring& name, const std::string& error) {
        if (!logOutputEnabled) return;

        std::string nameStr = WStringToString(name);
        ClearLine();
        SetColor(RED);
        std::cout << "  [-] ERROR: ";
        ResetColor();
        SetColor(WHITE);
        std::cout << nameStr;
        ResetColor();
        SetColor(DARK_GRAY);
        std::cout << " - " << error;
        ResetColor();
        std::cout << "\n";
    }

    static void ClearLine() {
        if (!logOutputEnabled) return;

        std::cout << "\r" << std::string(180, ' ') << "\r";
    }

private:
    static HANDLE hConsole;
    static WORD originalAttributes;
    static bool logOutputEnabled;
};

