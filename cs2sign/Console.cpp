#include "Console.h"

#include <iomanip>
#include <iostream>

HANDLE Console::hConsole = INVALID_HANDLE_VALUE;
WORD Console::originalAttributes = 0;
bool Console::logOutputEnabled = true;

void Console::Init() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    originalAttributes = csbi.wAttributes;
}

void Console::SetColor(Color foreground, Color background) {
    if (hConsole == INVALID_HANDLE_VALUE) {
        Init();
    }

    const WORD color = (background << 4) | foreground;
    SetConsoleTextAttribute(hConsole, color);
}

void Console::ResetColor() {
    if (hConsole == INVALID_HANDLE_VALUE) {
        Init();
    }

    SetConsoleTextAttribute(hConsole, originalAttributes);
}

bool Console::IsInteractiveOutput() {
    if (hConsole == INVALID_HANDLE_VALUE) {
        Init();
    }

    DWORD mode = 0;
    return GetConsoleMode(hConsole, &mode) != 0;
}

void Console::SetLogOutputEnabled(bool enabled) {
    logOutputEnabled = enabled;
}

bool Console::IsLogOutputEnabled() {
    return logOutputEnabled;
}

std::string Console::CenterText(const std::string& text, size_t width) {
    if (text.size() >= width) {
        return text.substr(0, width);
    }

    const size_t left = (width - text.size()) / 2;
    const size_t right = width - text.size() - left;
    return std::string(left, ' ') + text + std::string(right, ' ');
}

void Console::AnimateLine(const std::string& line, Color color, int delayMs) {
    if (!logOutputEnabled) {
        return;
    }

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

void Console::PrintColoredLine(const std::string& line, Color color, int delayMs) {
    if (!logOutputEnabled) {
        return;
    }

    SetColor(color);
    std::cout << line << "\n";
    ResetColor();
    if (delayMs > 0) {
        Sleep(delayMs);
    }
}

void Console::PrintBoxLine(const std::string& text, Color color, int delayMs) {
    if (!logOutputEnabled) {
        return;
    }

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

Console::Color Console::SelectBreathingColor(size_t row, size_t column, int frame) {
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

void Console::PrintBreathingBoxLine(const std::string& text, size_t row, int frame, int letterDelayMs) {
    if (!logOutputEnabled) {
        return;
    }

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

void Console::PulseBreathingArtBlock(const std::string* lines, int lineCount) {
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

void Console::AnimateScanBar() {
    if (!logOutputEnabled) {
        return;
    }

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

void Console::PrintBanner() {
    if (!logOutputEnabled) {
        return;
    }

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

std::string Console::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return {};
    }

    const int sizeNeeded = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    std::string result(static_cast<size_t>(sizeNeeded), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        result.data(),
        sizeNeeded,
        nullptr,
        nullptr
    );
    return result;
}

void Console::PrintHeader(const std::wstring& text) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string textStr = WStringToString(text);
    SetColor(CYAN);
    std::cout << "\n[ " << textStr;
    const int padding = 60 - static_cast<int>(textStr.length());
    for (int i = 0; i < padding; i++) {
        std::cout << " ";
    }
    std::cout << " ]\n";
    ResetColor();
}

void Console::PrintFooter() {
    if (!logOutputEnabled) {
        return;
    }

    SetColor(CYAN);
    std::cout << std::string(65, '=') << "\n";
    ResetColor();
}

void Console::PrintSuccess(const std::wstring& text) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string textStr = WStringToString(text);
    SetColor(GREEN);
    std::cout << "  [+] " << textStr << "\n";
    ResetColor();
}

void Console::PrintError(const std::wstring& text) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string textStr = WStringToString(text);
    SetColor(RED);
    std::cout << "  [-] " << textStr << "\n";
    ResetColor();
}

void Console::PrintInfo(const std::wstring& text) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string textStr = WStringToString(text);
    SetColor(CYAN);
    std::cout << "  [*] " << textStr << "\n";
    ResetColor();
}

void Console::PrintWarning(const std::wstring& text) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string textStr = WStringToString(text);
    SetColor(YELLOW);
    std::cout << "  [!] " << textStr << "\n";
    ResetColor();
}

void Console::PrintProgress(size_t current, size_t total, const std::wstring& name) {
    if (!logOutputEnabled) {
        return;
    }

    const double percent = static_cast<double>(current) / total * 100.0;
    constexpr int barWidth = 40;
    const int filled = static_cast<int>(barWidth * percent / 100.0);
    std::string nameStr = WStringToString(name);
    if (nameStr.length() > 25) {
        nameStr = nameStr.substr(0, 22) + "...";
    }

    SetColor(CYAN);
    std::cout << "\r  [";
    ResetColor();

    SetColor(GREEN);
    for (int i = 0; i < filled; i++) {
        std::cout << "=";
    }
    ResetColor();

    SetColor(DARK_GRAY);
    for (int i = filled; i < barWidth; i++) {
        std::cout << "-";
    }
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

void Console::PrintFound(const std::wstring& name, uintptr_t address, size_t regions, size_t bytes) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string nameStr = WStringToString(name);
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

void Console::PrintNotFound(const std::wstring& name, const std::string& error) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string nameStr = WStringToString(name);
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

void Console::PrintErrorMsg(const std::wstring& name, const std::string& error) {
    if (!logOutputEnabled) {
        return;
    }

    const std::string nameStr = WStringToString(name);
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

void Console::ClearLine() {
    if (!logOutputEnabled) {
        return;
    }

    std::cout << "\r" << std::string(180, ' ') << "\r";
}
