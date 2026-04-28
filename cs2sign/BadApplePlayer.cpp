#include "BadApplePlayer.h"

#include <windows.h>
#include <conio.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

namespace {
constexpr wchar_t kFrameResourceName[] = L"BAD_APPLE_FRAMES";
constexpr int kOverlayRows = 3;

std::uint16_t ReadU16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0] | (data[1] << 8));
}

std::uint32_t ReadU32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(
        data[0] |
        (data[1] << 8) |
        (data[2] << 16) |
        (data[3] << 24)
    );
}

void PutCenteredText(
    std::vector<CHAR_INFO>& cells,
    int width,
    int row,
    const char* text,
    WORD attributes
) {
    if (row < 0 || width <= 0) {
        return;
    }

    const int textLength = static_cast<int>(std::strlen(text));
    int column = (width - textLength) / 2;
    if (column < 0) {
        column = 0;
    }

    for (int index = 0; index < textLength && column + index < width; ++index) {
        CHAR_INFO& cell = cells[static_cast<size_t>(row * width + column + index)];
        cell.Char.AsciiChar = text[index];
        cell.Attributes = attributes;
    }
}

bool IsFilledAscii(char value) {
    return value != ' ' && value != '.' && value != '`' && value != '\'';
}

void EnsureConsoleArea(HANDLE outputHandle, int width, int height) {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(outputHandle, &info)) {
        return;
    }

    COORD size = info.dwSize;
    size.X = static_cast<SHORT>((std::max)(static_cast<int>(size.X), width));
    size.Y = static_cast<SHORT>((std::max)(static_cast<int>(size.Y), height));
    SetConsoleScreenBufferSize(outputHandle, size);
}
}

BadApplePlayer::~BadApplePlayer() {
    Stop();
}

void BadApplePlayer::Start() {
    bool expected = false;
    if (!isRunning_.compare_exchange_strong(expected, true)) {
        return;
    }

    stoppedByUser_ = false;
    workFinished_ = false;
    if (framePack_.frames.empty() && !LoadEmbeddedFramePack(framePack_)) {
        stoppedByUser_ = true;
        isRunning_ = false;
        return;
    }

    worker_ = std::thread(&BadApplePlayer::Run, this);
}

void BadApplePlayer::CompleteAndWait() {
    workFinished_ = true;

    if (worker_.joinable()) {
        worker_.join();
        ClearConsoleArea();
    }
}

void BadApplePlayer::Stop() {
    const bool hadWorker = worker_.joinable();
    isRunning_ = false;

    if (hadWorker) {
        worker_.join();
        ClearConsoleArea();
    }
}

bool BadApplePlayer::WasStoppedByUser() const {
    return stoppedByUser_.load();
}

bool BadApplePlayer::LoadEmbeddedFramePack(FramePack& framePack) {
    HRSRC resource = FindResourceW(nullptr, kFrameResourceName, RT_RCDATA);
    if (!resource) {
        return false;
    }

    HGLOBAL loadedResource = LoadResource(nullptr, resource);
    if (!loadedResource) {
        return false;
    }

    const auto* data = static_cast<const std::uint8_t*>(LockResource(loadedResource));
    const DWORD dataSize = SizeofResource(nullptr, resource);
    if (!data || dataSize < 16) {
        return false;
    }

    if (std::memcmp(data, "BAP2", 4) != 0) {
        return false;
    }

    const std::uint32_t frameCount = ReadU32(data + 4);
    const std::uint16_t width = ReadU16(data + 8);
    const std::uint16_t height = ReadU16(data + 10);
    const std::uint16_t fps = ReadU16(data + 12);
    if (frameCount == 0 || width == 0 || height == 0 || fps == 0) {
        return false;
    }

    const std::uint8_t* cursor = data + 16;
    const std::uint8_t* end = data + dataSize;

    FramePack parsed;
    parsed.width = width;
    parsed.height = height;
    parsed.fps = fps;
    parsed.frames.reserve(frameCount);

    for (std::uint32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
        if (cursor + 4 > end) {
            return false;
        }

        const std::uint32_t compressedLength = ReadU32(cursor);
        cursor += 4;
        if (cursor + compressedLength > end) {
            return false;
        }

        const size_t expectedFrameSize = static_cast<size_t>(width) * height;
        std::string frame;
        frame.reserve(expectedFrameSize);
        const std::uint8_t* frameCursor = cursor;
        const std::uint8_t* frameEnd = cursor + compressedLength;
        while (frameCursor + 2 <= frameEnd && frame.size() < expectedFrameSize) {
            const std::uint8_t count = frameCursor[0];
            const char value = static_cast<char>(frameCursor[1]);
            frameCursor += 2;

            for (std::uint8_t repeat = 0; repeat < count; ++repeat) {
                if (value == '\n') {
                    continue;
                }

                frame.push_back(value);
                if (frame.size() == expectedFrameSize) {
                    break;
                }
            }
        }

        if (frame.size() < expectedFrameSize) {
            frame.append(expectedFrameSize - frame.size(), ' ');
        }

        parsed.frames.push_back(std::move(frame));
        cursor += compressedLength;
    }

    framePack = std::move(parsed);
    return true;
}

void BadApplePlayer::Run() {
    outputHandle_ = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    if (outputHandle == INVALID_HANDLE_VALUE || outputHandle == nullptr) {
        return;
    }

    DWORD consoleMode = 0;
    if (GetConsoleMode(outputHandle, &consoleMode) == 0) {
        return;
    }

    HideCursor();
    EnsureConsoleArea(outputHandle, framePack_.width, framePack_.height + kOverlayRows);

    const auto frameDuration = std::chrono::milliseconds(1000 / framePack_.fps);
    size_t frameIndex = 0;
    int loopCount = 0;
    bool wasWorkFinished = false;

    while (isRunning_.load()) {
        const bool workFinished = workFinished_.load();
        if (workFinished && !wasWorkFinished) {
            DrainKeyboardInput();
            wasWorkFinished = true;
        }

        if (workFinished) {
            if (ShouldShowResultsFromKeyboard()) {
                isRunning_ = false;
                break;
            }
        } else if (ShouldStopFromKeyboard()) {
            stoppedByUser_ = true;
            isRunning_ = false;
            break;
        }

        RenderFrame(framePack_.frames[frameIndex], loopCount, workFinished);
        frameIndex = (frameIndex + 1) % framePack_.frames.size();
        if (frameIndex == 0) {
            ++loopCount;
        }

        const auto sleepUntil = std::chrono::steady_clock::now() + frameDuration;
        while (isRunning_.load() && std::chrono::steady_clock::now() < sleepUntil) {
            if (workFinished_.load()) {
                if (ShouldShowResultsFromKeyboard()) {
                    isRunning_ = false;
                    break;
                }
            } else if (ShouldStopFromKeyboard()) {
                stoppedByUser_ = true;
                isRunning_ = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    if (stoppedByUser_.load() && !workFinished_.load()) {
        RenderStatusScreen(
            "BAD APPLE STOPPED",
            "Work is still running. Final summary will appear automatically."
        );
    }

    RestoreCursor();
}

void BadApplePlayer::RenderFrame(const std::string& frame, int loopCount, bool workFinished) const {
    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    const int width = framePack_.width;
    const int height = framePack_.height + kOverlayRows;

    std::vector<CHAR_INFO> cells(static_cast<size_t>(width) * height);
    const WORD dark = FOREGROUND_INTENSITY;
    const WORD bright = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD accent = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

    for (int row = 0; row < framePack_.height; ++row) {
        for (int column = 0; column < width; ++column) {
            const size_t index = static_cast<size_t>(row * width + column);
            const char value = index < frame.size() ? frame[index] : ' ';
            CHAR_INFO& cell = cells[index];
            cell.Char.AsciiChar = value;
            cell.Attributes = IsFilledAscii(value) ? bright : dark;
        }
    }

    const int firstOverlayRow = framePack_.height;
    for (int row = firstOverlayRow; row < height; ++row) {
        for (int column = 0; column < width; ++column) {
            CHAR_INFO& cell = cells[static_cast<size_t>(row * width + column)];
            cell.Char.AsciiChar = ' ';
            cell.Attributes = accent;
        }
    }

    PutCenteredText(
        cells,
        width,
        firstOverlayRow,
        workFinished
            ? "Dump ready - press Space to view results"
            : "Bad Apple mode - logs hidden while cs2sign is working",
        workFinished ? bright : accent
    );

    char controls[128]{};
    std::snprintf(
        controls,
        sizeof(controls),
        workFinished
            ? "Animation keeps looping until you press Space  |  loop %d"
            : "Press Q / Esc / Enter / Space to stop animation only  |  loop %d",
        loopCount + 1
    );
    PutCenteredText(cells, width, firstOverlayRow + 1, controls, bright);
    PutCenteredText(
        cells,
        width,
        firstOverlayRow + 2,
        workFinished
            ? "Results are ready and files were written"
            : "Dump result will be shown when work is done",
        accent
    );

    SMALL_RECT region{
        0,
        0,
        static_cast<SHORT>(width - 1),
        static_cast<SHORT>(height - 1)
    };
    COORD bufferSize{static_cast<SHORT>(width), static_cast<SHORT>(height)};
    COORD bufferCoord{0, 0};
    WriteConsoleOutputA(outputHandle, cells.data(), bufferSize, bufferCoord, &region);
}

void BadApplePlayer::RenderStatusScreen(const char* title, const char* message) const {
    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    const int width = framePack_.width > 0 ? framePack_.width : 100;
    const int height = framePack_.height > 0 ? framePack_.height + kOverlayRows : 44;
    std::vector<CHAR_INFO> cells(static_cast<size_t>(width) * height);
    const WORD accent = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD bright = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

    for (CHAR_INFO& cell : cells) {
        cell.Char.AsciiChar = ' ';
        cell.Attributes = accent;
    }

    PutCenteredText(cells, width, height / 2 - 1, title, bright);
    PutCenteredText(cells, width, height / 2 + 1, message, accent);

    SMALL_RECT region{
        0,
        0,
        static_cast<SHORT>(width - 1),
        static_cast<SHORT>(height - 1)
    };
    COORD bufferSize{static_cast<SHORT>(width), static_cast<SHORT>(height)};
    COORD bufferCoord{0, 0};
    WriteConsoleOutputA(outputHandle, cells.data(), bufferSize, bufferCoord, &region);
}

void BadApplePlayer::ClearConsoleArea() const {
    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    if (outputHandle == INVALID_HANDLE_VALUE || outputHandle == nullptr) {
        return;
    }

    const int width = framePack_.width > 0 ? framePack_.width : 100;
    const int height = framePack_.height > 0 ? framePack_.height + kOverlayRows : 44;
    std::vector<CHAR_INFO> cells(static_cast<size_t>(width) * height);
    const WORD attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    for (CHAR_INFO& cell : cells) {
        cell.Char.AsciiChar = ' ';
        cell.Attributes = attributes;
    }

    SMALL_RECT region{
        0,
        0,
        static_cast<SHORT>(width - 1),
        static_cast<SHORT>(height - 1)
    };
    COORD bufferSize{static_cast<SHORT>(width), static_cast<SHORT>(height)};
    COORD bufferCoord{0, 0};
    WriteConsoleOutputA(outputHandle, cells.data(), bufferSize, bufferCoord, &region);
    SetConsoleCursorPosition(outputHandle, {0, 0});
}

void BadApplePlayer::HideCursor() {
    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    CONSOLE_CURSOR_INFO cursorInfo{};
    if (!GetConsoleCursorInfo(outputHandle, &cursorInfo)) {
        return;
    }

    originalCursorSize_ = cursorInfo.dwSize;
    originalCursorVisible_ = cursorInfo.bVisible != FALSE;
    hasOriginalCursorInfo_ = true;

    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(outputHandle, &cursorInfo);
}

void BadApplePlayer::RestoreCursor() {
    if (!hasOriginalCursorInfo_) {
        return;
    }

    HANDLE outputHandle = static_cast<HANDLE>(outputHandle_);
    CONSOLE_CURSOR_INFO cursorInfo{};
    cursorInfo.dwSize = originalCursorSize_;
    cursorInfo.bVisible = originalCursorVisible_ ? TRUE : FALSE;
    SetConsoleCursorInfo(outputHandle, &cursorInfo);
}

void BadApplePlayer::DrainKeyboardInput() {
    while (_kbhit()) {
        (void)_getch();
    }
}

bool BadApplePlayer::ShouldStopFromKeyboard() {
    if (!_kbhit()) {
        return false;
    }

    const int key = _getch();
    return key == 'q' || key == 'Q' || key == 27 || key == '\r' || key == ' ';
}

bool BadApplePlayer::ShouldShowResultsFromKeyboard() {
    if (!_kbhit()) {
        return false;
    }

    const int key = _getch();
    return key == ' ';
}
