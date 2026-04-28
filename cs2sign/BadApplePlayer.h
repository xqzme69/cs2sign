#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <vector>

class BadApplePlayer {
public:
    BadApplePlayer() = default;
    BadApplePlayer(const BadApplePlayer&) = delete;
    BadApplePlayer& operator=(const BadApplePlayer&) = delete;
    ~BadApplePlayer();

    void Start();
    void CompleteAndWait();
    void Stop();
    bool WasStoppedByUser() const;

private:
    struct FramePack {
        std::vector<std::string> frames;
        int width = 0;
        int height = 0;
        int fps = 30;
    };

    static bool LoadEmbeddedFramePack(FramePack& framePack);
    void Run();
    void RenderFrame(const std::string& frame, int loopCount, bool workFinished) const;
    void RenderStatusScreen(const char* title, const char* message) const;
    void ClearConsoleArea() const;
    void HideCursor();
    void RestoreCursor();
    void DrainKeyboardInput();
    bool ShouldStopFromKeyboard();
    bool ShouldShowResultsFromKeyboard();

    std::atomic<bool> isRunning_{false};
    std::atomic<bool> workFinished_{false};
    std::atomic<bool> stoppedByUser_{false};
    std::thread worker_;
    FramePack framePack_;
    void* outputHandle_ = nullptr;
    unsigned long originalCursorSize_ = 25;
    bool originalCursorVisible_ = true;
    bool hasOriginalCursorInfo_ = false;
};
