#pragma once

#include "ProcessMemoryReader.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct DumperStatus {
    std::string name;
    bool success = false;
    std::string error;
    size_t itemCount = 0;
};

struct ReadOnlyDumpOptions {
    std::filesystem::path outputDirectory = "dump";
    bool dumpSchemas = false;
    bool dumpInterfaces = false;
    bool dumpOffsets = false;
    bool dumpInfo = false;
};

struct ReadOnlyDumpReport {
    std::vector<DumperStatus> statuses;
    std::optional<std::uint32_t> buildNumber;
};

bool HasReadOnlyDumpWork(const ReadOnlyDumpOptions& options);
void RunReadOnlyDumpers(
    ProcessMemoryReader& process,
    const ReadOnlyDumpOptions& options,
    ReadOnlyDumpReport& report
);
