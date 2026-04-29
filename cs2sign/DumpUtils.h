#pragma once

#include "ProcessMemoryReader.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct PatternByte {
    std::uint8_t value = 0;
    bool wildcard = false;
};

std::string EscapeJson(std::string_view value);
std::string FormatHex(std::uint64_t value, bool withPrefix = true);
std::string ToLowerAscii(std::string value);
std::wstring Utf8ToWide(const std::string& value);
std::string WideToUtf8(const std::wstring& value);
std::string CurrentTimestampUtc();
std::string SanitizeIdentifier(std::string value, std::string fallback = "unnamed");
bool EndsWith(std::string_view value, std::string_view suffix);

bool EnsureDirectory(const std::filesystem::path& directory);
bool ParseIdaPattern(std::string_view pattern, std::vector<PatternByte>& bytes);
std::optional<size_t> FindPattern(const std::vector<std::uint8_t>& buffer, const std::vector<PatternByte>& pattern);
std::optional<std::uint32_t> ReadUInt32(const std::vector<std::uint8_t>& buffer, size_t offset);
std::optional<std::int32_t> ReadInt32(const std::vector<std::uint8_t>& buffer, size_t offset);
std::optional<std::uint32_t> ResolveRipRelativeRva(
    const std::vector<std::uint8_t>& buffer,
    size_t instructionRva,
    size_t relOffset,
    size_t instructionLength
);

bool ReadModuleImage(
    ProcessMemoryReader& process,
    const ProcessModule& module,
    std::vector<std::uint8_t>& image
);

std::optional<std::uint32_t> FindExportRva(
    const std::vector<std::uint8_t>& image,
    std::string_view exportName
);
