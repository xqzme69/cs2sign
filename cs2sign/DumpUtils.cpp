#include "DumpUtils.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

std::string EscapeJson(std::string_view value) {
    std::ostringstream escaped;

    for (unsigned char character : value) {
        switch (character) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (character <= 0x1f) {
                    escaped << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(character);
                } else {
                    escaped << static_cast<char>(character);
                }
        }
    }

    return escaped.str();
}

std::string FormatHex(std::uint64_t value, bool withPrefix) {
    std::ostringstream stream;
    if (withPrefix) {
        stream << "0x";
    }
    stream << std::uppercase << std::hex << value;
    return stream.str();
}

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int byteCount = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (byteCount <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(byteCount), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        byteCount,
        nullptr,
        nullptr
    );
    return result;
}

std::string CurrentTimestampUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm utcTime{};
    gmtime_s(&utcTime, &nowTime);

    std::ostringstream stream;
    stream << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return stream.str();
}

std::string SanitizeIdentifier(std::string value, std::string fallback) {
    if (value.empty()) {
        return fallback;
    }

    for (char& character : value) {
        const unsigned char byte = static_cast<unsigned char>(character);
        if (!std::isalnum(byte) && character != '_') {
            character = '_';
        }
    }

    if (value.empty() || std::isdigit(static_cast<unsigned char>(value.front()))) {
        value.insert(value.begin(), '_');
    }

    return value;
}

bool EnsureDirectory(const std::filesystem::path& directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    return !error && std::filesystem::is_directory(directory);
}

bool ParseIdaPattern(std::string_view pattern, std::vector<PatternByte>& bytes) {
    bytes.clear();

    std::istringstream stream{ std::string(pattern) };
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back({ 0, true });
            continue;
        }

        unsigned int value = 0;
        std::istringstream hexStream(token);
        hexStream >> std::hex >> value;
        if (hexStream.fail() || value > 0xff) {
            bytes.clear();
            return false;
        }

        bytes.push_back({ static_cast<std::uint8_t>(value), false });
    }

    return !bytes.empty();
}

std::optional<size_t> FindPattern(
    const std::vector<std::uint8_t>& buffer,
    const std::vector<PatternByte>& pattern
) {
    if (pattern.empty() || buffer.size() < pattern.size()) {
        return std::nullopt;
    }

    const size_t searchLimit = buffer.size() - pattern.size();
    for (size_t offset = 0; offset <= searchLimit; ++offset) {
        bool matched = true;
        for (size_t index = 0; index < pattern.size(); ++index) {
            if (!pattern[index].wildcard && buffer[offset + index] != pattern[index].value) {
                matched = false;
                break;
            }
        }

        if (matched) {
            return offset;
        }
    }

    return std::nullopt;
}

std::optional<std::uint32_t> ReadUInt32(const std::vector<std::uint8_t>& buffer, size_t offset) {
    if (offset + sizeof(std::uint32_t) > buffer.size()) {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    std::memcpy(&value, buffer.data() + offset, sizeof(value));
    return value;
}

std::optional<std::int32_t> ReadInt32(const std::vector<std::uint8_t>& buffer, size_t offset) {
    if (offset + sizeof(std::int32_t) > buffer.size()) {
        return std::nullopt;
    }

    std::int32_t value = 0;
    std::memcpy(&value, buffer.data() + offset, sizeof(value));
    return value;
}

std::optional<std::uint32_t> ResolveRipRelativeRva(
    const std::vector<std::uint8_t>& buffer,
    size_t instructionRva,
    size_t relOffset,
    size_t instructionLength
) {
    const auto displacement = ReadInt32(buffer, instructionRva + relOffset);
    if (!displacement) {
        return std::nullopt;
    }

    const std::int64_t target = static_cast<std::int64_t>(instructionRva) +
        static_cast<std::int64_t>(instructionLength) +
        *displacement;
    if (target < 0 || target > static_cast<std::int64_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(target);
}

bool ReadModuleImage(
    ProcessMemoryReader& process,
    const ProcessModule& module,
    std::vector<std::uint8_t>& image
) {
    if (module.base == 0 || module.size == 0) {
        image.clear();
        return false;
    }

    return process.ReadBuffer(module.base, module.size, image);
}

std::optional<std::uint32_t> FindExportRva(
    const std::vector<std::uint8_t>& image,
    std::string_view exportName
) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return std::nullopt;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < 0) {
        return std::nullopt;
    }

    const size_t ntOffset = static_cast<size_t>(dosHeader->e_lfanew);
    if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > image.size()) {
        return std::nullopt;
    }

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + ntOffset);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::nullopt;
    }

    const IMAGE_DATA_DIRECTORY& exportDirectory =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectory.VirtualAddress == 0 ||
        exportDirectory.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > image.size()) {
        return std::nullopt;
    }

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        image.data() + exportDirectory.VirtualAddress
    );

    if (exports->AddressOfNames == 0 ||
        exports->AddressOfNameOrdinals == 0 ||
        exports->AddressOfFunctions == 0) {
        return std::nullopt;
    }

    for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
        const size_t nameRvaOffset = static_cast<size_t>(exports->AddressOfNames) +
            index * sizeof(std::uint32_t);
        const auto nameRva = ReadUInt32(image, nameRvaOffset);
        if (!nameRva || *nameRva >= image.size()) {
            continue;
        }

        const char* name = reinterpret_cast<const char*>(image.data() + *nameRva);
        const size_t remaining = image.size() - *nameRva;
        const size_t nameLength = strnlen_s(name, remaining);
        if (nameLength == remaining || std::string_view(name, nameLength) != exportName) {
            continue;
        }

        const size_t ordinalOffset = static_cast<size_t>(exports->AddressOfNameOrdinals) +
            index * sizeof(std::uint16_t);
        if (ordinalOffset + sizeof(std::uint16_t) > image.size()) {
            continue;
        }

        std::uint16_t ordinal = 0;
        std::memcpy(&ordinal, image.data() + ordinalOffset, sizeof(ordinal));

        const size_t functionRvaOffset = static_cast<size_t>(exports->AddressOfFunctions) +
            ordinal * sizeof(std::uint32_t);
        return ReadUInt32(image, functionRvaOffset);
    }

    return std::nullopt;
}
