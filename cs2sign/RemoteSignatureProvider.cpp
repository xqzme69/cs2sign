#include "RemoteSignatureProvider.h"

#include <windows.h>
#include <urlmon.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {
struct RemoteSignatureFile {
    std::string name;
    std::string sha256;
};

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int requiredSize = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0
    );
    if (requiredSize <= 0) {
        return std::wstring(value.begin(), value.end());
    }

    std::wstring result(static_cast<size_t>(requiredSize), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        requiredSize
    );
    return result;
}

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool EndsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool IsSafeSignatureFilename(const std::string& name) {
    if (name.empty() || name == "cs2_signatures.json") {
        return false;
    }

    if (!EndsWith(name, "_signatures.json")) {
        return false;
    }

    for (const char character : name) {
        const bool safe =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '_' ||
            character == '-' ||
            character == '.';
        if (!safe) {
            return false;
        }
    }

    return true;
}

bool ReadTextFile(const std::filesystem::path& path, std::string& output) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::ostringstream stream;
    stream << file.rdbuf();
    output = stream.str();
    return true;
}

bool DownloadFile(const std::string& url, const std::filesystem::path& outputPath, std::string& error) {
    std::error_code errorCode;
    std::filesystem::create_directories(outputPath.parent_path(), errorCode);
    if (errorCode) {
        error = "failed to create cache directory: " + errorCode.message();
        return false;
    }

    const std::wstring wideUrl = Utf8ToWide(url);
    const std::wstring wideOutputPath = outputPath.wstring();
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool shouldUninitializeCom = SUCCEEDED(comResult);
    const HRESULT result = URLDownloadToFileW(
        nullptr,
        wideUrl.c_str(),
        wideOutputPath.c_str(),
        0,
        nullptr
    );
    if (shouldUninitializeCom) {
        CoUninitialize();
    }

    if (FAILED(result)) {
        std::ostringstream message;
        message << "download failed: 0x" << std::hex << std::uppercase << result;
        error = message.str();
        return false;
    }

    return true;
}

bool ParseJsonStringAt(const std::string& json, size_t& cursor, std::string& output) {
    if (cursor >= json.size() || json[cursor] != '"') {
        return false;
    }

    ++cursor;
    output.clear();
    while (cursor < json.size()) {
        const char character = json[cursor++];
        if (character == '"') {
            return true;
        }

        if (character == '\\' && cursor < json.size()) {
            const char escaped = json[cursor++];
            switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            default: output.push_back(escaped); break;
            }
        } else {
            output.push_back(character);
        }
    }

    return false;
}

bool FindStringValueInRange(
    const std::string& json,
    size_t begin,
    size_t end,
    const std::string& key,
    std::string& output
) {
    const std::string quotedKey = "\"" + key + "\"";
    size_t keyPosition = json.find(quotedKey, begin);
    if (keyPosition == std::string::npos || keyPosition >= end) {
        return false;
    }

    size_t colon = json.find(':', keyPosition + quotedKey.size());
    if (colon == std::string::npos || colon >= end) {
        return false;
    }

    size_t valuePosition = json.find('"', colon + 1);
    if (valuePosition == std::string::npos || valuePosition >= end) {
        return false;
    }

    return ParseJsonStringAt(json, valuePosition, output);
}

bool FindStringValue(const std::string& json, const std::string& key, std::string& output) {
    return FindStringValueInRange(json, 0, json.size(), key, output);
}

std::vector<RemoteSignatureFile> ParseManifestFiles(const std::string& manifestJson) {
    std::vector<RemoteSignatureFile> files;
    const size_t filesKey = manifestJson.find("\"files\"");
    if (filesKey == std::string::npos) {
        return files;
    }

    const size_t arrayBegin = manifestJson.find('[', filesKey);
    if (arrayBegin == std::string::npos) {
        return files;
    }

    size_t cursor = arrayBegin + 1;
    while (cursor < manifestJson.size()) {
        const size_t objectBegin = manifestJson.find('{', cursor);
        const size_t arrayEnd = manifestJson.find(']', cursor);
        if (objectBegin == std::string::npos || (arrayEnd != std::string::npos && arrayEnd < objectBegin)) {
            break;
        }

        const size_t objectEnd = manifestJson.find('}', objectBegin);
        if (objectEnd == std::string::npos) {
            break;
        }

        RemoteSignatureFile file;
        if (FindStringValueInRange(manifestJson, objectBegin, objectEnd, "name", file.name) &&
            FindStringValueInRange(manifestJson, objectBegin, objectEnd, "sha256", file.sha256) &&
            IsSafeSignatureFilename(file.name)) {
            file.sha256 = ToLowerAscii(file.sha256);
            files.push_back(file);
        }

        cursor = objectEnd + 1;
    }

    return files;
}

std::string DeriveBaseUrl(const std::string& manifestUrl) {
    const size_t slash = manifestUrl.find_last_of('/');
    if (slash == std::string::npos) {
        return {};
    }

    return manifestUrl.substr(0, slash + 1);
}

std::string BytesToHex(const std::uint8_t* bytes, size_t count) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (size_t index = 0; index < count; ++index) {
        stream << std::setw(2) << static_cast<int>(bytes[index]);
    }
    return stream.str();
}

bool CalculateSha256(const std::filesystem::path& path, std::string& output, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        error = "failed to open file for hashing: " + path.string();
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider failed";
        return false;
    }

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength),
        sizeof(objectLength),
        &resultLength,
        0
    );
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "BCryptGetProperty failed";
        return false;
    }

    std::vector<std::uint8_t> hashObject(objectLength);
    status = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "BCryptCreateHash failed";
        return false;
    }

    std::array<char, 64 * 1024> buffer{};
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        const std::streamsize bytesRead = file.gcount();
        if (bytesRead <= 0) {
            break;
        }

        status = BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(buffer.data()),
            static_cast<ULONG>(bytesRead),
            0
        );
        if (status < 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            error = "BCryptHashData failed";
            return false;
        }
    }

    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        error = "BCryptFinishHash failed";
        return false;
    }

    output = BytesToHex(digest.data(), digest.size());
    return true;
}

bool FileMatchesSha256(const std::filesystem::path& path, const std::string& expectedSha256) {
    if (expectedSha256.empty() || !std::filesystem::is_regular_file(path)) {
        return false;
    }

    std::string actualSha256;
    std::string error;
    return CalculateSha256(path, actualSha256, error) &&
           ToLowerAscii(actualSha256) == ToLowerAscii(expectedSha256);
}

std::string JoinUrl(const std::string& baseUrl, const std::string& fileName) {
    if (baseUrl.empty()) {
        return {};
    }

    if (baseUrl.back() == '/') {
        return baseUrl + fileName;
    }

    return baseUrl + "/" + fileName;
}
}

std::filesystem::path GetDefaultRemoteSignatureCacheDirectory() {
    wchar_t localAppData[MAX_PATH]{};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        return std::filesystem::path(localAppData) / L"cs2sign" / L"signatures";
    }

    wchar_t tempPath[MAX_PATH]{};
    const DWORD tempLength = GetTempPathW(MAX_PATH, tempPath);
    if (tempLength > 0 && tempLength < MAX_PATH) {
        return std::filesystem::path(tempPath) / L"cs2sign" / L"signatures";
    }

    return std::filesystem::path(L".") / L"cache" / L"signatures";
}

RemoteSignatureResult ResolveRemoteSignatureFiles(const RemoteSignatureOptions& options) {
    RemoteSignatureResult result;
    if (options.manifestUrl.empty()) {
        result.error = "remote signature manifest URL is empty";
        return result;
    }

    const std::filesystem::path cacheDirectory = options.cacheDirectory.empty()
        ? GetDefaultRemoteSignatureCacheDirectory()
        : options.cacheDirectory;
    const std::filesystem::path manifestPath = cacheDirectory / "index.json";

    std::string downloadError;
    if (!DownloadFile(options.manifestUrl, manifestPath, downloadError)) {
        result.error = "failed to download signature index: " + downloadError;
        return result;
    }

    std::string manifestJson;
    if (!ReadTextFile(manifestPath, manifestJson)) {
        result.error = "failed to read downloaded signature index";
        return result;
    }

    std::string baseUrl;
    if (!FindStringValue(manifestJson, "base_url", baseUrl) || baseUrl.empty()) {
        baseUrl = DeriveBaseUrl(options.manifestUrl);
    }

    const std::vector<RemoteSignatureFile> files = ParseManifestFiles(manifestJson);
    if (files.empty()) {
        result.error = "signature index does not contain any valid files";
        return result;
    }

    for (const RemoteSignatureFile& file : files) {
        const std::filesystem::path targetPath = cacheDirectory / file.name;
        if (!FileMatchesSha256(targetPath, file.sha256)) {
            const std::filesystem::path tempPath = targetPath.string() + ".download";
            std::error_code removeError;
            std::filesystem::remove(tempPath, removeError);

            const std::string fileUrl = JoinUrl(baseUrl, file.name);
            if (!DownloadFile(fileUrl, tempPath, downloadError)) {
                result.error = "failed to download " + file.name + ": " + downloadError;
                return result;
            }

            if (!FileMatchesSha256(tempPath, file.sha256)) {
                std::filesystem::remove(tempPath, removeError);
                result.error = "sha256 mismatch for " + file.name;
                return result;
            }

            std::filesystem::rename(tempPath, targetPath, removeError);
            if (removeError) {
                std::filesystem::copy_file(
                    tempPath,
                    targetPath,
                    std::filesystem::copy_options::overwrite_existing,
                    removeError
                );
                std::filesystem::remove(tempPath);
                if (removeError) {
                    result.error = "failed to update cache file " + file.name + ": " + removeError.message();
                    return result;
                }
            }
        }

        result.signatureFiles.push_back(targetPath.string());
    }

    result.success = true;
    return result;
}
