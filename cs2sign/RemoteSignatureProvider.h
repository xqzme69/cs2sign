#pragma once

#include <filesystem>
#include <string>
#include <vector>

struct RemoteSignatureOptions {
    std::string manifestUrl;
    std::filesystem::path cacheDirectory;
};

struct RemoteSignatureResult {
    bool success = false;
    std::string error;
    std::vector<std::string> signatureFiles;
};

std::filesystem::path GetDefaultRemoteSignatureCacheDirectory();
RemoteSignatureResult ResolveRemoteSignatureFiles(const RemoteSignatureOptions& options);
