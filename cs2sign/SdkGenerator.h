#pragma once

#include <filesystem>
#include <string>

struct SdkGenerationOptions {
    std::filesystem::path schemaDirectory = "dump/schemas";
    std::filesystem::path outputDirectory = "dump/sdk";
    bool emitCpp = true;
    bool emitIda = true;
};

struct SdkGenerationReport {
    bool success = false;
    std::string error;
    std::filesystem::path cppDirectory;
    std::filesystem::path idaHeader;
    size_t moduleCount = 0;
    size_t classCount = 0;
    size_t enumCount = 0;
    size_t cppFileCount = 0;
};

SdkGenerationReport GenerateSdkFromSchemas(const SdkGenerationOptions& options);
