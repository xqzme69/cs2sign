#include "SignatureScanner.h"

#include "Console.h"
#include "DumpUtils.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace {
bool IsExecutableRegion(const MemoryRegion& region) {
    return region.protect == PAGE_EXECUTE_READ ||
           region.protect == PAGE_EXECUTE_READWRITE ||
           region.protect == PAGE_EXECUTE_WRITECOPY;
}

bool IsReadableRegionForScan(const MemoryRegion& region) {
    return region.protect == PAGE_EXECUTE_READ ||
           region.protect == PAGE_EXECUTE_READWRITE ||
           region.protect == PAGE_EXECUTE_WRITECOPY ||
           region.protect == PAGE_READONLY ||
           region.protect == PAGE_READWRITE ||
           region.protect == PAGE_WRITECOPY;
}

bool RegionBelongsToSignatureModule(const MemoryRegion& region, const Signature& signature) {
    if (signature.module.empty()) {
        return true;
    }

    if (region.module.empty()) {
        return true;
    }

    const std::string targetModule = ToLowerAscii(signature.module + ".dll");
    const std::string regionModulePath = ToLowerAscii(region.module);
    return regionModulePath.find(targetModule) != std::string::npos;
}

size_t DetermineWorkerThreadCount() {
    size_t workerThreadCount = (std::max)(1u, std::thread::hardware_concurrency());
    if (workerThreadCount > 8) {
        workerThreadCount = 8;
    }
    return workerThreadCount;
}

uintptr_t ApplyAddressOffset(uintptr_t address, intptr_t offset) {
    if (offset < 0) {
        return address - static_cast<uintptr_t>(-offset);
    }

    return address + static_cast<uintptr_t>(offset);
}

uintptr_t ApplySignedOffset(uintptr_t address, std::int64_t offset) {
    if (offset < 0) {
        return address - static_cast<uintptr_t>(-offset);
    }

    return address + static_cast<uintptr_t>(offset);
}

std::string EffectiveImportance(const Signature& signature) {
    if (!signature.importance.empty()) {
        return signature.importance;
    }

    return signature.required ? "required" : "optional";
}

std::string SignatureStatus(const Signature& signature) {
    if (signature.found) {
        return "found";
    }

    return signature.required ? "missing" : "optional_missing";
}

bool BuildPatternStrings(
    const std::vector<PatternByte>& pattern,
    std::string& outBytes,
    std::string& outMask
) {
    outBytes.clear();
    outMask.clear();

    if (pattern.empty()) {
        return false;
    }

    for (const PatternByte& byte : pattern) {
        outBytes.push_back(static_cast<char>(byte.value));
        outMask.push_back(byte.wildcard ? '?' : 'x');
    }

    return true;
}

bool CompileMaskedPattern(
    const std::string& bytes,
    const std::string& mask,
    std::vector<PatternByte>& pattern
) {
    pattern.clear();

    if (bytes.empty() || bytes.size() != mask.size()) {
        return false;
    }

    pattern.reserve(bytes.size());
    for (size_t index = 0; index < bytes.size(); ++index) {
        pattern.push_back({
            static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[index])),
            mask[index] == '?'
        });
    }

    return true;
}

bool ReadSignedOperand(
    ProcessMemoryReader& memory,
    uintptr_t address,
    int size,
    std::int64_t& value
) {
    switch (size) {
        case 1: {
            std::int8_t readValue = 0;
            if (!memory.Read(address, readValue)) {
                return false;
            }
            value = readValue;
            return true;
        }
        case 2: {
            std::int16_t readValue = 0;
            if (!memory.Read(address, readValue)) {
                return false;
            }
            value = readValue;
            return true;
        }
        case 4: {
            std::int32_t readValue = 0;
            if (!memory.Read(address, readValue)) {
                return false;
            }
            value = readValue;
            return true;
        }
        case 8: {
            std::int64_t readValue = 0;
            if (!memory.Read(address, readValue)) {
                return false;
            }
            value = readValue;
            return true;
        }
        default:
            return false;
    }
}

std::string EffectiveResultType(const Signature& signature) {
    if (!signature.resultType.empty()) {
        return ToLowerAscii(signature.resultType);
    }

    if (!signature.resolver.resultType.empty()) {
        return ToLowerAscii(signature.resolver.resultType);
    }

    const std::string resolverType = ToLowerAscii(signature.resolver.type);
    if (resolverType == "instruction_displacement") {
        return "field_offset";
    }
    if (resolverType == "rip_relative") {
        return "absolute_address";
    }
    if (!signature.rva.empty()) {
        return "function_address";
    }
    return "absolute_address";
}

void WriteResolverJSON(std::ofstream& file, const SignatureResolver& resolver) {
    if (!resolver.enabled && resolver.type.empty()) {
        return;
    }

    file << "      \"resolver\": {\n";

    bool wrote = false;
    const auto nextField = [&]() {
        if (wrote) {
            file << ",\n";
        }
        wrote = true;
    };
    const auto writeString = [&](const char* key, const std::string& value) {
        if (value.empty()) {
            return;
        }
        nextField();
        file << "        \"" << key << "\": \"" << EscapeJson(value) << "\"";
    };
    const auto writeInt = [&](const char* key, std::int64_t value) {
        nextField();
        file << "        \"" << key << "\": " << value;
    };

    writeString("type", resolver.type);
    writeString("result_type", resolver.resultType);
    if (resolver.hasInstructionOffset) writeInt("instruction_offset", resolver.instructionOffset);
    if (resolver.hasInstructionSize) writeInt("instruction_size", resolver.instructionSize);
    if (resolver.hasOperandIndex) writeInt("operand_index", resolver.operandIndex);
    if (resolver.hasOperandOffset) writeInt("operand_offset", resolver.operandOffset);
    if (resolver.hasOperandSize) writeInt("operand_size", resolver.operandSize);
    if (resolver.hasAdd) writeInt("add", resolver.add);
    if (resolver.hasExpected) writeInt("expected", resolver.expected);
    writeString("target_rva", resolver.targetRva);
    writeString("formula", resolver.formula);

    file << "\n      },\n";
}
}

SignatureScanner::SignatureScanner(ProcessMemoryReader& memory)
    : m_memory(memory), m_jsonFilename("cs2_signatures.json") {
}

SignatureScanner::~SignatureScanner() {
}

void SignatureScanner::AddSignature(
    const std::string& name,
    const std::string& pattern,
    const std::string& mask,
    intptr_t offset
) {
    Signature signature;
    signature.name = name;
    signature.pattern = pattern;
    signature.mask = mask;
    CompileMaskedPattern(signature.pattern, signature.mask, signature.compiledPattern);
    signature.addressOffset = offset;
    signature.confidence = 0;
    signature.sourceCount = 0;
    signature.required = true;
    signature.matchAddress = 0;
    signature.resolvedAddress = 0;
    signature.moduleRva = 0;
    signature.hasModuleRva = false;
    signature.resolverStatus = "not_applicable";
    signature.found = false;
    signature.error.clear();
    signature.regionsScanned = 0;
    signature.bytesScanned = 0;
    m_signatures.push_back(signature);
}

void SignatureScanner::AddSignature(
    const std::string& name,
    const char* pattern,
    size_t patternLen,
    const std::string& mask,
    intptr_t offset
) {
    Signature signature;
    signature.name = name;
    signature.pattern = std::string(pattern, patternLen);
    signature.mask = mask;
    CompileMaskedPattern(signature.pattern, signature.mask, signature.compiledPattern);
    signature.addressOffset = offset;
    signature.confidence = 0;
    signature.sourceCount = 0;
    signature.required = true;
    signature.matchAddress = 0;
    signature.resolvedAddress = 0;
    signature.moduleRva = 0;
    signature.hasModuleRva = false;
    signature.resolverStatus = "not_applicable";
    signature.found = false;
    signature.error.clear();
    signature.regionsScanned = 0;
    signature.bytesScanned = 0;
    m_signatures.push_back(signature);
}

bool SignatureScanner::ParseIDAPattern(
    const std::string& idaPattern,
    std::string& outBytes,
    std::string& outMask
) {
    std::vector<PatternByte> pattern;
    return ParseIdaPattern(idaPattern, pattern) &&
           BuildPatternStrings(pattern, outBytes, outMask);
}

void SignatureScanner::AddSignatureFromIDA(
    const std::string& name,
    const std::string& idaPattern,
    const std::string& module,
    const std::string& rva,
    intptr_t addressOffset,
    const std::string& category,
    const std::string& quality,
    const std::string& importance,
    int confidence,
    int sourceCount,
    const std::string& source,
    const std::string& sourceProject,
    const std::string& sourceUrl,
    bool required,
    const SignatureResolver& resolver,
    const std::string& resultType
) {
    std::string patternBytes;
    std::string patternMask;
    std::vector<PatternByte> compiledPattern;
    if (!ParseIdaPattern(idaPattern, compiledPattern) ||
        !BuildPatternStrings(compiledPattern, patternBytes, patternMask)) {
        return;
    }

    Signature signature;
    signature.name = name;
    signature.pattern = patternBytes;
    signature.mask = patternMask;
    signature.compiledPattern = std::move(compiledPattern);
    signature.module = module;
    signature.rva = rva;
    signature.category = category;
    signature.quality = quality;
    signature.importance = importance;
    signature.source = source;
    signature.sourceProject = sourceProject;
    signature.sourceUrl = sourceUrl;
    signature.resultType = resultType;
    signature.resolver = resolver;
    signature.addressOffset = addressOffset;
    signature.confidence = confidence;
    signature.sourceCount = sourceCount;
    signature.required = required;
    signature.matchAddress = 0;
    signature.resolvedAddress = 0;
    signature.moduleRva = 0;
    signature.hasModuleRva = false;
    signature.resolverStatus = "not_applicable";
    signature.found = false;
    signature.error.clear();
    signature.regionsScanned = 0;
    signature.bytesScanned = 0;
    m_signatures.push_back(signature);
}

void SignatureScanner::ScanAll() {
    if (!m_memory.IsValid()) {
        std::wcout << L"Memory not attached!" << std::endl;
        return;
    }

    UpdateJSONFile();

    const std::vector<MemoryRegion> candidateRegions = BuildCandidateRegions();
    const size_t workerThreadCount = DetermineWorkerThreadCount();

    for (size_t signatureIndex = 0; signatureIndex < m_signatures.size(); ++signatureIndex) {
        Signature& signature = m_signatures[signatureIndex];
        const std::wstring displayName(signature.name.begin(), signature.name.end());

        ResetSignatureState(signature);

        if (!ValidateSignaturePattern(signature)) {
            Console::ClearLine();
            Console::PrintErrorMsg(displayName, signature.error);
            UpdateJSONFile();
            continue;
        }

        Console::PrintProgress(signatureIndex + 1, m_signatures.size(), displayName);

        const std::vector<MemoryRegion> scanRegions =
            SelectRegionsForSignature(signature, candidateRegions);
        if (scanRegions.empty()) {
            signature.error = "No suitable memory regions";
            Console::ClearLine();
            Console::PrintNotFound(displayName, signature.error);
            UpdateJSONFile();
            continue;
        }

        const SignatureScanOutcome outcome =
            ScanSignatureRegions(signature, scanRegions, workerThreadCount);

        if (outcome.found) {
            RecordFoundSignature(signature, outcome);
            Console::ClearLine();
            if (signature.found) {
                Console::PrintFound(
                    displayName,
                    signature.resolvedAddress,
                    signature.regionsScanned,
                    signature.bytesScanned
                );
            } else {
                Console::PrintNotFound(displayName, signature.error);
            }
        } else {
            RecordMissingSignature(signature, outcome);
            Console::ClearLine();
            Console::PrintNotFound(displayName, signature.error);
        }

        UpdateJSONFile();
    }

    Console::ClearLine();
    UpdateJSONFile();
    Console::PrintSuccess(
        L"Scan complete! Results saved to: " +
        std::wstring(m_jsonFilename.begin(), m_jsonFilename.end())
    );
}

void SignatureScanner::ResetSignatureState(Signature& signature) {
    signature.found = false;
    signature.matchAddress = 0;
    signature.resolvedAddress = 0;
    signature.moduleRva = 0;
    signature.hasModuleRva = false;
    signature.resolverStatus = signature.resolver.enabled ? "pending" : "not_applicable";
    signature.error.clear();
    signature.regionsScanned = 0;
    signature.bytesScanned = 0;
}

bool SignatureScanner::ValidateSignaturePattern(Signature& signature) {
    const size_t patternLength = signature.pattern.size();
    if (patternLength != signature.mask.length()) {
        std::ostringstream errorMessage;
        errorMessage << "Pattern and mask length mismatch ("
                     << patternLength << " bytes vs "
                     << signature.mask.length() << " mask chars)";
        signature.error = errorMessage.str();
        return false;
    }

    if (signature.pattern.empty()) {
        signature.error = "Empty pattern";
        return false;
    }

    if (signature.compiledPattern.empty() &&
        !CompileMaskedPattern(signature.pattern, signature.mask, signature.compiledPattern)) {
        signature.error = "Invalid compiled pattern";
        return false;
    }

    if (signature.compiledPattern.size() != patternLength) {
        signature.error = "Compiled pattern length mismatch";
        return false;
    }

    return true;
}

std::vector<MemoryRegion> SignatureScanner::BuildCandidateRegions() {
    std::vector<MemoryRegion> candidateRegions;
    const std::vector<MemoryRegion> processRegions = m_memory.GetMemoryRegions();

    for (const auto& region : processRegions) {
        if (region.size >= 16 && IsReadableRegionForScan(region)) {
            candidateRegions.push_back(region);
        }
    }

    std::sort(candidateRegions.begin(), candidateRegions.end(), [](const MemoryRegion& left, const MemoryRegion& right) {
        const bool leftExecutable = IsExecutableRegion(left);
        const bool rightExecutable = IsExecutableRegion(right);
        if (leftExecutable != rightExecutable) {
            return leftExecutable;
        }
        return left.size < right.size;
    });

    return candidateRegions;
}

std::vector<MemoryRegion> SignatureScanner::SelectRegionsForSignature(
    const Signature& signature,
    const std::vector<MemoryRegion>& candidateRegions
) {
    std::vector<MemoryRegion> scanRegions;
    const size_t patternLength = signature.compiledPattern.empty()
        ? signature.pattern.size()
        : signature.compiledPattern.size();

    for (const auto& region : candidateRegions) {
        if (region.size < patternLength) {
            continue;
        }

        if (!RegionBelongsToSignatureModule(region, signature)) {
            continue;
        }

        scanRegions.push_back(region);
    }

    return scanRegions;
}

SignatureScanner::SignatureScanOutcome SignatureScanner::ScanSignatureRegions(
    const Signature& signature,
    const std::vector<MemoryRegion>& scanRegions,
    size_t workerThreadCount
) {
    std::atomic<bool> wasFound(false);
    std::atomic<uintptr_t> foundAddress(0);
    std::atomic<size_t> regionsScanned(0);
    std::atomic<size_t> bytesScanned(0);
    std::vector<std::thread> workers;

    for (size_t workerIndex = 0; workerIndex < workerThreadCount; ++workerIndex) {
        workers.emplace_back([&, workerIndex]() {
            for (size_t regionIndex = workerIndex;
                 regionIndex < scanRegions.size() && !wasFound.load();
                 regionIndex += workerThreadCount) {
                const MemoryRegion& region = scanRegions[regionIndex];
                ++regionsScanned;
                bytesScanned += region.size;

                std::string scanError;
                const uintptr_t matchAddress = ScanPatternOptimized(
                    region.base,
                    region.size,
                    signature.compiledPattern,
                    scanError
                );

                if (matchAddress != 0) {
                    foundAddress = matchAddress;
                    wasFound = true;
                    break;
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    SignatureScanOutcome outcome;
    outcome.found = wasFound.load();
    outcome.address = foundAddress.load();
    outcome.regionsScanned = regionsScanned.load();
    outcome.bytesScanned = bytesScanned.load();
    return outcome;
}

void SignatureScanner::RecordFoundSignature(Signature& signature, const SignatureScanOutcome& outcome) {
    signature.matchAddress = outcome.address;
    signature.regionsScanned = outcome.regionsScanned;
    signature.bytesScanned = outcome.bytesScanned;

    if (!ResolveSignatureAddress(signature, outcome.address)) {
        signature.found = false;
        signature.resolvedAddress = 0;
        signature.moduleRva = 0;
        signature.hasModuleRva = false;
        return;
    }

    signature.found = true;
    signature.error.clear();
}

void SignatureScanner::RecordMissingSignature(Signature& signature, const SignatureScanOutcome& outcome) {
    signature.found = false;
    signature.matchAddress = 0;
    signature.resolvedAddress = 0;
    signature.moduleRva = 0;
    signature.hasModuleRva = false;
    signature.resolverStatus = "not_found";
    signature.regionsScanned = outcome.regionsScanned;
    signature.bytesScanned = outcome.bytesScanned;

    std::ostringstream errorMessage;
    errorMessage << "Not found after " << signature.regionsScanned << " regions";
    signature.error = errorMessage.str();
}

bool SignatureScanner::ResolveSignatureAddress(Signature& signature, uintptr_t matchAddress) {
    const auto updateModuleRva = [&]() {
        signature.moduleRva = 0;
        signature.hasModuleRva = false;

        const std::string resultType = EffectiveResultType(signature);
        if (resultType == "field_offset" || signature.module.empty() || signature.resolvedAddress == 0) {
            return;
        }

        std::string moduleName = signature.module;
        const std::string lowerModuleName = ToLowerAscii(moduleName);
        if (lowerModuleName.size() < 4 || lowerModuleName.substr(lowerModuleName.size() - 4) != ".dll") {
            moduleName += ".dll";
        }

        ProcessModule module{};
        if (!m_memory.GetModuleInfo(Utf8ToWide(moduleName), module)) {
            return;
        }

        const uintptr_t moduleEnd = module.base + module.size;
        if (signature.resolvedAddress < module.base || signature.resolvedAddress >= moduleEnd) {
            return;
        }

        signature.moduleRva = static_cast<std::uint32_t>(signature.resolvedAddress - module.base);
        signature.hasModuleRva = true;
    };

    const std::string resolverType = ToLowerAscii(signature.resolver.type);
    if (!signature.resolver.enabled || resolverType.empty() || resolverType == "direct_match") {
        signature.resolvedAddress = ApplyAddressOffset(matchAddress, signature.addressOffset);
        signature.resolverStatus = signature.resolver.enabled ? "resolved" : "not_applicable";
        updateModuleRva();
        signature.error.clear();
        return true;
    }

    if (!signature.resolver.hasOperandOffset || signature.resolver.operandOffset < 0) {
        signature.resolverStatus = "failed";
        signature.error = "Resolver missing operand_offset";
        return false;
    }

    const int instructionOffset = signature.resolver.hasInstructionOffset
        ? signature.resolver.instructionOffset
        : 0;
    if (instructionOffset < 0) {
        signature.resolverStatus = "failed";
        signature.error = "Resolver has negative instruction_offset";
        return false;
    }

    const int operandSize = signature.resolver.hasOperandSize
        ? signature.resolver.operandSize
        : 4;

    std::int64_t operandValue = 0;
    const uintptr_t operandAddress =
        matchAddress +
        static_cast<uintptr_t>(instructionOffset) +
        static_cast<uintptr_t>(signature.resolver.operandOffset);
    if (!ReadSignedOperand(m_memory, operandAddress, operandSize, operandValue)) {
        std::ostringstream errorMessage;
        errorMessage << "Failed to read resolver operand at 0x"
                     << std::hex << std::uppercase << operandAddress;
        signature.resolverStatus = "failed";
        signature.error = errorMessage.str();
        return false;
    }

    if (resolverType == "rip_relative") {
        const std::int64_t addValue = signature.resolver.hasAdd
            ? signature.resolver.add
            : signature.resolver.instructionSize;
        const uintptr_t instructionAddress =
            matchAddress + static_cast<uintptr_t>(instructionOffset);
        signature.resolvedAddress = ApplySignedOffset(
            ApplySignedOffset(instructionAddress, addValue),
            operandValue
        );
        signature.resolverStatus = "resolved";
        updateModuleRva();
        signature.error.clear();
        return true;
    }

    if (resolverType == "instruction_displacement") {
        if (operandValue < 0) {
            signature.resolverStatus = "failed";
            signature.error = "Resolver produced a negative displacement";
            return false;
        }
        signature.resolvedAddress = static_cast<uintptr_t>(operandValue);
        signature.resolverStatus = "resolved";
        signature.moduleRva = 0;
        signature.hasModuleRva = false;
        signature.error.clear();
        return true;
    }

    signature.resolverStatus = "failed";
    signature.error = "Unknown resolver type: " + signature.resolver.type;
    return false;
}

uintptr_t SignatureScanner::ScanPattern(
    uintptr_t start,
    size_t size,
    const std::vector<PatternByte>& pattern,
    std::string& error
) {
    return ScanPatternOptimized(start, size, pattern, error);
}

uintptr_t SignatureScanner::ScanPatternOptimized(
    uintptr_t start,
    size_t size,
    const std::vector<PatternByte>& pattern,
    std::string& error
) {
    const size_t patternLength = pattern.size();
    if (patternLength == 0) {
        error = "Invalid pattern";
        return 0;
    }

    if (size < patternLength) {
        return 0;
    }

    constexpr size_t maxChunkSize = 4 * 1024 * 1024;
    const size_t chunkSize = (size > maxChunkSize) ? maxChunkSize : size;

    const uint8_t firstByte = pattern[0].value;
    const bool firstByteIsWildcard = pattern[0].wildcard;

    const uint8_t secondByte = (patternLength > 1) ? pattern[1].value : 0;
    const bool secondByteIsWildcard = (patternLength > 1 && pattern[1].wildcard);

    std::vector<uint8_t> buffer(chunkSize);

    for (size_t regionOffset = 0;
         regionOffset <= size - patternLength;
         regionOffset += chunkSize - patternLength + 1) {
        const size_t readSize = (regionOffset + chunkSize > size)
            ? (size - regionOffset)
            : chunkSize;
        if (readSize < patternLength) {
            break;
        }

        if (!m_memory.ReadMemory(start + regionOffset, buffer.data(), readSize)) {
            continue;
        }

        const size_t searchLength = readSize - patternLength + 1;
        for (size_t bufferOffset = 0; bufferOffset < searchLength; ++bufferOffset) {
            if (!firstByteIsWildcard && buffer[bufferOffset] != firstByte) {
                continue;
            }

            if (patternLength > 1 &&
                !secondByteIsWildcard &&
                buffer[bufferOffset + 1] != secondByte) {
                continue;
            }

            if (ComparePattern(buffer.data() + bufferOffset, pattern)) {
                return start + regionOffset + bufferOffset;
            }
        }
    }

    return 0;
}

bool SignatureScanner::ComparePattern(
    const uint8_t* memoryBytes,
    const std::vector<PatternByte>& pattern
) {
    for (size_t byteIndex = 0; byteIndex < pattern.size(); ++byteIndex) {
        if (!pattern[byteIndex].wildcard && memoryBytes[byteIndex] != pattern[byteIndex].value) {
            return false;
        }
    }
    return true;
}

void SignatureScanner::UpdateJSONFile() {
    std::ofstream file(m_jsonFilename);
    if (!file.is_open()) {
        return;
    }

    WriteResultsJSON(file);
}

void SignatureScanner::WriteResultsJSON(std::ofstream& file) {
    file << "{\n";
    file << "  \"metadata\": {\n";
    file << "    \"game\": \"Counter-Strike 2\",\n";
    file << "    \"process_id\": " << m_memory.GetProcessId() << ",\n";
    file << "    \"total_signatures\": " << m_signatures.size() << ",\n";
    file << "    \"scan_time\": \"" << __DATE__ << " " << __TIME__ << "\"\n";
    file << "  },\n";
    file << "  \"signatures\": [\n";

    for (size_t signatureIndex = 0; signatureIndex < m_signatures.size(); ++signatureIndex) {
        const Signature& signature = m_signatures[signatureIndex];

        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(signature.name) << "\",\n";

        std::ostringstream patternHex;
        std::ostringstream idaPattern;
        std::ostringstream codeStylePattern;
        for (size_t byteIndex = 0; byteIndex < signature.pattern.size(); ++byteIndex) {
            const unsigned int byteValue =
                static_cast<unsigned int>(static_cast<unsigned char>(signature.pattern[byteIndex]));
            const bool isWildcard = byteIndex >= signature.mask.size() || signature.mask[byteIndex] == '?';

            patternHex << std::hex << std::setw(2) << std::setfill('0')
                       << byteValue;
            if (isWildcard) {
                idaPattern << "?";
                codeStylePattern << "\\x2A";
            } else {
                idaPattern << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                           << byteValue << std::nouppercase;
                codeStylePattern << "\\x" << std::uppercase << std::hex << std::setw(2)
                                 << std::setfill('0') << byteValue << std::nouppercase;
            }

            if (byteIndex < signature.pattern.size() - 1) {
                patternHex << " ";
                idaPattern << " ";
            }
        }

        file << "      \"pattern\": \"" << patternHex.str() << "\",\n";
        file << "      \"ida_pattern\": \"" << EscapeJson(idaPattern.str()) << "\",\n";
        file << "      \"code_style_pattern\": \"" << EscapeJson(codeStylePattern.str()) << "\",\n";
        file << "      \"mask\": \"" << EscapeJson(signature.mask) << "\",\n";
        if (!signature.module.empty()) {
            file << "      \"module\": \"" << EscapeJson(signature.module) << "\",\n";
        }
        if (!signature.rva.empty()) {
            file << "      \"rva\": \"" << EscapeJson(signature.rva) << "\",\n";
        }
        if (!signature.category.empty()) {
            file << "      \"category\": \"" << EscapeJson(signature.category) << "\",\n";
        }
        if (!signature.quality.empty()) {
            file << "      \"quality\": \"" << EscapeJson(signature.quality) << "\",\n";
        }
        file << "      \"result_type\": \"" << EscapeJson(EffectiveResultType(signature)) << "\",\n";
        file << "      \"importance\": \"" << EscapeJson(EffectiveImportance(signature)) << "\",\n";
        file << "      \"required\": " << (signature.required ? "true" : "false") << ",\n";
        file << "      \"status\": \"" << SignatureStatus(signature) << "\",\n";
        file << "      \"resolver_status\": \"" << EscapeJson(signature.resolverStatus) << "\",\n";
        if (signature.confidence > 0) {
            file << "      \"confidence\": " << signature.confidence << ",\n";
        }
        if (signature.sourceCount > 0) {
            file << "      \"source_count\": " << signature.sourceCount << ",\n";
        }
        if (!signature.source.empty()) {
            file << "      \"source\": \"" << EscapeJson(signature.source) << "\",\n";
        }
        if (!signature.sourceProject.empty()) {
            file << "      \"source_project\": \"" << EscapeJson(signature.sourceProject) << "\",\n";
        }
        if (!signature.sourceUrl.empty()) {
            file << "      \"source_url\": \"" << EscapeJson(signature.sourceUrl) << "\",\n";
        }
        WriteResolverJSON(file, signature.resolver);
        file << "      \"found\": " << (signature.found ? "true" : "false") << ",\n";

        if (signature.found) {
            if (signature.matchAddress != 0 && signature.matchAddress != signature.resolvedAddress) {
                file << "      \"match_address\": \"0x"
                     << std::hex << std::uppercase << signature.matchAddress << "\",\n";
            }
            file << "      \"address\": \"0x"
                 << std::hex << std::uppercase << signature.resolvedAddress << "\",\n";
            if (signature.hasModuleRva) {
                file << "      \"module_rva\": \"" << FormatHex(signature.moduleRva) << "\",\n";
            }
            if (EffectiveResultType(signature) == "field_offset") {
                file << "      \"field_offset\": \"" << FormatHex(signature.resolvedAddress) << "\",\n";
            }
            file << "      \"error\": null,\n";
        } else {
            file << "      \"address\": null,\n";
            file << "      \"module_rva\": null,\n";
            file << "      \"field_offset\": null,\n";
            file << "      \"error\": \"" << EscapeJson(signature.error) << "\",\n";
        }

        file << "      \"regions_scanned\": " << std::dec << signature.regionsScanned << ",\n";
        file << "      \"bytes_scanned\": " << signature.bytesScanned << "\n";
        file << "    }";

        if (signatureIndex < m_signatures.size() - 1) {
            file << ",";
        }
        file << "\n";
    }

    size_t foundCount = 0;
    size_t requiredCount = 0;
    size_t requiredFoundCount = 0;
    size_t optionalCount = 0;
    size_t optionalFoundCount = 0;
    for (const auto& signature : m_signatures) {
        if (signature.found) {
            ++foundCount;
        }
        if (signature.required) {
            ++requiredCount;
            if (signature.found) {
                ++requiredFoundCount;
            }
        } else {
            ++optionalCount;
            if (signature.found) {
                ++optionalFoundCount;
            }
        }
    }

    file << "  ],\n";
    file << "  \"summary\": {\n";
    file << "    \"found\": " << foundCount << ",\n";
    file << "    \"missing\": " << (m_signatures.size() - foundCount) << ",\n";
    file << "    \"total\": " << m_signatures.size() << ",\n";
    file << "    \"required_found\": " << requiredFoundCount << ",\n";
    file << "    \"required_missing\": " << (requiredCount - requiredFoundCount) << ",\n";
    file << "    \"required_total\": " << requiredCount << ",\n";
    file << "    \"optional_found\": " << optionalFoundCount << ",\n";
    file << "    \"optional_missing\": " << (optionalCount - optionalFoundCount) << ",\n";
    file << "    \"optional_total\": " << optionalCount << "\n";
    file << "  }\n";
    file << "}\n";
}

void SignatureScanner::DumpResultsJSON(const std::string& filename) {
    m_jsonFilename = filename;
    UpdateJSONFile();
}
