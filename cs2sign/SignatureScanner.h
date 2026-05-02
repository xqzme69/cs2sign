#pragma once

#include "DumpUtils.h"
#include "ProcessMemoryReader.h"
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <thread>
#include <atomic>
#include <algorithm>

struct SignatureResolver {
    std::string type;
    std::string resultType;
    std::string targetRva;
    std::string formula;
    std::int64_t add = 0;
    std::int64_t expected = 0;
    int instructionOffset = 0;
    int instructionSize = 0;
    int operandIndex = -1;
    int operandOffset = 0;
    int operandSize = 0;
    bool hasAdd = false;
    bool hasExpected = false;
    bool hasInstructionOffset = false;
    bool hasInstructionSize = false;
    bool hasOperandIndex = false;
    bool hasOperandOffset = false;
    bool hasOperandSize = false;
    bool enabled = false;
};

struct Signature {
    std::string name;
    std::string pattern;
    std::string mask;
    std::vector<PatternByte> compiledPattern;
    std::string module;     // target module (e.g. "client")
    std::string rva;        // original RVA from IDA
    std::string category;   // game/module/library/runtime/etc.
    std::string quality;    // good/ok/fragile
    std::string importance; // required/optional
    std::string source;
    std::string sourceProject;
    std::string sourceUrl;
    std::string resultType;
    SignatureResolver resolver;
    intptr_t addressOffset;
    int confidence;
    int sourceCount;
    bool required;
    uintptr_t matchAddress;
    uintptr_t resolvedAddress;
    std::uint32_t moduleRva;
    bool hasModuleRva;
    std::string patternSynth;
    std::string resolverStatus;
    bool found;
    std::string error;
    size_t regionsScanned;
    size_t bytesScanned;
};

class SignatureScanner {
public:
    SignatureScanner(ProcessMemoryReader& memory);
    ~SignatureScanner();

    // Add signature from raw bytes + mask.
    void AddSignature(const std::string& name, const std::string& pattern, const std::string& mask, intptr_t offset = 0);
    void AddSignature(const std::string& name, const char* pattern, size_t patternLen, const std::string& mask, intptr_t offset = 0);

    // Add signature from IDA-style pattern string: "48 89 5C 24 ? 57"
    bool AddSignatureFromIDA(const std::string& name, const std::string& idaPattern,
                             const std::string& module = "", const std::string& rva = "",
                             intptr_t addressOffset = 0, const std::string& category = "",
                             const std::string& quality = "", const std::string& importance = "",
                             int confidence = 0, int sourceCount = 0,
                             const std::string& source = "", const std::string& sourceProject = "",
                             const std::string& sourceUrl = "", bool required = true,
                             const SignatureResolver& resolver = {}, const std::string& resultType = "");

    void ScanAll();
    void DumpResultsJSON(const std::string& filename = "cs2_signatures.json");
    void UpdateJSONFile();

    std::vector<Signature>& GetSignatures() { return m_signatures; }
    const std::vector<Signature>& GetSignatures() const { return m_signatures; }

    // Parse IDA-style pattern into raw bytes + mask
    static bool ParseIDAPattern(const std::string& idaPattern, std::string& outBytes, std::string& outMask);

private:
    struct SignatureScanOutcome {
        bool found = false;
        uintptr_t address = 0;
        size_t regionsScanned = 0;
        size_t bytesScanned = 0;
    };

    void ResetSignatureState(Signature& signature);
    bool ValidateSignaturePattern(Signature& signature);
    std::vector<MemoryRegion> BuildCandidateRegions();
    std::vector<MemoryRegion> SelectRegionsForSignature(
        const Signature& signature,
        const std::vector<MemoryRegion>& candidateRegions
    );
    SignatureScanOutcome ScanStringReferenceSignature(const Signature& signature);
    SignatureScanOutcome ScanSignatureRegions(
        const Signature& signature,
        const std::vector<MemoryRegion>& scanRegions,
        size_t workerThreadCount
    );
    void RecordFoundSignature(Signature& signature, const SignatureScanOutcome& outcome);
    void RecordMissingSignature(Signature& signature, const SignatureScanOutcome& outcome);
    bool ResolveSignatureAddress(Signature& signature, uintptr_t matchAddress);
    std::string BuildPatternSynth(uintptr_t address);
    void WriteResultsJSON(std::ofstream& file);

    uintptr_t ScanPattern(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern, std::string& error);
    uintptr_t ScanPatternOptimized(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern, std::string& error);
    uintptr_t ScanPatternOptimized(
        uintptr_t start,
        size_t size,
        const std::vector<PatternByte>& pattern,
        std::string& error,
        const Signature* signature
    );
    bool MatchResolverExpected(const Signature& signature, uintptr_t matchAddress, std::string& error);
    bool ComparePattern(const uint8_t* memoryBytes, const std::vector<PatternByte>& pattern);

    ProcessMemoryReader& m_memory;
    std::vector<Signature> m_signatures;
    std::string m_jsonFilename;
};

