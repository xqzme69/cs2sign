#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct SignatureEntry {
    struct Resolver {
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

    std::string name;
    std::string pattern;   // IDA-style: "48 89 5C 24 ? 57"
    std::string module;    // e.g. "client"
    std::string rva;       // e.g. "0x1a2b3c"
    std::string category;  // game/module/library/runtime/etc.
    std::string quality;   // good/ok/fragile
    std::string importance; // required/optional
    std::string source;
    std::string sourceProject;
    std::string sourceUrl;
    std::string resultType;
    std::int64_t addressOffset;
    int confidence;
    int sourceCount;
    int length;
    bool required;
    bool hasRequiredFlag;
    Resolver resolver;
};

class JSONParser {
public:
    static bool LoadSignatures(const std::string& filepath, std::vector<SignatureEntry>& out, std::string& error);
};
