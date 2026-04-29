#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct SignatureEntry {
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
    std::int64_t addressOffset;
    int confidence;
    int sourceCount;
    int length;
    bool required;
    bool hasRequiredFlag;
};

class JSONParser {
public:
    static bool LoadSignatures(const std::string& filepath, std::vector<SignatureEntry>& out, std::string& error);
};
