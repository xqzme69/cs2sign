#include "JSONParser.h"

#include "JsonReader.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

namespace {
bool ReadString(const JsonValue& value, std::string& result) {
    if (value.type != JsonValue::Type::String) {
        return false;
    }

    result = value.stringValue;
    return true;
}

std::string Trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char character) {
        return std::isspace(character);
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char character) {
        return std::isspace(character);
    }).base();

    if (first >= last) {
        return {};
    }

    return std::string(first, last);
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool ReadInteger(const JsonValue& value, std::int64_t& result) {
    if (value.type == JsonValue::Type::Number) {
        result = value.numberValue;
        return true;
    }

    if (value.type != JsonValue::Type::String) {
        return false;
    }

    try {
        result = std::stoll(Trim(value.stringValue), nullptr, 0);
        return true;
    } catch (...) {
        return false;
    }
}

bool ReadBool(const JsonValue& value, bool& result) {
    if (value.type == JsonValue::Type::Bool) {
        result = value.boolValue;
        return true;
    }

    if (value.type != JsonValue::Type::String) {
        return false;
    }

    const std::string normalized = LowerAscii(Trim(value.stringValue));
    if (normalized == "true" || normalized == "1" || normalized == "yes") {
        result = true;
        return true;
    }
    if (normalized == "false" || normalized == "0" || normalized == "no") {
        result = false;
        return true;
    }

    return false;
}

bool IsPatternField(const std::string& key) {
    return key == "pattern" ||
           key == "ida_pattern" ||
           key == "idaPattern" ||
           key == "ida_style" ||
           key == "idaStyle" ||
           key == "code_style_pattern" ||
           key == "codeStylePattern" ||
           key == "mask";
}

bool IsTextField(const std::string& key) {
    return key == "module" ||
           key == "rva" ||
           key == "category" ||
           key == "quality" ||
           key == "importance" ||
           key == "source" ||
           key == "source_project" ||
           key == "sourceProject" ||
           key == "source_url" ||
           key == "sourceUrl";
}

bool ConvertCodeStylePatternToIda(const std::string& codeStylePattern, std::string& idaPattern) {
    std::vector<std::string> tokens;

    for (size_t index = 0; index < codeStylePattern.size();) {
        if (std::isspace(static_cast<unsigned char>(codeStylePattern[index]))) {
            ++index;
            continue;
        }

        if (codeStylePattern[index] == '?' || codeStylePattern[index] == '*') {
            tokens.push_back("?");
            ++index;
            continue;
        }

        if (index + 3 < codeStylePattern.size() &&
            codeStylePattern[index] == '\\' &&
            (codeStylePattern[index + 1] == 'x' || codeStylePattern[index + 1] == 'X') &&
            std::isxdigit(static_cast<unsigned char>(codeStylePattern[index + 2])) &&
            std::isxdigit(static_cast<unsigned char>(codeStylePattern[index + 3]))) {
            std::string byteToken = codeStylePattern.substr(index + 2, 2);
            std::transform(byteToken.begin(), byteToken.end(), byteToken.begin(), [](unsigned char character) {
                return static_cast<char>(std::toupper(character));
            });
            tokens.push_back(byteToken == "2A" ? "?" : byteToken);
            index += 4;
            continue;
        }

        return false;
    }

    if (tokens.empty()) {
        return false;
    }

    std::ostringstream result;
    for (size_t index = 0; index < tokens.size(); ++index) {
        if (index > 0) {
            result << ' ';
        }
        result << tokens[index];
    }

    idaPattern = result.str();
    return true;
}

bool ConvertMaskedPatternToIda(
    const std::string& patternText,
    const std::string& maskText,
    std::string& idaPattern
) {
    std::istringstream patternStream(patternText);
    std::vector<std::string> patternTokens;
    std::string token;

    while (patternStream >> token) {
        patternTokens.push_back(token);
    }

    if (patternTokens.empty() || patternTokens.size() != maskText.size()) {
        return false;
    }

    std::ostringstream result;
    for (size_t index = 0; index < patternTokens.size(); ++index) {
        if (index > 0) {
            result << ' ';
        }

        if (maskText[index] == '?') {
            result << '?';
            continue;
        }

        std::string byteToken = patternTokens[index];
        std::transform(byteToken.begin(), byteToken.end(), byteToken.begin(), [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });
        result << byteToken;
    }

    idaPattern = result.str();
    return true;
}

void ApplyStringField(SignatureEntry& entry, const std::string& key, const std::string& value) {
    if (key == "module") entry.module = value;
    else if (key == "rva") entry.rva = value;
    else if (key == "category") entry.category = value;
    else if (key == "quality") entry.quality = value;
    else if (key == "importance") entry.importance = value;
    else if (key == "source") entry.source = value;
    else if (key == "source_project" || key == "sourceProject") entry.sourceProject = value;
    else if (key == "source_url" || key == "sourceUrl") entry.sourceUrl = value;
}

void ApplyPatternField(
    SignatureEntry& entry,
    const std::string& key,
    const std::string& value,
    int& patternPriority,
    std::string& maskValue
) {
    if (key == "pattern") {
        if (patternPriority <= 1) {
            entry.pattern = value;
            patternPriority = 1;
        }
        return;
    }

    if (key == "ida_pattern" || key == "idaPattern" || key == "ida_style" || key == "idaStyle") {
        if (patternPriority <= 3) {
            entry.pattern = value;
            patternPriority = 3;
        }
        return;
    }

    if (key == "code_style_pattern" || key == "codeStylePattern") {
        std::string convertedPattern;
        if (patternPriority <= 2 && ConvertCodeStylePatternToIda(value, convertedPattern)) {
            entry.pattern = convertedPattern;
            patternPriority = 2;
        }
        return;
    }

    if (key == "mask") {
        maskValue = value;
    }
}

void ApplyNumberField(SignatureEntry& entry, const std::string& key, std::int64_t value) {
    if (key == "length") {
        entry.length = static_cast<int>(value);
    } else if (key == "confidence") {
        entry.confidence = static_cast<int>(value);
    } else if (key == "source_count" || key == "sourceCount") {
        entry.sourceCount = static_cast<int>(value);
    } else if (key == "address_offset" || key == "offset") {
        entry.addressOffset = value;
    }
}
}

bool JSONParser::LoadSignatures(
    const std::string& filepath,
    std::vector<SignatureEntry>& out,
    std::string& error
) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        error = "Cannot open file: " + filepath;
        return false;
    }

    std::stringstream stream;
    stream << file.rdbuf();
    const std::string jsonText = stream.str();

    if (jsonText.empty()) {
        error = "Empty file";
        return false;
    }

    JsonValue root;
    JsonReader reader(jsonText);
    if (!reader.Parse(root, error)) {
        return false;
    }

    if (root.type != JsonValue::Type::Object) {
        error = "Expected root object";
        return false;
    }

    for (const auto& [name, value] : root.objectValue) {
        if (value.type != JsonValue::Type::Object) {
            continue;
        }

        SignatureEntry entry{};
        entry.name = name;
        entry.required = true;

        int patternPriority = 0;
        std::string maskValue;

        for (const auto& [key, field] : value.objectValue) {
            std::string stringValue;
            if (ReadString(field, stringValue)) {
                if (IsPatternField(key)) {
                    ApplyPatternField(entry, key, stringValue, patternPriority, maskValue);
                    continue;
                }

                if (IsTextField(key)) {
                    ApplyStringField(entry, key, stringValue);
                    continue;
                }
            }

            if (key == "required") {
                bool boolValue = true;
                if (ReadBool(field, boolValue)) {
                    entry.required = boolValue;
                    entry.hasRequiredFlag = true;
                }
                continue;
            }

            std::int64_t numberValue = 0;
            if (ReadInteger(field, numberValue)) {
                ApplyNumberField(entry, key, numberValue);
                continue;
            }
        }

        if (entry.pattern.empty()) {
            continue;
        }

        if (patternPriority == 1 && !maskValue.empty()) {
            std::string convertedPattern;
            if (ConvertMaskedPatternToIda(entry.pattern, maskValue, convertedPattern)) {
                entry.pattern = convertedPattern;
            }
        }

        out.push_back(std::move(entry));
    }

    if (out.empty()) {
        error = "No signatures found in JSON";
        return false;
    }

    return true;
}
