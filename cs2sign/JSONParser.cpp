#include "JSONParser.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

std::string JSONParser::Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string JSONParser::UnescapeString(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            switch (s[i + 1]) {
                case '"':  result += '"'; i++; break;
                case '\\': result += '\\'; i++; break;
                case '/':  result += '/'; i++; break;
                case 'n':  result += '\n'; i++; break;
                case 'r':  result += '\r'; i++; break;
                case 't':  result += '\t'; i++; break;
                default:   result += s[i]; break;
            }
        } else {
            result += s[i];
        }
    }
    return result;
}

bool JSONParser::SkipWhitespace(const std::string& json, size_t& pos) {
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        pos++;
    }
    return pos < json.size();
}

bool JSONParser::ExpectChar(const std::string& json, size_t& pos, char c) {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != c) return false;
    pos++;
    return true;
}

bool JSONParser::ParseString(const std::string& json, size_t& pos, std::string& out) {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '"') return false;
    pos++;

    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            result += json[pos];
            result += json[pos + 1];
            pos += 2;
        } else {
            result += json[pos];
            pos++;
        }
    }
    if (pos >= json.size()) return false;
    pos++;

    out = UnescapeString(result);
    return true;
}

static bool SkipValue(const std::string& json, size_t& pos) {
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) pos++;
    if (pos >= json.size()) return false;

    char c = json[pos];

    if (c == '"') {
        pos++;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\') pos++;
            pos++;
        }
        if (pos < json.size()) pos++;
        return true;
    }

    if (c == '{') {
        pos++;
        int depth = 1;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') depth--;
            else if (json[pos] == '"') {
                pos++;
                while (pos < json.size() && json[pos] != '"') {
                    if (json[pos] == '\\') pos++;
                    pos++;
                }
            }
            pos++;
        }
        return true;
    }

    if (c == '[') {
        pos++;
        int depth = 1;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '[') depth++;
            else if (json[pos] == ']') depth--;
            else if (json[pos] == '"') {
                pos++;
                while (pos < json.size() && json[pos] != '"') {
                    if (json[pos] == '\\') pos++;
                    pos++;
                }
            }
            pos++;
        }
        return true;
    }

    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != ']'
           && !std::isspace(static_cast<unsigned char>(json[pos]))) {
        pos++;
    }
    return true;
}

static bool ParseInteger(const std::string& json, size_t& pos, std::int64_t& value) {
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        pos++;
    }

    const size_t numberStart = pos;
    if (pos < json.size() && (json[pos] == '-' || json[pos] == '+')) {
        pos++;
    }

    bool hasDigit = false;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        hasDigit = true;
        pos++;
    }

    if (!hasDigit) {
        pos = numberStart;
        return false;
    }

    try {
        value = std::stoll(json.substr(numberStart, pos - numberStart), nullptr, 10);
        return true;
    } catch (...) {
        pos = numberStart;
        return false;
    }
}

static bool ParseIntegerValue(const std::string& json, size_t& pos, std::int64_t& value) {
    if (ParseInteger(json, pos, value)) {
        return true;
    }

    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        pos++;
    }

    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }

    pos++;
    const size_t valueStart = pos;
    while (pos < json.size() && json[pos] != '"') {
        pos++;
    }
    if (pos >= json.size()) {
        return false;
    }

    const std::string stringValue = json.substr(valueStart, pos - valueStart);
    pos++;

    try {
        value = std::stoll(stringValue, nullptr, 0);
        return true;
    } catch (...) {
        return false;
    }
}

static bool ParseBoolValue(const std::string& json, size_t& pos, bool& value) {
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        pos++;
    }

    if (json.compare(pos, 4, "true") == 0) {
        pos += 4;
        value = true;
        return true;
    }

    if (json.compare(pos, 5, "false") == 0) {
        pos += 5;
        value = false;
        return true;
    }

    const size_t originalPosition = pos;
    if (pos < json.size() && json[pos] == '"') {
        pos++;
        const size_t valueStart = pos;
        while (pos < json.size() && json[pos] != '"') {
            pos++;
        }
        if (pos < json.size()) {
            std::string normalized = json.substr(valueStart, pos - valueStart);
            normalized.erase(normalized.begin(), std::find_if(normalized.begin(), normalized.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            normalized.erase(std::find_if(normalized.rbegin(), normalized.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), normalized.end());
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            pos++;

            if (normalized == "true" || normalized == "1" || normalized == "yes") {
                value = true;
                return true;
            }
            if (normalized == "false" || normalized == "0" || normalized == "no") {
                value = false;
                return true;
            }
        }
    }

    pos = originalPosition;
    return false;
}

static bool ConvertCodeStylePatternToIda(const std::string& codeStylePattern, std::string& idaPattern) {
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
            std::transform(byteToken.begin(), byteToken.end(), byteToken.begin(), [](unsigned char ch) {
                return static_cast<char>(std::toupper(ch));
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

static bool ConvertMaskedPatternToIda(
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
        std::transform(byteToken.begin(), byteToken.end(), byteToken.begin(), [](unsigned char ch) {
            return static_cast<char>(std::toupper(ch));
        });
        result << byteToken;
    }

    idaPattern = result.str();
    return true;
}

bool JSONParser::LoadSignatures(const std::string& filepath, std::vector<SignatureEntry>& out, std::string& error) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        error = "Cannot open file: " + filepath;
        return false;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    std::string json = ss.str();
    file.close();

    if (json.empty()) {
        error = "Empty file";
        return false;
    }

    size_t pos = 0;

    if (!ExpectChar(json, pos, '{')) {
        error = "Expected '{' at start of JSON";
        return false;
    }

    while (true) {
        SkipWhitespace(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == '}') { pos++; break; }

        if (json[pos] == ',') {
            pos++;
            SkipWhitespace(json, pos);
        }

        if (json[pos] == '}') { pos++; break; }

        std::string key;
        if (!ParseString(json, pos, key)) {
            error = "Expected string key at position " + std::to_string(pos);
            return false;
        }

        if (!ExpectChar(json, pos, ':')) {
            error = "Expected ':' after key at position " + std::to_string(pos);
            return false;
        }

        SkipWhitespace(json, pos);

        if (pos < json.size() && json[pos] == '{') {
            pos++;

            SignatureEntry entry;
            entry.name = key;
            entry.addressOffset = 0;
            entry.confidence = 0;
            entry.sourceCount = 0;
            entry.length = 0;
            entry.required = true;
            entry.hasRequiredFlag = false;
            int patternPriority = 0;
            std::string maskValue;

            while (true) {
                SkipWhitespace(json, pos);
                if (pos >= json.size()) break;
                if (json[pos] == '}') { pos++; break; }
                if (json[pos] == ',') { pos++; SkipWhitespace(json, pos); }
                if (json[pos] == '}') { pos++; break; }

                std::string innerKey;
                if (!ParseString(json, pos, innerKey)) break;
                if (!ExpectChar(json, pos, ':')) break;

                SkipWhitespace(json, pos);

                if (innerKey == "pattern" || innerKey == "module" || innerKey == "rva" ||
                    innerKey == "ida_pattern" || innerKey == "idaPattern" ||
                    innerKey == "ida_style" || innerKey == "idaStyle" ||
                    innerKey == "code_style_pattern" || innerKey == "codeStylePattern" ||
                    innerKey == "bytes" || innerKey == "mask" || innerKey == "category" ||
                    innerKey == "quality" || innerKey == "importance" || innerKey == "source" ||
                    innerKey == "source_project" || innerKey == "sourceProject" ||
                    innerKey == "source_url" || innerKey == "sourceUrl") {
                    std::string val;
                    if (ParseString(json, pos, val)) {
                        if (innerKey == "pattern") {
                            if (patternPriority <= 1) {
                                entry.pattern = val;
                                patternPriority = 1;
                            }
                        }
                        else if (innerKey == "ida_pattern" || innerKey == "idaPattern" ||
                                 innerKey == "ida_style" || innerKey == "idaStyle") {
                            if (patternPriority <= 3) {
                                entry.pattern = val;
                                patternPriority = 3;
                            }
                        } else if (innerKey == "code_style_pattern" || innerKey == "codeStylePattern") {
                            std::string convertedPattern;
                            if (patternPriority <= 2 && ConvertCodeStylePatternToIda(val, convertedPattern)) {
                                entry.pattern = convertedPattern;
                                patternPriority = 2;
                            }
                        }
                        else if (innerKey == "mask") maskValue = val;
                        else if (innerKey == "module") entry.module = val;
                        else if (innerKey == "rva") entry.rva = val;
                        else if (innerKey == "category") entry.category = val;
                        else if (innerKey == "quality") entry.quality = val;
                        else if (innerKey == "importance") entry.importance = val;
                        else if (innerKey == "source") entry.source = val;
                        else if (innerKey == "source_project" || innerKey == "sourceProject") entry.sourceProject = val;
                        else if (innerKey == "source_url" || innerKey == "sourceUrl") entry.sourceUrl = val;
                    }
                } else if (innerKey == "length" || innerKey == "address_offset" || innerKey == "offset" ||
                           innerKey == "confidence" || innerKey == "source_count" || innerKey == "sourceCount") {
                    std::int64_t numberValue = 0;
                    if (ParseIntegerValue(json, pos, numberValue)) {
                        if (innerKey == "length") {
                            entry.length = static_cast<int>(numberValue);
                        } else if (innerKey == "confidence") {
                            entry.confidence = static_cast<int>(numberValue);
                        } else if (innerKey == "source_count" || innerKey == "sourceCount") {
                            entry.sourceCount = static_cast<int>(numberValue);
                        } else {
                            entry.addressOffset = numberValue;
                        }
                    } else {
                        SkipValue(json, pos);
                    }
                } else if (innerKey == "required") {
                    bool boolValue = true;
                    if (ParseBoolValue(json, pos, boolValue)) {
                        entry.required = boolValue;
                        entry.hasRequiredFlag = true;
                    } else {
                        SkipValue(json, pos);
                    }
                } else {
                    SkipValue(json, pos);
                }
            }

            if (!entry.pattern.empty()) {
                if (patternPriority == 1 && !maskValue.empty()) {
                    std::string convertedPattern;
                    if (ConvertMaskedPatternToIda(entry.pattern, maskValue, convertedPattern)) {
                        entry.pattern = convertedPattern;
                    }
                }
                out.push_back(entry);
            }
        } else {
            SkipValue(json, pos);
        }
    }

    if (out.empty()) {
        error = "No signatures found in JSON";
        return false;
    }

    return true;
}
