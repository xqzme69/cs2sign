#include "JsonReader.h"

#include <cctype>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <utility>

JsonReader::JsonReader(std::string_view input) : input_(input) {
}

bool JsonReader::Parse(JsonValue& value, std::string& error) {
    SkipWhitespace();
    if (!ParseValue(value)) {
        error = error_.empty() ? "invalid json" : error_;
        return false;
    }

    SkipWhitespace();
    if (position_ != input_.size()) {
        error = "unexpected trailing json data";
        return false;
    }

    return true;
}

void JsonReader::SkipWhitespace() {
    while (position_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[position_]))) {
        ++position_;
    }
}

bool JsonReader::Consume(char expected) {
    SkipWhitespace();
    if (position_ >= input_.size() || input_[position_] != expected) {
        return false;
    }

    ++position_;
    return true;
}

bool JsonReader::MatchLiteral(std::string_view literal) {
    if (input_.substr(position_, literal.size()) != literal) {
        return false;
    }

    position_ += literal.size();
    return true;
}

bool JsonReader::ParseValue(JsonValue& value) {
    SkipWhitespace();
    if (position_ >= input_.size()) {
        error_ = "unexpected end of json";
        return false;
    }

    const char current = input_[position_];
    if (current == '"') {
        value.type = JsonValue::Type::String;
        return ParseString(value.stringValue);
    }
    if (current == '{') {
        return ParseObject(value);
    }
    if (current == '[') {
        return ParseArray(value);
    }
    if (current == '-' || std::isdigit(static_cast<unsigned char>(current))) {
        value.type = JsonValue::Type::Number;
        return ParseNumber(value);
    }
    if (MatchLiteral("true")) {
        value.type = JsonValue::Type::Bool;
        value.boolValue = true;
        return true;
    }
    if (MatchLiteral("false")) {
        value.type = JsonValue::Type::Bool;
        value.boolValue = false;
        return true;
    }
    if (MatchLiteral("null")) {
        value.type = JsonValue::Type::Null;
        return true;
    }

    error_ = "unexpected json token";
    return false;
}

bool JsonReader::ParseString(std::string& value) {
    if (position_ >= input_.size() || input_[position_] != '"') {
        error_ = "expected string";
        return false;
    }

    ++position_;
    value.clear();

    while (position_ < input_.size()) {
        const char current = input_[position_++];
        if (current == '"') {
            return true;
        }

        if (current != '\\') {
            value.push_back(current);
            continue;
        }

        if (position_ >= input_.size()) {
            error_ = "unterminated string escape";
            return false;
        }

        const char escaped = input_[position_++];
        switch (escaped) {
            case '"': value.push_back('"'); break;
            case '\\': value.push_back('\\'); break;
            case '/': value.push_back('/'); break;
            case 'b': value.push_back('\b'); break;
            case 'f': value.push_back('\f'); break;
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case 'u':
                if (position_ + 4 > input_.size()) {
                    error_ = "invalid unicode escape";
                    return false;
                }
                position_ += 4;
                value.push_back('?');
                break;
            default:
                error_ = "invalid string escape";
                return false;
        }
    }

    error_ = "unterminated string";
    return false;
}

bool JsonReader::ParseNumber(JsonValue& value) {
    const size_t start = position_;
    if (input_[position_] == '-') {
        ++position_;
    }

    if (position_ >= input_.size() ||
        !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
        error_ = "invalid number";
        return false;
    }

    if (input_[position_] == '0') {
        ++position_;
    } else {
        while (position_ < input_.size() &&
               std::isdigit(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
    }

    bool isInteger = true;
    if (position_ < input_.size() && input_[position_] == '.') {
        isInteger = false;
        ++position_;

        if (position_ >= input_.size() ||
            !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
            error_ = "invalid number";
            return false;
        }

        while (position_ < input_.size() &&
               std::isdigit(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
    }

    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
        isInteger = false;
        ++position_;

        if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
            ++position_;
        }

        if (position_ >= input_.size() ||
            !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
            error_ = "invalid number";
            return false;
        }

        while (position_ < input_.size() &&
               std::isdigit(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
    }

    const std::string numberText(input_.substr(start, position_ - start));
    try {
        value.numberIsInteger = isInteger;
        if (isInteger) {
            value.numberValue = std::stoll(numberText);
            value.numberFloatValue = static_cast<double>(value.numberValue);
            return true;
        }

        const long double parsed = std::stold(numberText);
        if (!std::isfinite(parsed)) {
            error_ = "invalid number";
            return false;
        }

        value.numberFloatValue = static_cast<double>(parsed);
        if (parsed >= static_cast<long double>(std::numeric_limits<std::int64_t>::min()) &&
            parsed <= static_cast<long double>(std::numeric_limits<std::int64_t>::max()) &&
            std::trunc(parsed) == parsed) {
            value.numberValue = static_cast<std::int64_t>(parsed);
        } else {
            value.numberValue = 0;
        }
        return true;
    } catch (...) {
        error_ = "invalid number";
        return false;
    }
}

bool JsonReader::ParseArray(JsonValue& value) {
    if (!Consume('[')) {
        error_ = "expected array";
        return false;
    }

    value.type = JsonValue::Type::Array;
    value.arrayValue.clear();

    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == ']') {
        ++position_;
        return true;
    }

    while (true) {
        JsonValue item;
        if (!ParseValue(item)) {
            return false;
        }

        value.arrayValue.push_back(std::move(item));

        SkipWhitespace();
        if (position_ < input_.size() && input_[position_] == ']') {
            ++position_;
            return true;
        }

        if (!Consume(',')) {
            error_ = "expected comma in array";
            return false;
        }
    }
}

bool JsonReader::ParseObject(JsonValue& value) {
    if (!Consume('{')) {
        error_ = "expected object";
        return false;
    }

    value.type = JsonValue::Type::Object;
    value.objectValue.clear();

    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == '}') {
        ++position_;
        return true;
    }

    while (true) {
        SkipWhitespace();

        std::string key;
        if (!ParseString(key)) {
            return false;
        }

        if (!Consume(':')) {
            error_ = "expected colon in object";
            return false;
        }

        JsonValue item;
        if (!ParseValue(item)) {
            return false;
        }

        value.objectValue[key] = std::move(item);

        SkipWhitespace();
        if (position_ < input_.size() && input_[position_] == '}') {
            ++position_;
            return true;
        }

        if (!Consume(',')) {
            error_ = "expected comma in object";
            return false;
        }
    }
}
