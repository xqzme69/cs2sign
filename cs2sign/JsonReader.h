#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

struct JsonValue {
    enum class Type {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object
    };

    Type type = Type::Null;
    bool boolValue = false;
    std::int64_t numberValue = 0;
    double numberFloatValue = 0.0;
    bool numberIsInteger = true;
    std::string stringValue;
    std::vector<JsonValue> arrayValue;
    std::map<std::string, JsonValue> objectValue;
};

class JsonReader {
public:
    explicit JsonReader(std::string_view input);

    bool Parse(JsonValue& value, std::string& error);

private:
    std::string_view input_;
    size_t position_ = 0;
    std::string error_;

    void SkipWhitespace();
    bool Consume(char expected);
    bool MatchLiteral(std::string_view literal);
    bool ParseValue(JsonValue& value);
    bool ParseString(std::string& value);
    bool ParseNumber(JsonValue& value);
    bool ParseArray(JsonValue& value);
    bool ParseObject(JsonValue& value);
};
