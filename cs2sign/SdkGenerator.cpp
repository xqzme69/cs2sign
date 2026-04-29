#include "SdkGenerator.h"

#include "DumpUtils.h"
#include "JsonReader.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
struct SchemaMetadata {
    std::string type;
    std::string name;
    std::string typeName;
};

struct SchemaField {
    std::string name;
    std::string typeName;
    std::int32_t offset = 0;
    std::vector<SchemaMetadata> metadata;
};

struct SchemaClass {
    std::string name;
    std::string baseClassName;
    std::int32_t size = 0;
    std::vector<SchemaMetadata> metadata;
    std::vector<SchemaField> fields;
};

struct SchemaEnumField {
    std::string name;
    std::int64_t value = 0;
};

struct SchemaEnum {
    std::string name;
    std::int32_t size = 4;
    std::vector<SchemaEnumField> fields;
};

struct SchemaModule {
    std::string moduleName;
    std::filesystem::path sourcePath;
    std::vector<SchemaClass> classes;
    std::vector<SchemaEnum> enums;
};

struct TypeInfo {
    std::string cppType;
    std::string cType;
    size_t size = 0;
    bool canEmitAsField = false;
};

struct EmittedField {
    std::string originalName;
    std::string originalType;
    std::string name;
    std::string cppType;
    std::string cType;
    std::int32_t offset = 0;
    size_t emittedSize = 0;
    bool byteArray = false;
    std::vector<SchemaMetadata> metadata;
};

const JsonValue* FindMember(const JsonValue& value, std::string_view name) {
    if (value.type != JsonValue::Type::Object) {
        return nullptr;
    }

    const auto found = value.objectValue.find(std::string(name));
    return found == value.objectValue.end() ? nullptr : &found->second;
}

std::string GetStringMember(const JsonValue& value, std::string_view name) {
    const JsonValue* member = FindMember(value, name);
    if (!member || member->type != JsonValue::Type::String) {
        return {};
    }

    return member->stringValue;
}

std::int64_t GetNumberMember(const JsonValue& value, std::string_view name, std::int64_t fallback = 0) {
    const JsonValue* member = FindMember(value, name);
    if (!member || member->type != JsonValue::Type::Number) {
        return fallback;
    }

    return member->numberValue;
}

const std::vector<JsonValue>* GetArrayMember(const JsonValue& value, std::string_view name) {
    const JsonValue* member = FindMember(value, name);
    if (!member || member->type != JsonValue::Type::Array) {
        return nullptr;
    }

    return &member->arrayValue;
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

bool StartsWith(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::string CommentText(std::string value) {
    for (char& character : value) {
        if (character == '\r' || character == '\n') {
            character = ' ';
        }
    }
    return value;
}

std::string SanitizeTypeName(std::string value, std::string fallback = "unnamed") {
    for (size_t index = 0; index < value.size(); ++index) {
        const unsigned char character = static_cast<unsigned char>(value[index]);
        if (std::isalnum(character) || value[index] == '_') {
            continue;
        }

        if (value[index] == ':' && index + 1 < value.size() && value[index + 1] == ':') {
            value[index] = '_';
            value[index + 1] = '_';
            ++index;
            continue;
        }

        value[index] = '_';
    }

    return SanitizeIdentifier(value, std::move(fallback));
}

std::string MakeUniqueIdentifier(const std::string& rawName, std::set<std::string>& used, const std::string& fallback) {
    std::string base = SanitizeTypeName(rawName, fallback);
    std::string candidate = base;

    size_t suffix = 1;
    while (used.contains(candidate)) {
        candidate = base + "_" + std::to_string(suffix++);
    }

    used.insert(candidate);
    return candidate;
}

std::optional<TypeInfo> ResolveKnownType(std::string typeName) {
    typeName = Trim(typeName);
    if (StartsWith(typeName, "const ")) {
        typeName = Trim(typeName.substr(6));
    }

    if (EndsWith(typeName, "*")) {
        return TypeInfo{ "std::uintptr_t", "uint64_t", 8, true };
    }

    if (typeName == "bool") return TypeInfo{ "bool", "bool", 1, true };
    if (typeName == "char") return TypeInfo{ "char", "char", 1, true };
    if (typeName == "int8") return TypeInfo{ "std::int8_t", "int8_t", 1, true };
    if (typeName == "uint8") return TypeInfo{ "std::uint8_t", "uint8_t", 1, true };
    if (typeName == "int16") return TypeInfo{ "std::int16_t", "int16_t", 2, true };
    if (typeName == "uint16") return TypeInfo{ "std::uint16_t", "uint16_t", 2, true };
    if (typeName == "int32") return TypeInfo{ "std::int32_t", "int32_t", 4, true };
    if (typeName == "uint32") return TypeInfo{ "std::uint32_t", "uint32_t", 4, true };
    if (typeName == "int64") return TypeInfo{ "std::int64_t", "int64_t", 8, true };
    if (typeName == "uint64") return TypeInfo{ "std::uint64_t", "uint64_t", 8, true };
    if (typeName == "float32") return TypeInfo{ "float", "float", 4, true };
    if (typeName == "float64") return TypeInfo{ "double", "double", 8, true };

    if (typeName == "GameTime_t") return TypeInfo{ "float", "float", 4, true };
    if (typeName == "GameTick_t") return TypeInfo{ "std::int32_t", "int32_t", 4, true };
    if (typeName == "CEntityIndex") return TypeInfo{ "std::int32_t", "int32_t", 4, true };
    if (typeName == "CPlayerSlot") return TypeInfo{ "std::int32_t", "int32_t", 4, true };
    if (typeName == "CEntityHandle") return TypeInfo{ "std::uint32_t", "uint32_t", 4, true };
    if (StartsWith(typeName, "CHandle<")) return TypeInfo{ "std::uint32_t", "uint32_t", 4, true };

    if (typeName == "CUtlStringToken") return TypeInfo{ "std::uint32_t", "uint32_t", 4, true };
    if (typeName == "CUtlSymbol") return TypeInfo{ "std::uint16_t", "uint16_t", 2, true };
    if (typeName == "CUtlSymbolLarge") return TypeInfo{ "std::uint64_t", "uint64_t", 8, true };
    if (typeName == "CUtlString") return TypeInfo{ "std::uint64_t", "uint64_t", 8, true };
    if (typeName == "CGlobalSymbol") return TypeInfo{ "std::uint64_t", "uint64_t", 8, true };

    if (typeName == "Color") return TypeInfo{ "Color", "cs2_Color", 4, true };
    if (typeName == "Vector2D") return TypeInfo{ "Vector2D", "cs2_Vector2D", 8, true };
    if (typeName == "Vector") return TypeInfo{ "Vector", "cs2_Vector", 12, true };
    if (typeName == "QAngle") return TypeInfo{ "QAngle", "cs2_QAngle", 12, true };
    if (typeName == "Quaternion") return TypeInfo{ "Quaternion", "cs2_Quaternion", 16, true };
    if (typeName == "Vector4D") return TypeInfo{ "Vector4D", "cs2_Vector4D", 16, true };
    if (typeName == "CTransform") return TypeInfo{ "CTransform", "cs2_CTransform", 32, true };

    if (StartsWith(typeName, "CStrongHandle<") ||
        StartsWith(typeName, "CStrongHandleCopyable<") ||
        typeName == "CStrongHandleVoid") {
        return TypeInfo{ "std::uint64_t", "uint64_t", 8, true };
    }

    if (StartsWith(typeName, "CUtlVector<") ||
        StartsWith(typeName, "C_NetworkUtlVectorBase<") ||
        StartsWith(typeName, "CNetworkUtlVectorBase<")) {
        return TypeInfo{ "", "", 24, false };
    }

    if (StartsWith(typeName, "C_UtlVectorEmbeddedNetworkVar<") ||
        StartsWith(typeName, "CUtlVectorEmbeddedNetworkVar<")) {
        return TypeInfo{ "", "", 80, false };
    }

    return std::nullopt;
}

size_t FallbackFieldSize(
    const SchemaClass& schemaClass,
    const std::vector<SchemaField>& fields,
    size_t fieldIndex,
    const SchemaField& field
) {
    std::optional<std::int32_t> nextOffset;
    for (size_t index = fieldIndex + 1; index < fields.size(); ++index) {
        if (fields[index].offset > field.offset) {
            nextOffset = fields[index].offset;
            break;
        }
    }

    if (nextOffset && *nextOffset > field.offset) {
        return static_cast<size_t>(*nextOffset - field.offset);
    }

    if (schemaClass.size > field.offset) {
        return static_cast<size_t>(schemaClass.size - field.offset);
    }

    return 1;
}

std::vector<EmittedField> BuildFieldPlan(const SchemaClass& schemaClass) {
    std::vector<SchemaField> fields = schemaClass.fields;
    std::sort(fields.begin(), fields.end(), [](const SchemaField& left, const SchemaField& right) {
        if (left.offset != right.offset) {
            return left.offset < right.offset;
        }
        return left.name < right.name;
    });

    std::vector<EmittedField> plan;
    std::set<std::string> usedNames;
    std::int32_t cursor = 0;

    for (size_t index = 0; index < fields.size(); ++index) {
        const SchemaField& field = fields[index];
        if (field.offset < cursor) {
            continue;
        }

        const std::optional<TypeInfo> knownType = ResolveKnownType(field.typeName);
        const size_t fallbackSize = FallbackFieldSize(schemaClass, fields, index, field);
        const size_t emittedSize = (std::max)(size_t{ 1 }, knownType ? knownType->size : fallbackSize);
        const bool canEmitAsTypedField =
            knownType.has_value() &&
            knownType->canEmitAsField &&
            knownType->size > 0 &&
            knownType->size <= fallbackSize;

        EmittedField emitted;
        emitted.originalName = field.name;
        emitted.originalType = field.typeName;
        emitted.name = MakeUniqueIdentifier(
            field.name,
            usedNames,
            "field_" + FormatHex(static_cast<std::uint32_t>(field.offset), false)
        );
        emitted.offset = field.offset;
        emitted.metadata = field.metadata;

        if (canEmitAsTypedField) {
            emitted.cppType = knownType->cppType;
            emitted.cType = knownType->cType;
            emitted.emittedSize = knownType->size;
            emitted.byteArray = false;
        } else {
            emitted.cppType = "std::byte";
            emitted.cType = "uint8_t";
            emitted.emittedSize = fallbackSize;
            emitted.byteArray = true;
        }

        plan.push_back(std::move(emitted));
        cursor = field.offset + static_cast<std::int32_t>(plan.back().emittedSize);
    }

    return plan;
}

void WriteCppPrelude(std::ofstream& file) {
    file << "#pragma once\n\n";
    file << "#include <cstddef>\n";
    file << "#include <cstdint>\n";
    file << "#include <type_traits>\n\n";
}

void WriteCppCommonTypes(std::ofstream& file) {
    file << "struct Color { std::uint8_t r; std::uint8_t g; std::uint8_t b; std::uint8_t a; };\n";
    file << "struct Vector2D { float x; float y; };\n";
    file << "struct Vector { float x; float y; float z; };\n";
    file << "struct QAngle { float x; float y; float z; };\n";
    file << "struct Vector4D { float x; float y; float z; float w; };\n";
    file << "struct Quaternion { float x; float y; float z; float w; };\n";
    file << "struct CTransform { float data[8]; };\n\n";
}

void WriteIdaPrelude(std::ofstream& file) {
    file << "#ifndef CS2SIGN_SDK_IDA_H\n";
    file << "#define CS2SIGN_SDK_IDA_H\n\n";
    file << "typedef signed char int8_t;\n";
    file << "typedef unsigned char uint8_t;\n";
    file << "typedef short int16_t;\n";
    file << "typedef unsigned short uint16_t;\n";
    file << "typedef int int32_t;\n";
    file << "typedef unsigned int uint32_t;\n";
    file << "typedef long long int64_t;\n";
    file << "typedef unsigned long long uint64_t;\n\n";
    file << "typedef unsigned char bool;\n\n";
    file << "typedef struct cs2_Color { uint8_t r; uint8_t g; uint8_t b; uint8_t a; } cs2_Color;\n";
    file << "typedef struct cs2_Vector2D { float x; float y; } cs2_Vector2D;\n";
    file << "typedef struct cs2_Vector { float x; float y; float z; } cs2_Vector;\n";
    file << "typedef struct cs2_QAngle { float x; float y; float z; } cs2_QAngle;\n";
    file << "typedef struct cs2_Vector4D { float x; float y; float z; float w; } cs2_Vector4D;\n";
    file << "typedef struct cs2_Quaternion { float x; float y; float z; float w; } cs2_Quaternion;\n";
    file << "typedef struct cs2_CTransform { float data[8]; } cs2_CTransform;\n\n";
    file << "#pragma pack(push, 1)\n\n";
}

void WriteMetadataComments(std::ofstream& file, const std::vector<SchemaMetadata>& metadata, const std::string& indent) {
    for (const SchemaMetadata& entry : metadata) {
        if (entry.type == "NetworkVarNames") {
            file << indent << "// NetworkVarNames: " << CommentText(entry.name);
            if (!entry.typeName.empty()) {
                file << " (" << CommentText(entry.typeName) << ")";
            }
            file << "\n";
        } else if (entry.type == "NetworkChangeCallback") {
            file << indent << "// NetworkChangeCallback: " << CommentText(entry.name) << "\n";
        } else {
            file << indent << "// Metadata: " << CommentText(entry.name) << "\n";
        }
    }
}

void WriteCppPadding(std::ofstream& file, std::int32_t offset, size_t size) {
    if (size == 0) {
        return;
    }

    file << "    std::byte _pad" << std::hex << std::setw(4) << std::setfill('0')
         << offset << std::dec << std::setfill(' ') << "[0x" << std::hex << size
         << std::dec << "];\n";
}

void WriteIdaPadding(std::ofstream& file, std::int32_t offset, size_t size) {
    if (size == 0) {
        return;
    }

    file << "    uint8_t _pad" << std::hex << std::setw(4) << std::setfill('0')
         << offset << std::dec << std::setfill(' ') << "[0x" << std::hex << size
         << std::dec << "];\n";
}

std::string EnumUnderlyingType(const SchemaEnum& schemaEnum) {
    switch (schemaEnum.size) {
        case 1: return "std::uint8_t";
        case 2: return "std::uint16_t";
        case 8: return "std::uint64_t";
        default: return "std::uint32_t";
    }
}

bool HasNegativeEnumValue(const SchemaEnum& schemaEnum) {
    return std::any_of(schemaEnum.fields.begin(), schemaEnum.fields.end(), [](const SchemaEnumField& field) {
        return field.value < 0;
    });
}

std::string FormatIntegerLiteral(std::int64_t value) {
    if (value < 0) {
        return std::to_string(value);
    }

    return FormatHex(static_cast<std::uint64_t>(value), true);
}

bool IsKeyword(const std::string& value, std::initializer_list<std::string_view> keywords) {
    return std::any_of(keywords.begin(), keywords.end(), [&](std::string_view keyword) {
        return value == keyword;
    });
}

std::string CSharpIdentifier(const std::string& value) {
    if (IsKeyword(value, {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
        "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is",
        "lock", "long", "namespace", "new", "null", "object", "operator", "out", "override",
        "params", "private", "protected", "public", "readonly", "ref", "return", "sbyte",
        "sealed", "short", "sizeof", "stackalloc", "static", "string", "struct", "switch",
        "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe",
        "ushort", "using", "virtual", "void", "volatile", "while"
    })) {
        return "@" + value;
    }

    return value;
}

std::string RustIdentifier(const std::string& value) {
    if (IsKeyword(value, { "self", "Self", "super", "crate" })) {
        return value + "_";
    }

    if (IsKeyword(value, {
        "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
        "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
        "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
        "trait", "true", "type", "unsafe", "use", "where", "while"
    })) {
        return "r#" + value;
    }

    return value;
}

std::string ZigIdentifier(const std::string& value) {
    if (IsKeyword(value, {
        "addrspace", "align", "allowzero", "and", "anyerror", "anyframe", "anytype", "asm",
        "async", "await", "break", "callconv", "catch", "comptime", "const", "continue",
        "defer", "else", "enum", "errdefer", "error", "export", "extern", "fn", "for",
        "if", "inline", "linksection", "noalias", "noinline", "nosuspend", "opaque", "or",
        "orelse", "packed", "pub", "resume", "return", "struct", "suspend", "switch",
        "test", "threadlocal", "try", "type", "union", "unreachable", "usingnamespace",
        "var", "volatile", "while"
    })) {
        return "@\"" + value + "\"";
    }

    return value;
}

std::string CSharpEnumType(const SchemaEnum& schemaEnum) {
    const bool isSigned = HasNegativeEnumValue(schemaEnum);
    switch (schemaEnum.size) {
        case 1: return isSigned ? "sbyte" : "byte";
        case 2: return isSigned ? "short" : "ushort";
        case 8: return isSigned ? "long" : "ulong";
        default: return isSigned ? "int" : "uint";
    }
}

std::string RustEnumRepr(const SchemaEnum& schemaEnum) {
    const bool isSigned = HasNegativeEnumValue(schemaEnum);
    switch (schemaEnum.size) {
        case 1: return isSigned ? "i8" : "u8";
        case 2: return isSigned ? "i16" : "u16";
        case 8: return isSigned ? "i64" : "u64";
        default: return isSigned ? "i32" : "u32";
    }
}

std::string ZigEnumTag(const SchemaEnum& schemaEnum) {
    const bool isSigned = HasNegativeEnumValue(schemaEnum);
    switch (schemaEnum.size) {
        case 1: return isSigned ? "i8" : "u8";
        case 2: return isSigned ? "i16" : "u16";
        case 8: return isSigned ? "i64" : "u64";
        default: return isSigned ? "i32" : "u32";
    }
}

void WriteCSharpModule(const std::filesystem::path& outputPath, const SchemaModule& module) {
    std::ofstream file(outputPath);
    const std::string moduleClass = SanitizeTypeName(module.moduleName, "Module");

    file << "// Generated by cs2sign SDK generator from read-only schema JSON.\n";
    file << "// Module: " << module.moduleName << "\n\n";
    file << "namespace Cs2Sign.Schemas {\n";
    file << "    public static class " << CSharpIdentifier(moduleClass) << " {\n";

    for (const SchemaEnum& schemaEnum : module.enums) {
        const std::string enumName = SanitizeTypeName(schemaEnum.name, "UnnamedEnum");
        file << "        public enum " << CSharpIdentifier(enumName) << " : " << CSharpEnumType(schemaEnum) << " {\n";

        std::set<std::string> usedEnumNames;
        for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
            const SchemaEnumField& enumField = schemaEnum.fields[index];
            const std::string itemName = MakeUniqueIdentifier(enumField.name, usedEnumNames, "Value");
            file << "            " << CSharpIdentifier(itemName) << " = " << FormatIntegerLiteral(enumField.value)
                 << (index + 1 == schemaEnum.fields.size() ? "" : ",") << "\n";
        }

        file << "        }\n\n";
    }

    std::set<std::string> usedClassNames;
    for (const SchemaClass& schemaClass : module.classes) {
        const std::string className = MakeUniqueIdentifier(schemaClass.name, usedClassNames, "UnnamedClass");
        file << "        public static class " << CSharpIdentifier(className) << " {\n";
        if (schemaClass.size > 0) {
            file << "            public const nint Size = " << FormatHex(static_cast<std::uint32_t>(schemaClass.size)) << ";\n";
        }

        std::set<std::string> usedFieldNames;
        for (const SchemaField& field : schemaClass.fields) {
            const std::string fieldName = MakeUniqueIdentifier(field.name, usedFieldNames, "Field");
            file << "            public const nint " << CSharpIdentifier(fieldName) << " = "
                 << FormatHex(static_cast<std::uint32_t>(field.offset)) << ";";
            if (!field.typeName.empty()) {
                file << " // " << CommentText(field.typeName);
            }
            file << "\n";
        }
        file << "        }\n\n";
    }

    file << "    }\n";
    file << "}\n";
}

void WriteRustModule(const std::filesystem::path& outputPath, const SchemaModule& module) {
    std::ofstream file(outputPath);
    const std::string moduleName = SanitizeIdentifier(module.moduleName, "module");

    file << "// Generated by cs2sign SDK generator from read-only schema JSON.\n";
    file << "// Module: " << module.moduleName << "\n\n";
    file << "#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]\n\n";
    file << "pub mod cs2sign {\n";
    file << "    pub mod schemas {\n";
    file << "        pub mod " << RustIdentifier(moduleName) << " {\n";

    for (const SchemaEnum& schemaEnum : module.enums) {
        const std::string enumName = SanitizeTypeName(schemaEnum.name, "UnnamedEnum");
        file << "            pub mod " << RustIdentifier(enumName) << " {\n";
        file << "                pub type Type = " << RustEnumRepr(schemaEnum) << ";\n";

        std::set<std::string> usedEnumNames;
        for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
            const SchemaEnumField& enumField = schemaEnum.fields[index];
            const std::string itemName = MakeUniqueIdentifier(enumField.name, usedEnumNames, "Value");
            file << "                pub const " << RustIdentifier(itemName) << ": Type = "
                 << FormatIntegerLiteral(enumField.value) << ";\n";
        }

        file << "            }\n\n";
    }

    std::set<std::string> usedClassNames;
    for (const SchemaClass& schemaClass : module.classes) {
        const std::string className = MakeUniqueIdentifier(schemaClass.name, usedClassNames, "unnamed_class");
        file << "            pub mod " << RustIdentifier(className) << " {\n";
        if (schemaClass.size > 0) {
            file << "                pub const SIZE: usize = " << FormatHex(static_cast<std::uint32_t>(schemaClass.size)) << ";\n";
        }

        std::set<std::string> usedFieldNames;
        for (const SchemaField& field : schemaClass.fields) {
            const std::string fieldName = MakeUniqueIdentifier(field.name, usedFieldNames, "field");
            file << "                pub const " << RustIdentifier(fieldName) << ": usize = "
                 << FormatHex(static_cast<std::uint32_t>(field.offset)) << ";";
            if (!field.typeName.empty()) {
                file << " // " << CommentText(field.typeName);
            }
            file << "\n";
        }
        file << "            }\n\n";
    }

    file << "        }\n";
    file << "    }\n";
    file << "}\n";
}

void WriteZigModule(const std::filesystem::path& outputPath, const SchemaModule& module) {
    std::ofstream file(outputPath);
    const std::string moduleName = SanitizeIdentifier(module.moduleName, "module");

    file << "// Generated by cs2sign SDK generator from read-only schema JSON.\n";
    file << "// Module: " << module.moduleName << "\n\n";
    file << "pub const cs2sign = struct {\n";
    file << "    pub const schemas = struct {\n";
    file << "        pub const " << ZigIdentifier(moduleName) << " = struct {\n";

    for (const SchemaEnum& schemaEnum : module.enums) {
        const std::string enumName = SanitizeTypeName(schemaEnum.name, "UnnamedEnum");
        file << "            pub const " << ZigIdentifier(enumName) << " = struct {\n";
        file << "                pub const Type = " << ZigEnumTag(schemaEnum) << ";\n";

        std::set<std::string> usedEnumNames;
        for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
            const SchemaEnumField& enumField = schemaEnum.fields[index];
            const std::string itemName = MakeUniqueIdentifier(enumField.name, usedEnumNames, "Value");
            file << "                pub const " << ZigIdentifier(itemName) << ": Type = "
                 << FormatIntegerLiteral(enumField.value) << ";\n";
        }

        file << "            };\n\n";
    }

    std::set<std::string> usedClassNames;
    for (const SchemaClass& schemaClass : module.classes) {
        const std::string className = MakeUniqueIdentifier(schemaClass.name, usedClassNames, "unnamed_class");
        file << "            pub const " << ZigIdentifier(className) << " = struct {\n";
        if (schemaClass.size > 0) {
            file << "                pub const SIZE: usize = " << FormatHex(static_cast<std::uint32_t>(schemaClass.size)) << ";\n";
        }

        std::set<std::string> usedFieldNames;
        for (const SchemaField& field : schemaClass.fields) {
            const std::string fieldName = MakeUniqueIdentifier(field.name, usedFieldNames, "field");
            file << "                pub const " << ZigIdentifier(fieldName) << ": usize = "
                 << FormatHex(static_cast<std::uint32_t>(field.offset)) << ";";
            if (!field.typeName.empty()) {
                file << " // " << CommentText(field.typeName);
            }
            file << "\n";
        }
        file << "            };\n\n";
    }

    file << "        };\n";
    file << "    };\n";
    file << "};\n";
}

void WriteCppModule(const std::filesystem::path& outputPath, const SchemaModule& module) {
    std::ofstream file(outputPath);
    const std::string moduleNamespace = SanitizeIdentifier(module.moduleName, "module");

    WriteCppPrelude(file);
    file << "// Generated by cs2sign SDK generator from read-only schema JSON.\n";
    file << "// Module: " << module.moduleName << "\n";
    file << "// Classes: " << module.classes.size() << "\n";
    file << "// Enums: " << module.enums.size() << "\n\n";
    file << "namespace cs2::sdk::" << moduleNamespace << " {\n\n";
    WriteCppCommonTypes(file);

    if (!module.enums.empty()) {
        file << "namespace enums {\n\n";
        for (const SchemaEnum& schemaEnum : module.enums) {
            const std::string enumName = SanitizeTypeName(schemaEnum.name, "UnnamedEnum");
            file << "enum class " << enumName << " : " << EnumUnderlyingType(schemaEnum) << " {\n";

            std::set<std::string> usedEnumNames;
            for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
                const SchemaEnumField& enumField = schemaEnum.fields[index];
                const std::string itemName = MakeUniqueIdentifier(enumField.name, usedEnumNames, "Value");
                file << "    " << itemName << " = " << enumField.value
                     << (index + 1 == schemaEnum.fields.size() ? "" : ",") << "\n";
            }

            file << "};\n\n";
        }
        file << "} // namespace enums\n\n";
    }

    file << "namespace classes {\n\n";
    file << "#pragma pack(push, 1)\n\n";

    for (const SchemaClass& schemaClass : module.classes) {
        const std::string className = SanitizeTypeName(schemaClass.name, "UnnamedClass");
        WriteMetadataComments(file, schemaClass.metadata, "");
        if (!schemaClass.baseClassName.empty()) {
            file << "// Base: " << CommentText(schemaClass.baseClassName) << "\n";
        }
        file << "struct " << className << " {\n";

        const std::vector<EmittedField> fields = BuildFieldPlan(schemaClass);
        std::int32_t cursor = 0;
        for (const EmittedField& field : fields) {
            if (field.offset > cursor) {
                WriteCppPadding(file, cursor, static_cast<size_t>(field.offset - cursor));
            }

            WriteMetadataComments(file, field.metadata, "    ");
            if (field.byteArray) {
                file << "    std::byte " << field.name << "[0x" << std::hex << field.emittedSize << std::dec << "];";
            } else {
                file << "    " << field.cppType << " " << field.name << ";";
            }
            file << " // 0x" << std::hex << field.offset << std::dec;
            if (!field.originalType.empty()) {
                file << " " << CommentText(field.originalType);
            }
            file << "\n";
            cursor = field.offset + static_cast<std::int32_t>(field.emittedSize);
        }

        if (schemaClass.size > cursor) {
            WriteCppPadding(file, cursor, static_cast<size_t>(schemaClass.size - cursor));
        }

        file << "};\n";
        if (schemaClass.size > 0) {
            file << "static_assert(sizeof(" << className << ") == 0x"
                 << std::hex << schemaClass.size << std::dec << ");\n";
        }
        for (const EmittedField& field : fields) {
            file << "static_assert(offsetof(" << className << ", " << field.name << ") == 0x"
                 << std::hex << field.offset << std::dec << ");\n";
        }
        file << "\n";
    }

    file << "#pragma pack(pop)\n\n";
    file << "} // namespace classes\n\n";
    file << "} // namespace cs2::sdk::" << moduleNamespace << "\n";
}

void WriteIdaEnum(std::ofstream& file, const std::string& modulePrefix, const SchemaEnum& schemaEnum) {
    const std::string enumName = modulePrefix + "_" + SanitizeTypeName(schemaEnum.name, "UnnamedEnum");
    file << "enum " << enumName << " {\n";
    std::set<std::string> usedEnumNames;
    for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
        const SchemaEnumField& enumField = schemaEnum.fields[index];
        const std::string itemName = MakeUniqueIdentifier(enumField.name, usedEnumNames, "Value");
        file << "    " << enumName << "_" << itemName << " = " << enumField.value
             << (index + 1 == schemaEnum.fields.size() ? "" : ",") << "\n";
    }
    file << "};\n\n";
}

void WriteIdaClass(std::ofstream& file, const std::string& modulePrefix, const SchemaClass& schemaClass) {
    const std::string className = modulePrefix + "_" + SanitizeTypeName(schemaClass.name, "UnnamedClass");
    WriteMetadataComments(file, schemaClass.metadata, "");
    if (!schemaClass.baseClassName.empty()) {
        file << "// Base: " << CommentText(schemaClass.baseClassName) << "\n";
    }
    file << "struct " << className << " {\n";

    const std::vector<EmittedField> fields = BuildFieldPlan(schemaClass);
    std::int32_t cursor = 0;
    for (const EmittedField& field : fields) {
        if (field.offset > cursor) {
            WriteIdaPadding(file, cursor, static_cast<size_t>(field.offset - cursor));
        }

        WriteMetadataComments(file, field.metadata, "    ");
        if (field.byteArray) {
            file << "    uint8_t " << field.name << "[0x" << std::hex << field.emittedSize << std::dec << "];";
        } else {
            file << "    " << field.cType << " " << field.name << ";";
        }
        file << " // 0x" << std::hex << field.offset << std::dec;
        if (!field.originalType.empty()) {
            file << " " << CommentText(field.originalType);
        }
        file << "\n";
        cursor = field.offset + static_cast<std::int32_t>(field.emittedSize);
    }

    if (schemaClass.size > cursor) {
        WriteIdaPadding(file, cursor, static_cast<size_t>(schemaClass.size - cursor));
    }

    file << "};\n\n";
}

void WriteIdaHeader(const std::filesystem::path& outputPath, const std::vector<SchemaModule>& modules) {
    std::ofstream file(outputPath);
    WriteIdaPrelude(file);

    for (const SchemaModule& module : modules) {
        const std::string modulePrefix = SanitizeIdentifier(module.moduleName, "module");
        file << "// Module: " << module.moduleName << "\n\n";

        for (const SchemaEnum& schemaEnum : module.enums) {
            WriteIdaEnum(file, modulePrefix, schemaEnum);
        }

        for (const SchemaClass& schemaClass : module.classes) {
            WriteIdaClass(file, modulePrefix, schemaClass);
        }
    }

    file << "#pragma pack(pop)\n\n";
    file << "#endif // CS2SIGN_SDK_IDA_H\n";
}

std::vector<SchemaMetadata> ParseMetadataArray(const JsonValue& owner) {
    std::vector<SchemaMetadata> metadata;
    const std::vector<JsonValue>* metadataItems = GetArrayMember(owner, "metadata");
    if (!metadataItems) {
        return metadata;
    }

    for (const JsonValue& item : *metadataItems) {
        if (item.type != JsonValue::Type::Object) {
            continue;
        }

        SchemaMetadata entry;
        entry.type = GetStringMember(item, "type");
        entry.name = GetStringMember(item, "name");
        entry.typeName = GetStringMember(item, "type_name");
        metadata.push_back(std::move(entry));
    }

    return metadata;
}

bool LoadSchemaModule(const std::filesystem::path& path, SchemaModule& module, std::string& error) {
    std::ifstream input(path);
    if (!input) {
        error = "failed to open " + path.string();
        return false;
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string jsonText = buffer.str();

    JsonValue root;
    JsonReader reader(jsonText);
    if (!reader.Parse(root, error)) {
        error = path.string() + ": " + error;
        return false;
    }

    if (root.type != JsonValue::Type::Object) {
        error = path.string() + ": root json value is not an object";
        return false;
    }

    module = {};
    module.sourcePath = path;
    module.moduleName = GetStringMember(root, "module");
    if (module.moduleName.empty()) {
        module.moduleName = path.stem().string();
    }

    if (const std::vector<JsonValue>* classes = GetArrayMember(root, "classes")) {
        for (const JsonValue& classValue : *classes) {
            if (classValue.type != JsonValue::Type::Object) {
                continue;
            }

            SchemaClass schemaClass;
            schemaClass.name = GetStringMember(classValue, "name");
            schemaClass.baseClassName = GetStringMember(classValue, "base_class");
            schemaClass.size = static_cast<std::int32_t>(GetNumberMember(classValue, "size"));
            schemaClass.metadata = ParseMetadataArray(classValue);

            if (const std::vector<JsonValue>* fields = GetArrayMember(classValue, "fields")) {
                for (const JsonValue& fieldValue : *fields) {
                    if (fieldValue.type != JsonValue::Type::Object) {
                        continue;
                    }

                    SchemaField field;
                    field.name = GetStringMember(fieldValue, "name");
                    field.typeName = GetStringMember(fieldValue, "type");
                    field.offset = static_cast<std::int32_t>(GetNumberMember(fieldValue, "offset"));
                    field.metadata = ParseMetadataArray(fieldValue);
                    schemaClass.fields.push_back(std::move(field));
                }
            }

            if (!schemaClass.name.empty()) {
                module.classes.push_back(std::move(schemaClass));
            }
        }
    }

    if (const std::vector<JsonValue>* enums = GetArrayMember(root, "enums")) {
        for (const JsonValue& enumValue : *enums) {
            if (enumValue.type != JsonValue::Type::Object) {
                continue;
            }

            SchemaEnum schemaEnum;
            schemaEnum.name = GetStringMember(enumValue, "name");
            schemaEnum.size = static_cast<std::int32_t>(GetNumberMember(enumValue, "size", 4));

            if (const std::vector<JsonValue>* fields = GetArrayMember(enumValue, "fields")) {
                for (const JsonValue& fieldValue : *fields) {
                    if (fieldValue.type != JsonValue::Type::Object) {
                        continue;
                    }

                    SchemaEnumField field;
                    field.name = GetStringMember(fieldValue, "name");
                    field.value = GetNumberMember(fieldValue, "value");
                    schemaEnum.fields.push_back(std::move(field));
                }
            }

            if (!schemaEnum.name.empty()) {
                module.enums.push_back(std::move(schemaEnum));
            }
        }
    }

    return true;
}

std::vector<SchemaModule> LoadSchemaModules(const std::filesystem::path& schemaDirectory, std::string& error) {
    std::vector<SchemaModule> modules;

    if (!std::filesystem::is_directory(schemaDirectory)) {
        error = "schema directory does not exist: " + schemaDirectory.string();
        return modules;
    }

    for (const auto& entry : std::filesystem::directory_iterator(schemaDirectory)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".json") {
            continue;
        }

        SchemaModule module;
        if (!LoadSchemaModule(entry.path(), module, error)) {
            modules.clear();
            return modules;
        }

        modules.push_back(std::move(module));
    }

    std::sort(modules.begin(), modules.end(), [](const SchemaModule& left, const SchemaModule& right) {
        return left.moduleName < right.moduleName;
    });

    return modules;
}
} // namespace

SdkGenerationReport GenerateSdkFromSchemas(const SdkGenerationOptions& options) {
    SdkGenerationReport report;
    report.cppDirectory = options.outputDirectory / "cpp";
    report.csharpDirectory = options.outputDirectory / "csharp";
    report.rustDirectory = options.outputDirectory / "rust";
    report.zigDirectory = options.outputDirectory / "zig";
    report.idaHeader = options.outputDirectory / "ida.h";

    try {
        std::string error;
        std::vector<SchemaModule> modules = LoadSchemaModules(options.schemaDirectory, error);
        if (!error.empty()) {
            report.error = error;
            return report;
        }

        if (modules.empty()) {
            report.error = "no schema json files found in " + options.schemaDirectory.string();
            return report;
        }

        if (!EnsureDirectory(options.outputDirectory)) {
            report.error = "failed to create sdk output directory";
            return report;
        }

        if (options.emitCpp && !EnsureDirectory(report.cppDirectory)) {
            report.error = "failed to create cpp sdk output directory";
            return report;
        }

        if (options.emitCSharp && !EnsureDirectory(report.csharpDirectory)) {
            report.error = "failed to create csharp sdk output directory";
            return report;
        }

        if (options.emitRust && !EnsureDirectory(report.rustDirectory)) {
            report.error = "failed to create rust sdk output directory";
            return report;
        }

        if (options.emitZig && !EnsureDirectory(report.zigDirectory)) {
            report.error = "failed to create zig sdk output directory";
            return report;
        }

        for (const SchemaModule& module : modules) {
            ++report.moduleCount;
            report.classCount += module.classes.size();
            report.enumCount += module.enums.size();

            const std::string outputName = SanitizeIdentifier(module.moduleName, "module");

            if (options.emitCpp) {
                const std::filesystem::path outputPath = report.cppDirectory / (outputName + ".hpp");
                WriteCppModule(outputPath, module);
                ++report.cppFileCount;
            }

            if (options.emitCSharp) {
                WriteCSharpModule(report.csharpDirectory / (outputName + ".cs"), module);
                ++report.csharpFileCount;
            }

            if (options.emitRust) {
                WriteRustModule(report.rustDirectory / (outputName + ".rs"), module);
                ++report.rustFileCount;
            }

            if (options.emitZig) {
                WriteZigModule(report.zigDirectory / (outputName + ".zig"), module);
                ++report.zigFileCount;
            }
        }

        if (options.emitIda) {
            WriteIdaHeader(report.idaHeader, modules);
        }

        report.success = true;
        return report;
    } catch (const std::exception& exception) {
        report.error = exception.what();
        return report;
    } catch (...) {
        report.error = "unknown sdk generation failure";
        return report;
    }
}
