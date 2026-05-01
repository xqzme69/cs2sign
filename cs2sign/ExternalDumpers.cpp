#include "ExternalDumpers.h"

#include "DumpUtils.h"
#include "JsonReader.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace {
constexpr size_t kMaxTypeScopes = 512;
constexpr size_t kMaxHashElements = 100000;
constexpr size_t kMaxFields = 4096;
constexpr size_t kMaxMetadata = 256;
constexpr size_t kMaxEnums = 4096;
constexpr size_t kMaxSchemaClassesTotal = 50000;
constexpr size_t kMaxSchemaFieldsTotal = 500000;
constexpr size_t kMaxSchemaEnumsTotal = 50000;
constexpr size_t kMaxSchemaEnumValuesTotal = 500000;
constexpr size_t kMaxInterfacesPerModule = 4096;
constexpr std::int32_t kMaxClassSize = 0x400000;
constexpr std::uint32_t kMaxReasonableFieldOffset = 0x1000000;

struct RemoteUtlVector {
    std::int32_t count;
    std::int32_t pad0;
    std::uint64_t data;
};

struct RemoteTsListBase {
    std::uint64_t headNext;
};

struct RemoteUtlMemoryPool {
    std::int32_t blockSize;
    std::int32_t blocksPerBlob;
    std::uint32_t growMode;
    std::int32_t blocksAllocated;
    std::int32_t peakAllocated;
    std::uint16_t alignment;
    std::uint16_t blobCount;
    std::uint8_t pad0[0x2];
    RemoteTsListBase freeBlocks;
    std::uint8_t pad1[0x20];
    std::uint64_t blobHead;
    std::int32_t totalSize;
    std::uint8_t pad2[0xC];
};

struct RemoteUtlTsHashFixedData {
    std::uint64_t key;
    std::uint64_t next;
    std::uint64_t data;
};

struct RemoteUtlTsHashAllocatedBlob {
    std::uint64_t next;
    std::uint8_t pad0[0x8];
    std::uint64_t data;
    std::uint8_t pad1[0x18];
};

struct RemoteUtlTsHashBucket {
    std::uint64_t addLock;
    std::uint64_t first;
    std::uint64_t firstUncommitted;
};

struct RemoteUtlTsHash256 {
    RemoteUtlMemoryPool entryMemory;
    RemoteUtlTsHashBucket buckets[256];
    bool needsCommit;
    std::uint8_t pad0[0x3];
    std::int32_t contentionCheck;
    std::uint8_t pad1[0x8];
};

struct RemoteSchemaClassInfoData {
    std::uint64_t base;
    std::uint64_t name;
    std::uint64_t binaryName;
    std::uint64_t moduleName;
    std::int32_t size;
    std::int16_t fieldCount;
    std::int16_t staticMetadataCount;
    std::uint8_t pad0[0x2];
    std::uint8_t alignment;
    std::uint8_t hasBaseClass;
    std::int16_t totalClassSize;
    std::int16_t derivedClassSize;
    std::uint64_t fields;
    std::uint8_t pad1[0x8];
    std::uint64_t baseClasses;
    std::uint64_t staticMetadata;
    std::uint8_t pad2[0x8];
    std::uint64_t typeScope;
    std::uint64_t type;
    std::uint8_t pad3[0x10];
};

struct RemoteSchemaClassFieldData {
    std::uint64_t name;
    std::uint64_t type;
    std::int32_t offset;
    std::int32_t metadataCount;
    std::uint64_t metadata;
};

struct RemoteSchemaMetadataEntryData {
    std::uint64_t name;
    std::uint64_t networkValue;
};

struct RemoteSchemaEnumInfoData {
    std::uint64_t base;
    std::uint64_t name;
    std::uint64_t moduleName;
    std::uint8_t size;
    std::uint8_t alignment;
    std::uint8_t flags;
    std::uint8_t pad0;
    std::uint16_t enumeratorCount;
    std::uint16_t staticMetadataCount;
    std::uint64_t enumerators;
    std::uint64_t staticMetadata;
    std::uint64_t typeScope;
    std::int64_t minEnumeratorValue;
    std::int64_t maxEnumeratorValue;
};

struct RemoteSchemaEnumeratorInfoData {
    std::uint64_t name;
    std::uint64_t value;
    std::int32_t metadataCount;
    std::uint8_t pad0[0x4];
    std::uint64_t metadata;
};

struct RemoteInterfaceReg {
    std::uint64_t createFn;
    std::uint64_t name;
    std::uint64_t next;
};

static_assert(offsetof(RemoteUtlMemoryPool, freeBlocks) == 0x20);
static_assert(offsetof(RemoteUtlMemoryPool, blobHead) == 0x48);
static_assert(offsetof(RemoteUtlTsHash256, buckets) == 0x60);
static_assert(offsetof(RemoteSchemaClassInfoData, fields) == 0x30);
static_assert(offsetof(RemoteSchemaClassInfoData, baseClasses) == 0x40);
static_assert(offsetof(RemoteSchemaClassInfoData, staticMetadata) == 0x48);
static_assert(offsetof(RemoteSchemaClassInfoData, typeScope) == 0x58);

struct SchemaMetadata {
    std::string type;
    std::string name;
    std::string typeName;
};

struct SchemaFieldInfo {
    std::string name;
    std::string typeName;
    std::int32_t offset = 0;
    std::vector<SchemaMetadata> metadata;
};

struct SchemaClassInfo {
    std::string name;
    std::string binaryName;
    std::string moduleName;
    std::string baseClassName;
    std::int32_t size = 0;
    std::vector<SchemaFieldInfo> fields;
    std::vector<SchemaMetadata> metadata;
};

struct SchemaEnumFieldInfo {
    std::string name;
    std::int64_t value = 0;
};

struct SchemaEnumInfo {
    std::string name;
    std::string moduleName;
    std::uint8_t size = 0;
    std::vector<SchemaEnumFieldInfo> fields;
};

struct SchemaModuleDump {
    std::string name;
    std::vector<SchemaClassInfo> classes;
    std::vector<SchemaEnumInfo> enums;
};

struct InterfaceInfo {
    std::string module;
    std::string name;
    std::uint32_t instanceRva = 0;
};

struct KnownOffsetInfo {
    std::string module;
    std::string name;
    bool found = false;
    std::uint32_t rva = 0;
    std::string error;
    std::string source = "pattern";
    std::string resultType = "module_rva";
    std::string validationStatus = "not_run";
    std::string validationError;
};

struct ResolvedSignatureInfo {
    std::string module;
    std::string name;
    std::string resultType;
    std::string valueField = "module_rva";
    std::uint32_t value = 0;
};

struct OffsetDumpResult {
    DumperStatus knownOffsets;
    DumperStatus resolvedSignatures;
};

template <typename T>
bool ReadRemote(ProcessMemoryReader& process, std::uint64_t address, T& value) {
    if (address == 0 || address > static_cast<std::uint64_t>((std::numeric_limits<uintptr_t>::max)())) {
        return false;
    }

    return process.Read(static_cast<uintptr_t>(address), value);
}

bool ReadRemotePointer(ProcessMemoryReader& process, std::uint64_t address, std::uint64_t& value) {
    value = 0;
    return ReadRemote(process, address, value);
}

bool ReadRemoteString(ProcessMemoryReader& process, std::uint64_t address, std::string& value, size_t maxLength = 256) {
    if (address == 0 || address > static_cast<std::uint64_t>((std::numeric_limits<uintptr_t>::max)())) {
        value.clear();
        return false;
    }

    return process.ReadString(static_cast<uintptr_t>(address), value, maxLength);
}

std::string ReadStringOrEmpty(ProcessMemoryReader& process, std::uint64_t address, size_t maxLength = 256) {
    std::string value;
    ReadRemoteString(process, address, value, maxLength);
    return value;
}

bool IsSaneSchemaText(const std::string& value, size_t maxLength = 256) {
    if (value.empty() || value.size() > maxLength) {
        return false;
    }

    bool hasNameCharacter = false;
    for (unsigned char character : value) {
        if (character < 0x20 || character > 0x7e) {
            return false;
        }

        if (std::isalnum(character) || character == '_') {
            hasNameCharacter = true;
        }
    }

    return hasNameCharacter;
}

bool IsSaneClassInfo(const RemoteSchemaClassInfoData& remoteClass, const std::string& name) {
    if (!IsSaneSchemaText(name)) {
        return false;
    }

    if (remoteClass.size <= 0 || remoteClass.size > kMaxClassSize) {
        return false;
    }

    if (remoteClass.fieldCount < 0 || static_cast<size_t>(remoteClass.fieldCount) > kMaxFields) {
        return false;
    }

    if (remoteClass.staticMetadataCount < 0 ||
        static_cast<size_t>(remoteClass.staticMetadataCount) > kMaxMetadata) {
        return false;
    }

    return true;
}

bool IsSaneFieldInfo(const RemoteSchemaClassFieldData& remoteField, const std::string& name, std::int32_t classSize) {
    if (!IsSaneSchemaText(name)) {
        return false;
    }

    if (remoteField.offset < 0 || remoteField.offset > classSize + 0x1000) {
        return false;
    }

    if (remoteField.metadataCount < 0 || static_cast<size_t>(remoteField.metadataCount) > kMaxMetadata) {
        return false;
    }

    return true;
}

bool IsSaneEnumInfo(const RemoteSchemaEnumInfoData& remoteEnum, const std::string& name) {
    if (!IsSaneSchemaText(name)) {
        return false;
    }

    if (remoteEnum.size != 1 && remoteEnum.size != 2 && remoteEnum.size != 4 && remoteEnum.size != 8) {
        return false;
    }

    if (remoteEnum.enumeratorCount > kMaxEnums || remoteEnum.staticMetadataCount > kMaxMetadata) {
        return false;
    }

    return true;
}

std::vector<std::uint64_t> ReadTsHashElements(ProcessMemoryReader& process, std::uint64_t hashAddress) {
    RemoteUtlTsHash256 hash{};
    if (!ReadRemote(process, hashAddress, hash)) {
        return {};
    }

    const size_t usedCount = hash.entryMemory.blocksAllocated > 0
        ? (std::min)(static_cast<size_t>(hash.entryMemory.blocksAllocated), kMaxHashElements)
        : 0;
    const size_t freeCount = hash.entryMemory.peakAllocated > 0
        ? (std::min)(static_cast<size_t>(hash.entryMemory.peakAllocated), kMaxHashElements)
        : 0;

    std::vector<std::uint64_t> elements;
    elements.reserve((std::min)(usedCount + freeCount, kMaxHashElements));

    for (const RemoteUtlTsHashBucket& bucket : hash.buckets) {
        std::uint64_t nodeAddress = bucket.firstUncommitted;
        size_t guard = 0;

        while (nodeAddress != 0 && guard++ < usedCount + 256 && elements.size() < kMaxHashElements) {
            RemoteUtlTsHashFixedData node{};
            if (!ReadRemote(process, nodeAddress, node)) {
                break;
            }

            if (node.data != 0) {
                elements.push_back(node.data);
            }

            nodeAddress = node.next;
        }
    }

    std::uint64_t blobAddress = hash.entryMemory.freeBlocks.headNext;
    size_t blobGuard = 0;
    while (blobAddress != 0 && blobGuard++ < freeCount + 256 && elements.size() < kMaxHashElements) {
        RemoteUtlTsHashAllocatedBlob blob{};
        if (!ReadRemote(process, blobAddress, blob)) {
            break;
        }

        if (blob.data != 0) {
            elements.push_back(blob.data);
        }

        blobAddress = blob.next;
    }

    std::unordered_set<std::uint64_t> seen;
    elements.erase(
        std::remove_if(elements.begin(), elements.end(), [&](std::uint64_t pointer) {
            return pointer == 0 || !seen.insert(pointer).second;
        }),
        elements.end()
    );

    return elements;
}

std::vector<SchemaMetadata> ReadMetadataEntries(
    ProcessMemoryReader& process,
    std::uint64_t metadataAddress,
    std::int32_t metadataCount
) {
    std::vector<SchemaMetadata> metadata;
    if (metadataAddress == 0 || metadataCount <= 0) {
        return metadata;
    }

    const size_t count = (std::min)(static_cast<size_t>(metadataCount), kMaxMetadata);
    metadata.reserve(count);

    for (size_t index = 0; index < count; ++index) {
        RemoteSchemaMetadataEntryData entry{};
        const std::uint64_t entryAddress = metadataAddress + index * sizeof(RemoteSchemaMetadataEntryData);
        if (!ReadRemote(process, entryAddress, entry) || entry.name == 0) {
            continue;
        }

        const std::string metadataName = ReadStringOrEmpty(process, entry.name);
        if (metadataName.empty()) {
            continue;
        }

        SchemaMetadata item;
        item.name = metadataName;

        if (metadataName == "MNetworkChangeCallback" && entry.networkValue != 0) {
            std::uint64_t callbackName = 0;
            if (ReadRemotePointer(process, entry.networkValue, callbackName)) {
                item.type = "NetworkChangeCallback";
                item.name = ReadStringOrEmpty(process, callbackName);
            }
        } else if (metadataName == "MNetworkVarNames" && entry.networkValue != 0) {
            std::uint64_t variableName = 0;
            std::uint64_t typeName = 0;
            if (ReadRemotePointer(process, entry.networkValue, variableName) &&
                ReadRemotePointer(process, entry.networkValue + sizeof(std::uint64_t), typeName)) {
                item.type = "NetworkVarNames";
                item.name = ReadStringOrEmpty(process, variableName);
                item.typeName = ReadStringOrEmpty(process, typeName);
                item.typeName.erase(
                    std::remove(item.typeName.begin(), item.typeName.end(), ' '),
                    item.typeName.end()
                );
            }
        } else {
            item.type = "Unknown";
        }

        if (!item.name.empty()) {
            metadata.push_back(item);
        }
    }

    return metadata;
}

std::string ReadSchemaTypeName(ProcessMemoryReader& process, std::uint64_t typeAddress) {
    if (typeAddress == 0) {
        return "unknown";
    }

    std::uint64_t nameAddress = 0;
    if (!ReadRemotePointer(process, typeAddress + 0x8, nameAddress)) {
        return "unknown";
    }

    std::string typeName = ReadStringOrEmpty(process, nameAddress);
    if (typeName.empty()) {
        return "unknown";
    }

    typeName.erase(std::remove(typeName.begin(), typeName.end(), ' '), typeName.end());
    return typeName;
}

std::string ReadBaseClassName(ProcessMemoryReader& process, const RemoteSchemaClassInfoData& remoteClass) {
    if (remoteClass.baseClasses == 0 || remoteClass.totalClassSize <= 0) {
        return {};
    }

    std::uint64_t baseClassAddress = 0;
    if (!ReadRemotePointer(process, remoteClass.baseClasses + 0x18, baseClassAddress) ||
        baseClassAddress == 0) {
        return {};
    }

    std::uint64_t baseNameAddress = 0;
    if (!ReadRemotePointer(process, baseClassAddress + 0x10, baseNameAddress)) {
        return {};
    }

    return SanitizeIdentifier(ReadStringOrEmpty(process, baseNameAddress), "");
}

std::optional<SchemaClassInfo> ReadSchemaClass(ProcessMemoryReader& process, std::uint64_t classAddress) {
    RemoteSchemaClassInfoData remoteClass{};
    if (!ReadRemote(process, classAddress, remoteClass)) {
        return std::nullopt;
    }

    const std::string rawName = ReadStringOrEmpty(process, remoteClass.name);
    if (!IsSaneClassInfo(remoteClass, rawName)) {
        return std::nullopt;
    }

    SchemaClassInfo info;
    info.name = SanitizeIdentifier(rawName, "");
    info.binaryName = ReadStringOrEmpty(process, remoteClass.binaryName);
    info.moduleName = ReadStringOrEmpty(process, remoteClass.moduleName);
    info.baseClassName = ReadBaseClassName(process, remoteClass);
    info.size = remoteClass.size;
    info.metadata = ReadMetadataEntries(process, remoteClass.staticMetadata, remoteClass.staticMetadataCount);

    if (remoteClass.fields != 0 && remoteClass.fieldCount > 0) {
        const size_t fieldCount = (std::min)(static_cast<size_t>(remoteClass.fieldCount), kMaxFields);
        info.fields.reserve(fieldCount);

        for (size_t index = 0; index < fieldCount; ++index) {
            RemoteSchemaClassFieldData remoteField{};
            const std::uint64_t fieldAddress = remoteClass.fields + index * sizeof(RemoteSchemaClassFieldData);
            if (!ReadRemote(process, fieldAddress, remoteField)) {
                continue;
            }

            const std::string rawFieldName = ReadStringOrEmpty(process, remoteField.name);
            if (!IsSaneFieldInfo(remoteField, rawFieldName, remoteClass.size)) {
                continue;
            }

            SchemaFieldInfo field;
            field.name = SanitizeIdentifier(rawFieldName, "");
            field.typeName = ReadSchemaTypeName(process, remoteField.type);
            field.offset = remoteField.offset;
            field.metadata = ReadMetadataEntries(process, remoteField.metadata, remoteField.metadataCount);
            info.fields.push_back(std::move(field));
        }
    }

    return info;
}

std::optional<SchemaEnumInfo> ReadSchemaEnum(ProcessMemoryReader& process, std::uint64_t enumAddress) {
    RemoteSchemaEnumInfoData remoteEnum{};
    if (!ReadRemote(process, enumAddress, remoteEnum)) {
        return std::nullopt;
    }

    const std::string rawName = ReadStringOrEmpty(process, remoteEnum.name);
    if (!IsSaneEnumInfo(remoteEnum, rawName)) {
        return std::nullopt;
    }

    SchemaEnumInfo info;
    info.name = SanitizeIdentifier(rawName, "");
    info.moduleName = ReadStringOrEmpty(process, remoteEnum.moduleName);
    info.size = remoteEnum.size;

    if (remoteEnum.enumerators != 0 && remoteEnum.enumeratorCount > 0) {
        const size_t enumCount = (std::min)(static_cast<size_t>(remoteEnum.enumeratorCount), kMaxEnums);
        info.fields.reserve(enumCount);

        for (size_t index = 0; index < enumCount; ++index) {
            RemoteSchemaEnumeratorInfoData remoteField{};
            const std::uint64_t fieldAddress = remoteEnum.enumerators + index * sizeof(RemoteSchemaEnumeratorInfoData);
            if (!ReadRemote(process, fieldAddress, remoteField)) {
                continue;
            }

            const std::string rawFieldName = ReadStringOrEmpty(process, remoteField.name);
            if (!IsSaneSchemaText(rawFieldName)) {
                continue;
            }

            SchemaEnumFieldInfo field;
            field.name = SanitizeIdentifier(rawFieldName, "");
            field.value = static_cast<std::int64_t>(remoteField.value);
            if (!field.name.empty()) {
                info.fields.push_back(std::move(field));
            }
        }
    }

    return info;
}

std::optional<std::uint64_t> FindSchemaSystem(ProcessMemoryReader& process) {
    ProcessModule module{};
    if (!process.GetModuleInfo(L"schemasystem.dll", module)) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> image;
    if (!ReadModuleImage(process, module, image)) {
        return std::nullopt;
    }

    std::vector<PatternByte> pattern;
    if (!ParseIdaPattern("4C 8D 35 ? ? ? ? 0F 28 45", pattern)) {
        return std::nullopt;
    }

    const auto match = FindPattern(image, pattern);
    if (!match) {
        return std::nullopt;
    }

    const auto targetRva = ResolveRipRelativeRva(image, *match, 3, 7);
    if (!targetRva) {
        return std::nullopt;
    }

    return static_cast<std::uint64_t>(module.base) + *targetRva;
}

std::vector<SchemaModuleDump> ReadSchemaModules(ProcessMemoryReader& process) {
    const auto schemaSystemAddress = FindSchemaSystem(process);
    if (!schemaSystemAddress) {
        throw std::runtime_error("schemasystem pattern was not found");
    }

    RemoteUtlVector typeScopes{};
    if (!ReadRemote(process, *schemaSystemAddress + 0x190, typeScopes) ||
        typeScopes.count <= 0 ||
        static_cast<size_t>(typeScopes.count) > kMaxTypeScopes ||
        typeScopes.data == 0) {
        throw std::runtime_error("schema type scope vector is invalid");
    }

    std::vector<SchemaModuleDump> modules;
    modules.reserve(static_cast<size_t>(typeScopes.count));
    size_t totalClasses = 0;
    size_t totalFields = 0;
    size_t totalEnums = 0;
    size_t totalEnumValues = 0;

    for (std::int32_t index = 0; index < typeScopes.count; ++index) {
        std::uint64_t typeScopeAddress = 0;
        if (!ReadRemotePointer(process, typeScopes.data + index * sizeof(std::uint64_t), typeScopeAddress) ||
            typeScopeAddress == 0) {
            continue;
        }

        char rawName[256]{};
        if (!process.ReadMemory(static_cast<uintptr_t>(typeScopeAddress + 0x8), rawName, sizeof(rawName))) {
            continue;
        }

        SchemaModuleDump module;
        module.name.assign(rawName, strnlen_s(rawName, sizeof(rawName)));
        if (module.name.empty()) {
            continue;
        }

        const std::vector<std::uint64_t> classes =
            ReadTsHashElements(process, typeScopeAddress + 0x560);
        for (std::uint64_t classAddress : classes) {
            auto classInfo = ReadSchemaClass(process, classAddress);
            if (classInfo) {
                if (totalClasses >= kMaxSchemaClassesTotal) {
                    throw std::runtime_error("schema class limit exceeded");
                }

                totalFields += classInfo->fields.size();
                if (totalFields > kMaxSchemaFieldsTotal) {
                    throw std::runtime_error("schema field limit exceeded");
                }

                ++totalClasses;
                module.classes.push_back(std::move(*classInfo));
            }
        }

        const std::vector<std::uint64_t> enums =
            ReadTsHashElements(process, typeScopeAddress + 0x1DD0);
        for (std::uint64_t enumAddress : enums) {
            auto enumInfo = ReadSchemaEnum(process, enumAddress);
            if (enumInfo) {
                if (totalEnums >= kMaxSchemaEnumsTotal) {
                    throw std::runtime_error("schema enum limit exceeded");
                }

                totalEnumValues += enumInfo->fields.size();
                if (totalEnumValues > kMaxSchemaEnumValuesTotal) {
                    throw std::runtime_error("schema enum value limit exceeded");
                }

                ++totalEnums;
                module.enums.push_back(std::move(*enumInfo));
            }
        }

        if (!module.classes.empty() || !module.enums.empty()) {
            std::sort(module.classes.begin(), module.classes.end(), [](const auto& left, const auto& right) {
                return left.name < right.name;
            });
            std::sort(module.enums.begin(), module.enums.end(), [](const auto& left, const auto& right) {
                return left.name < right.name;
            });
            modules.push_back(std::move(module));
        }
    }

    return modules;
}

void WriteMetadataJson(std::ofstream& file, const std::vector<SchemaMetadata>& metadata, int indent) {
    const std::string pad(static_cast<size_t>(indent), ' ');
    file << "[";
    if (!metadata.empty()) {
        file << "\n";
    }

    for (size_t index = 0; index < metadata.size(); ++index) {
        const SchemaMetadata& entry = metadata[index];
        file << pad << "  {\n";
        file << pad << "    \"type\": \"" << EscapeJson(entry.type) << "\",\n";
        file << pad << "    \"name\": \"" << EscapeJson(entry.name) << "\"";
        if (!entry.typeName.empty()) {
            file << ",\n" << pad << "    \"type_name\": \"" << EscapeJson(entry.typeName) << "\"\n";
        } else {
            file << "\n";
        }
        file << pad << "  }" << (index + 1 == metadata.size() ? "" : ",") << "\n";
    }

    if (!metadata.empty()) {
        file << pad;
    }
    file << "]";
}

void WriteSchemaModuleJson(const std::filesystem::path& outputPath, const SchemaModuleDump& module) {
    std::ofstream file(outputPath);
    file << "{\n";
    file << "  \"module\": \"" << EscapeJson(module.name) << "\",\n";
    file << "  \"classes\": [\n";

    for (size_t classIndex = 0; classIndex < module.classes.size(); ++classIndex) {
        const SchemaClassInfo& schemaClass = module.classes[classIndex];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(schemaClass.name) << "\",\n";
        file << "      \"binary_name\": \"" << EscapeJson(schemaClass.binaryName) << "\",\n";
        file << "      \"module_name\": \"" << EscapeJson(schemaClass.moduleName) << "\",\n";
        file << "      \"base_class\": \"" << EscapeJson(schemaClass.baseClassName) << "\",\n";
        file << "      \"size\": " << schemaClass.size << ",\n";
        file << "      \"metadata\": ";
        WriteMetadataJson(file, schemaClass.metadata, 6);
        file << ",\n";
        file << "      \"fields\": [\n";

        for (size_t fieldIndex = 0; fieldIndex < schemaClass.fields.size(); ++fieldIndex) {
            const SchemaFieldInfo& field = schemaClass.fields[fieldIndex];
            file << "        {\n";
            file << "          \"name\": \"" << EscapeJson(field.name) << "\",\n";
            file << "          \"type\": \"" << EscapeJson(field.typeName) << "\",\n";
            file << "          \"offset\": " << field.offset << ",\n";
            file << "          \"offset_hex\": \"" << FormatHex(static_cast<std::uint32_t>(field.offset)) << "\",\n";
            file << "          \"metadata\": ";
            WriteMetadataJson(file, field.metadata, 10);
            file << "\n";
            file << "        }" << (fieldIndex + 1 == schemaClass.fields.size() ? "" : ",") << "\n";
        }

        file << "      ]\n";
        file << "    }" << (classIndex + 1 == module.classes.size() ? "" : ",") << "\n";
    }

    file << "  ],\n";
    file << "  \"enums\": [\n";

    for (size_t enumIndex = 0; enumIndex < module.enums.size(); ++enumIndex) {
        const SchemaEnumInfo& schemaEnum = module.enums[enumIndex];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(schemaEnum.name) << "\",\n";
        file << "      \"module_name\": \"" << EscapeJson(schemaEnum.moduleName) << "\",\n";
        file << "      \"size\": " << static_cast<int>(schemaEnum.size) << ",\n";
        file << "      \"fields\": [\n";

        for (size_t fieldIndex = 0; fieldIndex < schemaEnum.fields.size(); ++fieldIndex) {
            const SchemaEnumFieldInfo& field = schemaEnum.fields[fieldIndex];
            file << "        {\n";
            file << "          \"name\": \"" << EscapeJson(field.name) << "\",\n";
            file << "          \"value\": " << field.value << "\n";
            file << "        }" << (fieldIndex + 1 == schemaEnum.fields.size() ? "" : ",") << "\n";
        }

        file << "      ]\n";
        file << "    }" << (enumIndex + 1 == module.enums.size() ? "" : ",") << "\n";
    }

    file << "  ]\n";
    file << "}\n";
}

void WriteMetadataComments(std::ofstream& file, const std::vector<SchemaMetadata>& metadata, const std::string& indent) {
    for (const SchemaMetadata& entry : metadata) {
        if (entry.type == "NetworkVarNames") {
            file << indent << "// NetworkVarNames: " << entry.name << " (" << entry.typeName << ")\n";
        } else if (entry.type == "NetworkChangeCallback") {
            file << indent << "// NetworkChangeCallback: " << entry.name << "\n";
        } else {
            file << indent << "// Metadata: " << entry.name << "\n";
        }
    }
}

void WriteSchemaModuleHpp(const std::filesystem::path& outputPath, const SchemaModuleDump& module) {
    std::ofstream file(outputPath);
    const std::string moduleNamespace = SanitizeIdentifier(module.name, "module");

    file << "#pragma once\n\n";
    file << "#include <cstdint>\n\n";
    file << "// Generated by cs2sign read-only schema dumper.\n";
    file << "// Module: " << module.name << "\n";
    file << "// Classes: " << module.classes.size() << "\n";
    file << "// Enums: " << module.enums.size() << "\n\n";
    file << "namespace cs2::schemas::" << moduleNamespace << " {\n\n";

    if (!module.enums.empty()) {
        file << "namespace enums {\n";
        for (const SchemaEnumInfo& schemaEnum : module.enums) {
            const int bitWidth = schemaEnum.size == 1 ? 8 : schemaEnum.size == 2 ? 16 : schemaEnum.size == 8 ? 64 : 32;
            file << "enum class " << schemaEnum.name << " : std::uint" << bitWidth << "_t {\n";
            for (size_t index = 0; index < schemaEnum.fields.size(); ++index) {
                const SchemaEnumFieldInfo& field = schemaEnum.fields[index];
                file << "    " << field.name << " = " << field.value
                     << (index + 1 == schemaEnum.fields.size() ? "" : ",") << "\n";
            }
            file << "};\n\n";
        }
        file << "} // namespace enums\n\n";
    }

    file << "namespace offsets {\n";
    for (const SchemaClassInfo& schemaClass : module.classes) {
        WriteMetadataComments(file, schemaClass.metadata, "");
        file << "struct " << schemaClass.name;
        if (!schemaClass.baseClassName.empty()) {
            file << " : " << schemaClass.baseClassName;
        }
        file << " {\n";
        for (const SchemaFieldInfo& field : schemaClass.fields) {
            WriteMetadataComments(file, field.metadata, "    ");
            file << "    static constexpr std::uintptr_t " << field.name << " = "
                 << FormatHex(static_cast<std::uint32_t>(field.offset)) << ";";
            if (!field.typeName.empty()) {
                file << " // " << field.typeName;
            }
            file << "\n";
        }
        file << "};\n\n";
    }
    file << "} // namespace offsets\n\n";
    file << "} // namespace cs2::schemas::" << moduleNamespace << "\n";
}

DumperStatus DumpSchemas(ProcessMemoryReader& process, const std::filesystem::path& outputDirectory) {
    DumperStatus status;
    status.name = "schemas";

    const std::filesystem::path schemaDirectory = outputDirectory / "schemas";
    if (!EnsureDirectory(schemaDirectory)) {
        status.error = "failed to create schema output directory";
        return status;
    }

    const std::vector<SchemaModuleDump> modules = ReadSchemaModules(process);
    size_t totalItems = 0;
    for (const SchemaModuleDump& module : modules) {
        totalItems += module.classes.size() + module.enums.size();
        const std::string fileStem = SanitizeIdentifier(module.name, "module");
        WriteSchemaModuleJson(schemaDirectory / (fileStem + ".json"), module);
        WriteSchemaModuleHpp(schemaDirectory / (fileStem + ".hpp"), module);
    }

    status.success = true;
    status.itemCount = totalItems;
    return status;
}

std::vector<InterfaceInfo> ReadInterfaces(ProcessMemoryReader& process) {
    std::vector<InterfaceInfo> interfaces;
    const std::vector<ProcessModule> modules = process.GetModules();

    for (const ProcessModule& module : modules) {
        std::vector<std::uint8_t> image;
        if (!ReadModuleImage(process, module, image)) {
            continue;
        }

        const auto createInterfaceRva = FindExportRva(image, "CreateInterface");
        if (!createInterfaceRva) {
            continue;
        }

        const auto listPointerRva = ResolveRipRelativeRva(image, *createInterfaceRva, 3, 7);
        if (!listPointerRva) {
            continue;
        }

        std::uint64_t listHead = 0;
        if (!ReadRemotePointer(process, static_cast<std::uint64_t>(module.base) + *listPointerRva, listHead)) {
            continue;
        }

        std::uint64_t regAddress = listHead;
        std::unordered_set<std::uint64_t> seen;
        size_t guard = 0;

        while (regAddress != 0 &&
               seen.insert(regAddress).second &&
               guard++ < kMaxInterfacesPerModule) {
            RemoteInterfaceReg reg{};
            if (!ReadRemote(process, regAddress, reg)) {
                break;
            }

            InterfaceInfo info;
            info.module = WideToUtf8(module.name);
            info.name = ReadStringOrEmpty(process, reg.name);

            if (reg.createFn >= module.base && reg.createFn < module.base + module.size) {
                const size_t createRva = static_cast<size_t>(reg.createFn - module.base);
                const auto instanceRva = ResolveRipRelativeRva(image, createRva, 3, 7);
                if (instanceRva) {
                    info.instanceRva = *instanceRva;
                }
            }

            if (!info.name.empty()) {
                interfaces.push_back(std::move(info));
            }

            regAddress = reg.next;
        }
    }

    std::sort(interfaces.begin(), interfaces.end(), [](const InterfaceInfo& left, const InterfaceInfo& right) {
        if (left.module != right.module) {
            return left.module < right.module;
        }
        return left.name < right.name;
    });

    return interfaces;
}

void WriteInterfacesJson(const std::filesystem::path& outputPath, const std::vector<InterfaceInfo>& interfaces) {
    std::ofstream file(outputPath);
    file << "{\n";
    file << "  \"interfaces\": [\n";
    for (size_t index = 0; index < interfaces.size(); ++index) {
        const InterfaceInfo& iface = interfaces[index];
        file << "    {\n";
        file << "      \"module\": \"" << EscapeJson(iface.module) << "\",\n";
        file << "      \"name\": \"" << EscapeJson(iface.name) << "\",\n";
        file << "      \"instance_rva\": \"" << FormatHex(iface.instanceRva) << "\"\n";
        file << "    }" << (index + 1 == interfaces.size() ? "" : ",") << "\n";
    }
    file << "  ]\n";
    file << "}\n";
}

void WriteInterfacesHpp(const std::filesystem::path& outputPath, const std::vector<InterfaceInfo>& interfaces) {
    std::ofstream file(outputPath);
    file << "#pragma once\n\n";
    file << "#include <cstdint>\n\n";
    file << "// Generated by cs2sign read-only interface dumper.\n\n";
    file << "namespace cs2::interfaces {\n";

    std::string currentModule;
    for (const InterfaceInfo& iface : interfaces) {
        const std::string moduleName = SanitizeIdentifier(iface.module, "module");
        if (moduleName != currentModule) {
            if (!currentModule.empty()) {
                file << "} // namespace " << currentModule << "\n\n";
            }
            currentModule = moduleName;
            file << "namespace " << currentModule << " {\n";
        }

        file << "    static constexpr std::uintptr_t "
             << SanitizeIdentifier(iface.name, "interface") << " = "
             << FormatHex(iface.instanceRva) << ";\n";
    }

    if (!currentModule.empty()) {
        file << "} // namespace " << currentModule << "\n";
    }

    file << "} // namespace cs2::interfaces\n";
}

DumperStatus DumpInterfaces(ProcessMemoryReader& process, const std::filesystem::path& outputDirectory) {
    DumperStatus status;
    status.name = "interfaces";

    if (!EnsureDirectory(outputDirectory)) {
        status.error = "failed to create output directory";
        return status;
    }

    const std::vector<InterfaceInfo> interfaces = ReadInterfaces(process);
    WriteInterfacesJson(outputDirectory / "interfaces.json", interfaces);
    WriteInterfacesHpp(outputDirectory / "interfaces.hpp", interfaces);

    status.success = true;
    status.itemCount = interfaces.size();
    return status;
}

enum class CaptureMode {
    RipRelative,
    U8Immediate,
    U32Immediate,
};

struct KnownOffsetPattern {
    std::wstring moduleName;
    std::string name;
    std::string pattern;
    CaptureMode captureMode;
    size_t captureOffset;
    size_t instructionLength;
    std::string resultType;
    std::string source = "known_offsets.json";
};

struct BuildKnownOffset {
    std::uint32_t buildNumber;
    std::string module;
    std::string name;
    std::uint32_t rva;
};

struct KnownOffsetConfig {
    std::vector<KnownOffsetPattern> patterns;
    std::vector<BuildKnownOffset> buildOverrides;
    std::string error;
};

constexpr wchar_t kKnownOffsetsResourceName[] = L"KNOWN_OFFSETS_JSON";

std::string ResultTypeForCaptureMode(CaptureMode captureMode);
bool JsonStringField(const JsonValue& object, const std::string& key, std::string& value);
bool ParseIntegerText(const std::string& value, std::uint64_t& result);

std::string EnsureDllModuleName(std::string module) {
    if (module.empty()) {
        return module;
    }

    const std::string lowerModule = ToLowerAscii(module);
    if (!EndsWith(lowerModule, ".dll")) {
        module += ".dll";
    }
    return module;
}

std::optional<std::string> ReadTextFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    std::stringstream stream;
    stream << file.rdbuf();
    return stream.str();
}

std::filesystem::path ExecutableDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    while (size == buffer.size()) {
        buffer.resize(buffer.size() * 2);
        size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    }

    if (size == 0) {
        return {};
    }

    buffer.resize(size);
    return std::filesystem::path(buffer).parent_path();
}

std::optional<std::string> ReadEmbeddedTextResource(const wchar_t* resourceName) {
    HRSRC resource = FindResourceW(nullptr, resourceName, RT_RCDATA);
    if (!resource) {
        return std::nullopt;
    }

    HGLOBAL loadedResource = LoadResource(nullptr, resource);
    if (!loadedResource) {
        return std::nullopt;
    }

    const auto* data = static_cast<const char*>(LockResource(loadedResource));
    const DWORD dataSize = SizeofResource(nullptr, resource);
    if (!data || dataSize == 0) {
        return std::nullopt;
    }

    return std::string(data, data + dataSize);
}

std::string LoadKnownOffsetConfigText() {
    const std::filesystem::path current = std::filesystem::current_path();
    const std::filesystem::path exeDirectory = ExecutableDirectory();
    const std::filesystem::path candidates[] = {
        current / "known_offsets.json",
        current / "tools" / "targets" / "known_offsets.json",
        exeDirectory / "known_offsets.json"
    };

    for (const std::filesystem::path& candidate : candidates) {
        if (candidate.empty()) {
            continue;
        }
        if (std::optional<std::string> text = ReadTextFile(candidate)) {
            return *text;
        }
    }

    return ReadEmbeddedTextResource(kKnownOffsetsResourceName).value_or(std::string{});
}

const JsonValue* JsonObjectMember(const JsonValue& object, const std::string& key) {
    if (object.type != JsonValue::Type::Object) {
        return nullptr;
    }

    const auto fieldIt = object.objectValue.find(key);
    return fieldIt == object.objectValue.end() ? nullptr : &fieldIt->second;
}

bool JsonUInt32Member(const JsonValue& object, const std::string& key, std::uint32_t& value) {
    const JsonValue* member = JsonObjectMember(object, key);
    if (!member) {
        return false;
    }

    std::uint64_t parsed = 0;
    if (member->type == JsonValue::Type::Number && member->numberIsInteger && member->numberValue >= 0) {
        parsed = static_cast<std::uint64_t>(member->numberValue);
    } else if (member->type == JsonValue::Type::String) {
        if (!ParseIntegerText(member->stringValue, parsed)) {
            return false;
        }
    } else {
        return false;
    }

    if (parsed > (std::numeric_limits<std::uint32_t>::max)()) {
        return false;
    }

    value = static_cast<std::uint32_t>(parsed);
    return true;
}

std::optional<CaptureMode> CaptureModeFromString(const std::string& mode) {
    const std::string normalized = ToLowerAscii(mode);
    if (normalized == "rip_relative") {
        return CaptureMode::RipRelative;
    }
    if (normalized == "u8_immediate") {
        return CaptureMode::U8Immediate;
    }
    if (normalized == "u32_immediate") {
        return CaptureMode::U32Immediate;
    }
    return std::nullopt;
}

std::optional<KnownOffsetPattern> ParseKnownOffsetPattern(const JsonValue& value, std::string& error) {
    if (value.type != JsonValue::Type::Object) {
        error = "known offset pattern must be an object";
        return std::nullopt;
    }

    std::string name;
    std::string module;
    std::string pattern;
    if (!JsonStringField(value, "name", name) || name.empty()) {
        error = "known offset pattern has no name";
        return std::nullopt;
    }
    if (!JsonStringField(value, "module", module) || module.empty()) {
        error = "known offset pattern has no module: " + name;
        return std::nullopt;
    }
    if (!JsonStringField(value, "pattern", pattern) || pattern.empty()) {
        error = "known offset pattern has no pattern: " + name;
        return std::nullopt;
    }

    const JsonValue* capture = JsonObjectMember(value, "capture");
    if (!capture || capture->type != JsonValue::Type::Object) {
        error = "known offset pattern has no capture object: " + name;
        return std::nullopt;
    }

    std::string modeText;
    if (!JsonStringField(*capture, "mode", modeText)) {
        error = "known offset capture has no mode: " + name;
        return std::nullopt;
    }

    const std::optional<CaptureMode> captureMode = CaptureModeFromString(modeText);
    if (!captureMode) {
        error = "unknown known offset capture mode for " + name + ": " + modeText;
        return std::nullopt;
    }

    std::uint32_t captureOffset = 0;
    if (!JsonUInt32Member(*capture, "offset", captureOffset)) {
        error = "known offset capture has no offset: " + name;
        return std::nullopt;
    }

    std::uint32_t instructionLength = 0;
    JsonUInt32Member(*capture, "instruction_length", instructionLength);

    KnownOffsetPattern descriptor;
    descriptor.moduleName = Utf8ToWide(EnsureDllModuleName(module));
    descriptor.name = name;
    descriptor.pattern = pattern;
    descriptor.captureMode = *captureMode;
    descriptor.captureOffset = captureOffset;
    descriptor.instructionLength = instructionLength;
    JsonStringField(value, "result_type", descriptor.resultType);
    if (descriptor.resultType.empty()) {
        descriptor.resultType = ResultTypeForCaptureMode(descriptor.captureMode);
    }
    return descriptor;
}

std::optional<BuildKnownOffset> ParseBuildKnownOffset(const JsonValue& value, std::string& error) {
    if (value.type != JsonValue::Type::Object) {
        error = "build override must be an object";
        return std::nullopt;
    }

    std::string module;
    std::string name;
    std::uint32_t build = 0;
    std::uint32_t rva = 0;
    if (!JsonUInt32Member(value, "build", build)) {
        error = "build override has no build number";
        return std::nullopt;
    }
    if (!JsonStringField(value, "module", module) || module.empty()) {
        error = "build override has no module";
        return std::nullopt;
    }
    if (!JsonStringField(value, "name", name) || name.empty()) {
        error = "build override has no name";
        return std::nullopt;
    }
    if (!JsonUInt32Member(value, "rva", rva)) {
        error = "build override has no rva: " + name;
        return std::nullopt;
    }

    return BuildKnownOffset{ build, EnsureDllModuleName(module), name, rva };
}

KnownOffsetConfig LoadKnownOffsetConfig() {
    KnownOffsetConfig config;
    const std::string jsonText = LoadKnownOffsetConfigText();
    if (jsonText.empty()) {
        config.error = "known_offsets.json was not found";
        return config;
    }

    JsonValue root;
    std::string error;
    JsonReader reader(jsonText);
    if (!reader.Parse(root, error) || root.type != JsonValue::Type::Object) {
        config.error = "failed to parse known_offsets.json: " + error;
        return config;
    }

    const JsonValue* patterns = JsonObjectMember(root, "patterns");
    if (!patterns || patterns->type != JsonValue::Type::Array) {
        config.error = "known_offsets.json has no patterns array";
        return config;
    }

    for (const JsonValue& item : patterns->arrayValue) {
        std::optional<KnownOffsetPattern> descriptor = ParseKnownOffsetPattern(item, error);
        if (!descriptor) {
            config.error = error;
            return config;
        }
        config.patterns.push_back(std::move(*descriptor));
    }

    if (const JsonValue* overrides = JsonObjectMember(root, "build_overrides")) {
        if (overrides->type != JsonValue::Type::Array) {
            config.error = "known_offsets.json build_overrides must be an array";
            return config;
        }
        for (const JsonValue& item : overrides->arrayValue) {
            std::optional<BuildKnownOffset> knownOffset = ParseBuildKnownOffset(item, error);
            if (!knownOffset) {
                config.error = error;
                return config;
            }
            config.buildOverrides.push_back(*knownOffset);
        }
    }

    return config;
}

const KnownOffsetConfig& KnownOffsetConfigData() {
    static const KnownOffsetConfig config = LoadKnownOffsetConfig();
    return config;
}

std::optional<std::uint32_t> ResolveKnownOffset(
    const std::vector<std::uint8_t>& image,
    const KnownOffsetPattern& descriptor
) {
    std::vector<PatternByte> pattern;
    if (!ParseIdaPattern(descriptor.pattern, pattern)) {
        return std::nullopt;
    }

    const auto match = FindPattern(image, pattern);
    if (!match) {
        return std::nullopt;
    }

    switch (descriptor.captureMode) {
        case CaptureMode::RipRelative:
            return ResolveRipRelativeRva(
                image,
                *match,
                descriptor.captureOffset,
                descriptor.instructionLength
            );
        case CaptureMode::U8Immediate:
            if (*match + descriptor.captureOffset < image.size()) {
                return image[*match + descriptor.captureOffset];
            }
            return std::nullopt;
        case CaptureMode::U32Immediate:
            return ReadUInt32(image, *match + descriptor.captureOffset);
    }

    return std::nullopt;
}

std::string ResultTypeForCaptureMode(CaptureMode captureMode) {
    switch (captureMode) {
        case CaptureMode::RipRelative:
            return "module_rva";
        case CaptureMode::U8Immediate:
        case CaptureMode::U32Immediate:
            return "field_offset";
    }

    return "module_rva";
}

const std::vector<KnownOffsetPattern>& KnownOffsetPatterns() {
    return KnownOffsetConfigData().patterns;
}

const std::vector<BuildKnownOffset>& BuildKnownOffsets() {
    return KnownOffsetConfigData().buildOverrides;
}

void AddDerivedOffsets(
    const std::map<std::wstring, std::vector<std::uint8_t>>& images,
    std::vector<KnownOffsetInfo>& offsets
) {
    auto findOffset = [&](const std::string& name) -> std::optional<std::uint32_t> {
        for (const KnownOffsetInfo& offset : offsets) {
            if (offset.found && offset.name == name) {
                return offset.rva;
            }
        }
        return std::nullopt;
    };

    const auto clientImage = images.find(L"client.dll");
    if (clientImage == images.end()) {
        return;
    }

    std::vector<PatternByte> viewAnglesPattern;
    if (ParseIdaPattern("F2 42 0F 10 84 28 ? ? ? ?", viewAnglesPattern)) {
        const auto match = FindPattern(clientImage->second, viewAnglesPattern);
        const auto base = findOffset("dwCSGOInput");
        const auto addend = match ? ReadUInt32(clientImage->second, *match + 6) : std::nullopt;
        if (base && addend) {
            offsets.push_back({ "client.dll", "dwViewAngles", true, *base + *addend, "" });
        }
    }

    std::vector<PatternByte> localPawnPattern;
    if (ParseIdaPattern("4C 39 B6 ? ? ? ? 74 ? 44 88 BE", localPawnPattern)) {
        const auto match = FindPattern(clientImage->second, localPawnPattern);
        const auto base = findOffset("dwPrediction");
        const auto addend = match ? ReadUInt32(clientImage->second, *match + 3) : std::nullopt;
        if (base && addend) {
            offsets.push_back({ "client.dll", "dwLocalPlayerPawn", true, *base + *addend, "" });
        }
    }
}

std::optional<std::uint32_t> FindKnownOffsetRva(
    const std::vector<KnownOffsetInfo>& offsets,
    const std::string& module,
    const std::string& name
) {
    for (const KnownOffsetInfo& offset : offsets) {
        if (offset.found && offset.module == module && offset.name == name) {
            return offset.rva;
        }
    }
    return std::nullopt;
}

void ApplyBuildKnownOffsets(std::vector<KnownOffsetInfo>& offsets, std::uint32_t buildNumber) {
    for (const BuildKnownOffset& knownOffset : BuildKnownOffsets()) {
        if (knownOffset.buildNumber != buildNumber) {
            continue;
        }

        auto offsetIt = std::find_if(offsets.begin(), offsets.end(), [&](const KnownOffsetInfo& offset) {
            return offset.module == knownOffset.module && offset.name == knownOffset.name;
        });

        if (offsetIt == offsets.end()) {
            KnownOffsetInfo info;
            info.module = knownOffset.module;
            info.name = knownOffset.name;
            info.found = true;
            info.rva = knownOffset.rva;
            info.source = "build_override";
            offsets.push_back(std::move(info));
            continue;
        }

        offsetIt->found = true;
        offsetIt->rva = knownOffset.rva;
        offsetIt->error.clear();
        offsetIt->source = "build_override";
    }
}

bool JsonStringField(const JsonValue& object, const std::string& key, std::string& value) {
    if (object.type != JsonValue::Type::Object) {
        return false;
    }

    const auto fieldIt = object.objectValue.find(key);
    if (fieldIt == object.objectValue.end() || fieldIt->second.type != JsonValue::Type::String) {
        return false;
    }

    value = fieldIt->second.stringValue;
    return true;
}

bool JsonBoolField(const JsonValue& object, const std::string& key, bool& value) {
    if (object.type != JsonValue::Type::Object) {
        return false;
    }

    const auto fieldIt = object.objectValue.find(key);
    if (fieldIt == object.objectValue.end() || fieldIt->second.type != JsonValue::Type::Bool) {
        return false;
    }

    value = fieldIt->second.boolValue;
    return true;
}

bool ParseIntegerText(const std::string& value, std::uint64_t& result) {
    try {
        result = std::stoull(value, nullptr, 0);
        return true;
    } catch (...) {
        return false;
    }
}

std::string NormalizeModuleName(std::string module) {
    if (module.empty()) {
        return module;
    }

    const std::string lowerModule = ToLowerAscii(module);
    if (lowerModule.size() < 4 || lowerModule.substr(lowerModule.size() - 4) != ".dll") {
        module += ".dll";
    }
    return module;
}

std::optional<std::uint32_t> ResolveModuleRvaFromAddress(
    const std::vector<ProcessModule>& modules,
    const std::string& preferredModule,
    std::uint64_t address,
    std::string& moduleName
) {
    for (const ProcessModule& module : modules) {
        const std::string currentName = WideToUtf8(module.name);
        if (!preferredModule.empty() && ToLowerAscii(currentName) != ToLowerAscii(preferredModule)) {
            continue;
        }

        const std::uint64_t base = static_cast<std::uint64_t>(module.base);
        const std::uint64_t end = base + module.size;
        if (address >= base && address < end) {
            moduleName = currentName;
            return static_cast<std::uint32_t>(address - base);
        }
    }

    if (!preferredModule.empty()) {
        return std::nullopt;
    }

    for (const ProcessModule& module : modules) {
        const std::uint64_t base = static_cast<std::uint64_t>(module.base);
        const std::uint64_t end = base + module.size;
        if (address >= base && address < end) {
            moduleName = WideToUtf8(module.name);
            return static_cast<std::uint32_t>(address - base);
        }
    }

    return std::nullopt;
}

std::vector<ResolvedSignatureInfo> ReadResolvedSignatures(ProcessMemoryReader& process) {
    std::vector<ResolvedSignatureInfo> signatures;
    const std::filesystem::path scanPath = "cs2_signatures.json";
    if (!std::filesystem::exists(scanPath)) {
        return signatures;
    }

    std::ifstream file(scanPath);
    std::stringstream stream;
    stream << file.rdbuf();
    const std::string jsonText = stream.str();

    JsonValue root;
    std::string error;
    JsonReader reader(jsonText);
    if (!reader.Parse(root, error) || root.type != JsonValue::Type::Object) {
        return signatures;
    }

    const auto signaturesIt = root.objectValue.find("signatures");
    if (signaturesIt == root.objectValue.end() || signaturesIt->second.type != JsonValue::Type::Array) {
        return signatures;
    }

    const std::vector<ProcessModule> modules = process.GetModules();

    for (const JsonValue& signature : signaturesIt->second.arrayValue) {
        bool found = false;
        if (!JsonBoolField(signature, "found", found) || !found) {
            continue;
        }

        std::string name;
        if (!JsonStringField(signature, "name", name) || name.empty()) {
            continue;
        }

        std::string resultType = "absolute_address";
        JsonStringField(signature, "result_type", resultType);
        resultType = ToLowerAscii(resultType);

        std::string module = "client.dll";
        JsonStringField(signature, "module", module);
        module = NormalizeModuleName(module);

        std::uint64_t value = 0;
        ResolvedSignatureInfo info;
        info.module = module;
        info.name = name;
        info.resultType = resultType;

        if (resultType == "field_offset") {
            std::string fieldOffset;
            if (!JsonStringField(signature, "field_offset", fieldOffset) &&
                !JsonStringField(signature, "address", fieldOffset)) {
                continue;
            }
            if (!ParseIntegerText(fieldOffset, value) || value > (std::numeric_limits<std::uint32_t>::max)()) {
                continue;
            }
            info.valueField = "field_offset";
            info.value = static_cast<std::uint32_t>(value);
            signatures.push_back(std::move(info));
            continue;
        }

        std::string moduleRva;
        if (JsonStringField(signature, "module_rva", moduleRva)) {
            if (!ParseIntegerText(moduleRva, value) || value > (std::numeric_limits<std::uint32_t>::max)()) {
                continue;
            }
            info.value = static_cast<std::uint32_t>(value);
            signatures.push_back(std::move(info));
            continue;
        }

        std::string address;
        if (!JsonStringField(signature, "address", address) || !ParseIntegerText(address, value)) {
            continue;
        }

        std::string resolvedModule = module;
        const auto rva = ResolveModuleRvaFromAddress(modules, module, value, resolvedModule);
        if (!rva) {
            continue;
        }

        info.module = resolvedModule;
        info.value = *rva;
        signatures.push_back(std::move(info));
    }

    return signatures;
}

std::vector<KnownOffsetInfo> ReadKnownOffsets(ProcessMemoryReader& process) {
    const KnownOffsetConfig& config = KnownOffsetConfigData();
    if (!config.error.empty()) {
        throw std::runtime_error(config.error);
    }

    std::vector<KnownOffsetInfo> offsets;
    std::map<std::wstring, std::vector<std::uint8_t>> images;

    for (const KnownOffsetPattern& descriptor : KnownOffsetPatterns()) {
        ProcessModule module{};
        KnownOffsetInfo info;
        info.module = WideToUtf8(descriptor.moduleName);
        info.name = descriptor.name;
        info.source = descriptor.source;
        info.resultType = descriptor.resultType.empty() ?
            ResultTypeForCaptureMode(descriptor.captureMode) :
            descriptor.resultType;

        if (!process.GetModuleInfo(descriptor.moduleName, module)) {
            info.error = "module not loaded";
            offsets.push_back(std::move(info));
            continue;
        }

        auto imageIt = images.find(descriptor.moduleName);
        if (imageIt == images.end()) {
            std::vector<std::uint8_t> image;
            if (!ReadModuleImage(process, module, image)) {
                info.error = "failed to read module image";
                offsets.push_back(std::move(info));
                continue;
            }

            imageIt = images.emplace(descriptor.moduleName, std::move(image)).first;
        }

        const auto rva = ResolveKnownOffset(imageIt->second, descriptor);
        if (!rva) {
            info.error = "pattern not found";
            offsets.push_back(std::move(info));
            continue;
        }

        info.found = true;
        info.rva = *rva;
        offsets.push_back(std::move(info));
    }

    AddDerivedOffsets(images, offsets);
    return offsets;
}

void ValidateKnownOffsets(ProcessMemoryReader& process, std::vector<KnownOffsetInfo>& offsets) {
    for (KnownOffsetInfo& offset : offsets) {
        if (!offset.found) {
            offset.validationStatus = "skipped";
            offset.validationError = offset.error.empty() ? "not found" : offset.error;
            continue;
        }

        ProcessModule module{};
        if (!process.GetModuleInfo(Utf8ToWide(offset.module), module)) {
            offset.validationStatus = "failed";
            offset.validationError = "module not loaded";
            continue;
        }

        if (offset.resultType == "module_rva") {
            if (offset.rva < module.size) {
                offset.validationStatus = "ok";
                offset.validationError.clear();
            } else {
                offset.validationStatus = "failed";
                offset.validationError = "rva outside module";
            }
            continue;
        }

        if (offset.resultType == "field_offset") {
            if (offset.rva <= kMaxReasonableFieldOffset) {
                offset.validationStatus = "ok";
                offset.validationError.clear();
            } else {
                offset.validationStatus = "failed";
                offset.validationError = "field offset is too large";
            }
            continue;
        }

        offset.validationStatus = "skipped";
        offset.validationError = "unsupported result type";
    }
}

void WriteOffsetsJson(const std::filesystem::path& outputPath, const std::vector<KnownOffsetInfo>& offsets) {
    std::ofstream file(outputPath);
    file << "{\n";
    file << "  \"offsets\": [\n";
    for (size_t index = 0; index < offsets.size(); ++index) {
        const KnownOffsetInfo& offset = offsets[index];
        file << "    {\n";
        file << "      \"module\": \"" << EscapeJson(offset.module) << "\",\n";
        file << "      \"name\": \"" << EscapeJson(offset.name) << "\",\n";
        file << "      \"source\": \"" << EscapeJson(offset.source) << "\",\n";
        file << "      \"result_type\": \"" << EscapeJson(offset.resultType) << "\",\n";
        file << "      \"validation\": \"" << EscapeJson(offset.validationStatus) << "\",\n";
        file << "      \"found\": " << (offset.found ? "true" : "false") << ",\n";
        if (offset.found) {
            const std::string valueName = offset.resultType == "field_offset" ? "offset" : "rva";
            file << "      \"" << valueName << "\": \"" << FormatHex(offset.rva) << "\",\n";
            file << "      \"error\": null,\n";
        } else {
            const std::string valueName = offset.resultType == "field_offset" ? "offset" : "rva";
            file << "      \"" << valueName << "\": null,\n";
            file << "      \"error\": \"" << EscapeJson(offset.error) << "\",\n";
        }
        if (offset.validationError.empty()) {
            file << "      \"validation_error\": null\n";
        } else {
            file << "      \"validation_error\": \"" << EscapeJson(offset.validationError) << "\"\n";
        }
        file << "    }" << (index + 1 == offsets.size() ? "" : ",") << "\n";
    }
    file << "  ]\n";
    file << "}\n";
}

void WriteResolvedSignaturesJson(
    const std::filesystem::path& outputPath,
    const std::vector<ResolvedSignatureInfo>& signatures
) {
    std::ofstream file(outputPath);
    file << "{\n";
    file << "  \"resolved_signatures\": [\n";
    for (size_t index = 0; index < signatures.size(); ++index) {
        const ResolvedSignatureInfo& signature = signatures[index];
        file << "    {\n";
        file << "      \"module\": \"" << EscapeJson(signature.module) << "\",\n";
        file << "      \"name\": \"" << EscapeJson(signature.name) << "\",\n";
        file << "      \"source\": \"cs2_signatures.json\",\n";
        file << "      \"result_type\": \"" << EscapeJson(signature.resultType) << "\",\n";
        file << "      \"" << EscapeJson(signature.valueField) << "\": \"" << FormatHex(signature.value) << "\"\n";
        file << "    }" << (index + 1 == signatures.size() ? "" : ",") << "\n";
    }
    file << "  ]\n";
    file << "}\n";
}

void WriteOffsetsHpp(const std::filesystem::path& outputPath, const std::vector<KnownOffsetInfo>& offsets) {
    std::ofstream file(outputPath);
    file << "#pragma once\n\n";
    file << "#include <cstdint>\n\n";
    file << "// Generated by cs2sign read-only known offset dumper.\n\n";
    file << "namespace cs2::offsets {\n";

    std::string currentModule;
    for (const KnownOffsetInfo& offset : offsets) {
        const std::string moduleName = SanitizeIdentifier(offset.module, "module");
        if (moduleName != currentModule) {
            if (!currentModule.empty()) {
                file << "} // namespace " << currentModule << "\n\n";
            }
            currentModule = moduleName;
            file << "namespace " << currentModule << " {\n";
        }

        if (offset.found && offset.validationStatus != "failed") {
            file << "    static constexpr std::uintptr_t " << offset.name
                 << " = " << FormatHex(offset.rva) << ";\n";
        } else if (offset.found) {
            file << "    // " << offset.name << " failed validation: "
                 << offset.validationError << "\n";
        } else {
            file << "    // " << offset.name << " failed: " << offset.error << "\n";
        }
    }

    if (!currentModule.empty()) {
        file << "} // namespace " << currentModule << "\n";
    }
    file << "} // namespace cs2::offsets\n";
}

OffsetDumpResult DumpKnownOffsets(
    ProcessMemoryReader& process,
    const std::filesystem::path& outputDirectory,
    std::optional<std::uint32_t>& buildNumber
) {
    OffsetDumpResult result;
    result.knownOffsets.name = "known_offsets";
    result.resolvedSignatures.name = "resolved_signatures";

    if (!EnsureDirectory(outputDirectory)) {
        result.knownOffsets.error = "failed to create output directory";
        result.resolvedSignatures.error = "failed to create output directory";
        return result;
    }

    std::vector<KnownOffsetInfo> offsets = ReadKnownOffsets(process);
    const std::vector<ResolvedSignatureInfo> resolvedSignatures = ReadResolvedSignatures(process);

    if (const auto buildNumberRva = FindKnownOffsetRva(offsets, "engine2.dll", "dwBuildNumber")) {
        ProcessModule engineModule{};
        if (process.GetModuleInfo(L"engine2.dll", engineModule)) {
            std::uint32_t value = 0;
            if (process.Read(engineModule.base + *buildNumberRva, value)) {
                buildNumber = value;
                ApplyBuildKnownOffsets(offsets, value);
            }
        }
    }

    ValidateKnownOffsets(process, offsets);

    WriteOffsetsJson(outputDirectory / "offsets.json", offsets);
    WriteOffsetsHpp(outputDirectory / "offsets.hpp", offsets);
    WriteResolvedSignaturesJson(outputDirectory / "resolved_signatures.json", resolvedSignatures);

    size_t foundCount = 0;
    for (const KnownOffsetInfo& offset : offsets) {
        if (offset.found) {
            ++foundCount;
        }
    }

    result.knownOffsets.success = true;
    result.knownOffsets.itemCount = foundCount;
    result.resolvedSignatures.success = true;
    result.resolvedSignatures.itemCount = resolvedSignatures.size();
    return result;
}

void WriteDumpInfo(
    ProcessMemoryReader& process,
    const std::filesystem::path& outputDirectory,
    const ReadOnlyDumpReport& report
) {
    if (!EnsureDirectory(outputDirectory)) {
        return;
    }

    std::ofstream file(outputDirectory / "dump_info.json");
    file << "{\n";
    file << "  \"generator\": \"cs2sign\",\n";
    file << "  \"mode\": \"read_only\",\n";
    file << "  \"timestamp\": \"" << CurrentTimestampUtc() << "\",\n";
    file << "  \"process_id\": " << process.GetProcessId() << ",\n";
    if (report.buildNumber) {
        file << "  \"build_number\": " << *report.buildNumber << ",\n";
    } else {
        file << "  \"build_number\": null,\n";
    }

    file << "  \"modules\": [\n";
    const std::vector<ProcessModule> modules = process.GetModules();
    for (size_t index = 0; index < modules.size(); ++index) {
        const ProcessModule& module = modules[index];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(WideToUtf8(module.name)) << "\",\n";
        file << "      \"path\": \"" << EscapeJson(WideToUtf8(module.path)) << "\",\n";
        file << "      \"base\": \"" << FormatHex(module.base) << "\",\n";
        file << "      \"size\": " << module.size << "\n";
        file << "    }" << (index + 1 == modules.size() ? "" : ",") << "\n";
    }
    file << "  ],\n";

    file << "  \"dumpers\": [\n";
    for (size_t index = 0; index < report.statuses.size(); ++index) {
        const DumperStatus& status = report.statuses[index];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(status.name) << "\",\n";
        file << "      \"success\": " << (status.success ? "true" : "false") << ",\n";
        file << "      \"item_count\": " << status.itemCount << ",\n";
        if (status.success) {
            file << "      \"error\": null\n";
        } else {
            file << "      \"error\": \"" << EscapeJson(status.error) << "\"\n";
        }
        file << "    }" << (index + 1 == report.statuses.size() ? "" : ",") << "\n";
    }
    file << "  ]\n";
    file << "}\n";
}

void RunOneDumper(
    ReadOnlyDumpReport& report,
    const std::string& name,
    const std::function<DumperStatus()>& action
) {
    try {
        report.statuses.push_back(action());
    } catch (const std::exception& exception) {
        report.statuses.push_back({ name, false, exception.what(), 0 });
    } catch (...) {
        report.statuses.push_back({ name, false, "unknown failure", 0 });
    }
}
} // namespace

bool HasReadOnlyDumpWork(const ReadOnlyDumpOptions& options) {
    return options.dumpSchemas || options.dumpInterfaces || options.dumpOffsets || options.dumpInfo;
}

void RunReadOnlyDumpers(
    ProcessMemoryReader& process,
    const ReadOnlyDumpOptions& options,
    ReadOnlyDumpReport& report
) {
    report.statuses.clear();
    report.buildNumber.reset();

    if (options.dumpSchemas) {
        RunOneDumper(report, "schemas", [&]() {
            return DumpSchemas(process, options.outputDirectory);
        });
    }

    if (options.dumpInterfaces) {
        RunOneDumper(report, "interfaces", [&]() {
            return DumpInterfaces(process, options.outputDirectory);
        });
    }

    if (options.dumpOffsets) {
        try {
            const OffsetDumpResult result = DumpKnownOffsets(
                process,
                options.outputDirectory,
                report.buildNumber
            );
            report.statuses.push_back(result.knownOffsets);
            report.statuses.push_back(result.resolvedSignatures);
        } catch (const std::exception& exception) {
            report.statuses.push_back({ "known_offsets", false, exception.what(), 0 });
            report.statuses.push_back({ "resolved_signatures", false, exception.what(), 0 });
        } catch (...) {
            report.statuses.push_back({ "known_offsets", false, "unknown failure", 0 });
            report.statuses.push_back({ "resolved_signatures", false, "unknown failure", 0 });
        }
    }

    if (options.dumpInfo) {
        try {
            ReadOnlyDumpReport infoReport = report;
            infoReport.statuses.push_back({ "dump_info", true, "", 1 });
            WriteDumpInfo(process, options.outputDirectory, infoReport);
            report.statuses.push_back({ "dump_info", true, "", 1 });
        } catch (const std::exception& exception) {
            report.statuses.push_back({ "dump_info", false, exception.what(), 0 });
        } catch (...) {
            report.statuses.push_back({ "dump_info", false, "unknown failure", 0 });
        }
    }
}
