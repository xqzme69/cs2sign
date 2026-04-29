#include "ExternalDumpers.h"

#include "DumpUtils.h"

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
constexpr size_t kMaxInterfacesPerModule = 4096;
constexpr std::int32_t kMaxClassSize = 0x400000;

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
                module.classes.push_back(std::move(*classInfo));
            }
        }

        const std::vector<std::uint64_t> enums =
            ReadTsHashElements(process, typeScopeAddress + 0x1DD0);
        for (std::uint64_t enumAddress : enums) {
            auto enumInfo = ReadSchemaEnum(process, enumAddress);
            if (enumInfo) {
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
};

struct BuildKnownOffset {
    std::uint32_t buildNumber;
    std::string module;
    std::string name;
    std::uint32_t rva;
};

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

std::vector<KnownOffsetPattern> KnownOffsetPatterns() {
    return {
        { L"client.dll", "dwCSGOInput", "48 89 05 ? ? ? ? 0F 57 C0 0F 11 05", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwEntityList", "48 89 0D ? ? ? ? E9 ? ? ? ? CC", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwGameEntitySystem", "48 8B 1D ? ? ? ? 48 89 1D ? ? ? ? 4C 63 B3", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwGameEntitySystem_highestEntityIndex", "FF 81 ? ? ? ? 48 85 D2", CaptureMode::U32Immediate, 2, 0 },
        { L"client.dll", "dwGameRules", "F6 C1 01 0F 85 ? ? ? ? 4C 8B 05 ? ? ? ? 4D 85", CaptureMode::RipRelative, 12, 16 },
        { L"client.dll", "dwGlobalVars", "48 89 15 ? ? ? ? 48 89 42", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwGlowManager", "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 41", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwLocalPlayerController", "48 8B 05 ? ? ? ? 41 89 BE", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwPlantedC4", "48 8B 15 ? ? ? ? 41 FF C0 48 8D 4C 24 ? 44 89 05 ? ? ? ?", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwPrediction", "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwSensitivity", "48 8D 0D ? ? ? ? ? ? ? ? ? ? ? ? 66 0F 6E CD", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwSensitivity_sensitivity", "48 8D 7E ? 48 0F BA E0 ? 72 ? 85 D2 49 0F 4F FF", CaptureMode::U8Immediate, 3, 0 },
        { L"client.dll", "dwViewMatrix", "48 8D 0D ? ? ? ? 48 C1 E0 06", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwViewRender", "48 89 05 ? ? ? ? 48 8B C8 48 85 C0", CaptureMode::RipRelative, 3, 7 },
        { L"client.dll", "dwWeaponC4", "48 8B 15 ? ? ? ? 48 8B 5C 24 ? FF C0 89 05 ? ? ? ? 48 8B C6 48 89 34 EA 80 BE", CaptureMode::RipRelative, 3, 7 },
        { L"engine2.dll", "dwBuildNumber", "89 05 ? ? ? ? 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 0D", CaptureMode::RipRelative, 2, 6 },
        { L"engine2.dll", "dwNetworkGameClient", "48 89 3D ? ? ? ? FF 87", CaptureMode::RipRelative, 3, 7 },
        { L"engine2.dll", "dwNetworkGameClient_clientTickCount", "8B 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 83 B9", CaptureMode::U32Immediate, 2, 0 },
        { L"engine2.dll", "dwNetworkGameClient_deltaTick", "4C 8D B7 ? ? ? ? 4C 89 7C 24", CaptureMode::U32Immediate, 3, 0 },
        { L"engine2.dll", "dwNetworkGameClient_isBackgroundMap", "0F B6 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 0F B6 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 40 53", CaptureMode::U32Immediate, 3, 0 },
        { L"engine2.dll", "dwNetworkGameClient_localPlayer", "42 8B 94 D3 ? ? ? ? 5B 49 FF E3 32 C0 5B C3 CC CC CC CC CC CC CC CC 40 53", CaptureMode::U32Immediate, 4, 0 },
        { L"engine2.dll", "dwNetworkGameClient_maxClients", "8B 81 ? ? ? ? C3 ? ? ? ? ? ? ? ? ? 8B 81 ? ? ? ? C3 ? ? ? ? ? ? ? ? ? 8B 81", CaptureMode::U32Immediate, 2, 0 },
        { L"engine2.dll", "dwNetworkGameClient_serverTickCount", "8B 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 83 B9", CaptureMode::U32Immediate, 2, 0 },
        { L"engine2.dll", "dwNetworkGameClient_signOnState", "44 8B 81 ? ? ? ? 48 8D 0D", CaptureMode::U32Immediate, 3, 0 },
        { L"engine2.dll", "dwWindowHeight", "8B 05 ? ? ? ? 89 03", CaptureMode::RipRelative, 2, 6 },
        { L"engine2.dll", "dwWindowWidth", "8B 05 ? ? ? ? 89 07", CaptureMode::RipRelative, 2, 6 },
        { L"inputsystem.dll", "dwInputSystem", "48 89 05 ? ? ? ? 33 C0", CaptureMode::RipRelative, 3, 7 },
        { L"matchmaking.dll", "dwGameTypes", "48 8D 0D ? ? ? ? FF 90", CaptureMode::RipRelative, 3, 7 },
        { L"soundsystem.dll", "dwSoundSystem", "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 15", CaptureMode::RipRelative, 3, 7 },
        { L"soundsystem.dll", "dwSoundSystem_engineViewData", "0F 11 47 ? 0F 10 4E ? 0F 11 8F", CaptureMode::U8Immediate, 3, 0 },
    };
}

std::vector<BuildKnownOffset> BuildKnownOffsets() {
    return {
        { 14156, "client.dll", "dwGameRules", 0x2328E38 },
        { 14156, "client.dll", "dwSensitivity", 0x2326748 },
        { 14156, "engine2.dll", "dwNetworkGameClient_clientTickCount", 0x378 },
        { 14156, "engine2.dll", "dwNetworkGameClient_isBackgroundMap", 0x2C141F },
        { 14156, "engine2.dll", "dwNetworkGameClient_localPlayer", 0xF8 },
        { 14156, "engine2.dll", "dwNetworkGameClient_serverTickCount", 0x24C },
    };
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
            offsets.push_back({ knownOffset.module, knownOffset.name, true, knownOffset.rva, "" });
            continue;
        }

        offsetIt->found = true;
        offsetIt->rva = knownOffset.rva;
        offsetIt->error.clear();
    }
}

std::vector<KnownOffsetInfo> ReadKnownOffsets(ProcessMemoryReader& process) {
    std::vector<KnownOffsetInfo> offsets;
    std::map<std::wstring, std::vector<std::uint8_t>> images;

    for (const KnownOffsetPattern& descriptor : KnownOffsetPatterns()) {
        ProcessModule module{};
        KnownOffsetInfo info;
        info.module = WideToUtf8(descriptor.moduleName);
        info.name = descriptor.name;

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

void WriteOffsetsJson(const std::filesystem::path& outputPath, const std::vector<KnownOffsetInfo>& offsets) {
    std::ofstream file(outputPath);
    file << "{\n";
    file << "  \"offsets\": [\n";
    for (size_t index = 0; index < offsets.size(); ++index) {
        const KnownOffsetInfo& offset = offsets[index];
        file << "    {\n";
        file << "      \"module\": \"" << EscapeJson(offset.module) << "\",\n";
        file << "      \"name\": \"" << EscapeJson(offset.name) << "\",\n";
        file << "      \"found\": " << (offset.found ? "true" : "false") << ",\n";
        if (offset.found) {
            file << "      \"rva\": \"" << FormatHex(offset.rva) << "\",\n";
            file << "      \"error\": null\n";
        } else {
            file << "      \"rva\": null,\n";
            file << "      \"error\": \"" << EscapeJson(offset.error) << "\"\n";
        }
        file << "    }" << (index + 1 == offsets.size() ? "" : ",") << "\n";
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

        if (offset.found) {
            file << "    static constexpr std::uintptr_t " << offset.name
                 << " = " << FormatHex(offset.rva) << ";\n";
        } else {
            file << "    // " << offset.name << " failed: " << offset.error << "\n";
        }
    }

    if (!currentModule.empty()) {
        file << "} // namespace " << currentModule << "\n";
    }
    file << "} // namespace cs2::offsets\n";
}

DumperStatus DumpKnownOffsets(
    ProcessMemoryReader& process,
    const std::filesystem::path& outputDirectory,
    std::optional<std::uint32_t>& buildNumber
) {
    DumperStatus status;
    status.name = "known_offsets";

    if (!EnsureDirectory(outputDirectory)) {
        status.error = "failed to create output directory";
        return status;
    }

    std::vector<KnownOffsetInfo> offsets = ReadKnownOffsets(process);

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

    WriteOffsetsJson(outputDirectory / "offsets.json", offsets);
    WriteOffsetsHpp(outputDirectory / "offsets.hpp", offsets);

    size_t foundCount = 0;
    for (const KnownOffsetInfo& offset : offsets) {
        if (offset.found) {
            ++foundCount;
        }
    }

    status.success = true;
    status.itemCount = foundCount;
    return status;
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
        RunOneDumper(report, "known_offsets", [&]() {
            return DumpKnownOffsets(process, options.outputDirectory, report.buildNumber);
        });
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
