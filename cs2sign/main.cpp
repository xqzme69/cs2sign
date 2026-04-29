#include <windows.h>

#include "BadApplePlayer.h"
#include "Console.h"
#include "DumpUtils.h"
#include "ExternalDumpers.h"
#include "ProcessMemoryReader.h"
#include "RemoteSignatureProvider.h"
#include "SdkGenerator.h"
#include "SignatureLoader.h"
#include "SignatureScanner.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
constexpr const char* kCs2SignVersion = "0.1.5";
constexpr const char* kDefaultSignatureInputPath = "signatures.json";
constexpr const char* kDefaultRemoteSignatureManifestUrl =
    "https://api.github.com/repos/xqzme69/cs2sign/contents/signatures/index.json?ref=main";
constexpr const wchar_t* kTargetProcessName = L"cs2.exe";

enum class SignatureSourceMode {
    RemoteGitHub,
    LocalDirectory
};

struct RuntimeOptions {
    std::string signatureInputPath = kDefaultSignatureInputPath;
    std::string remoteSignatureManifestUrl = kDefaultRemoteSignatureManifestUrl;
    SignatureSourceMode signatureSourceMode = SignatureSourceMode::RemoteGitHub;
    bool shouldRunSignatureScan = true;
    bool shouldPauseBeforeExit = true;
    bool shouldGenerateSdk = false;
    bool showConsoleLogs = true;
    ReadOnlyDumpOptions dumpOptions;
};

struct CommandLineParseResult {
    RuntimeOptions options;
    bool shouldShowHelp = false;
    bool shouldShowVersion = false;
    bool hasError = false;
    std::string errorMessage;
};

struct SignatureLoadReport {
    size_t jsonFileCount = 0;
    int loadedSignatureCount = 0;
};

struct RunHealthReport {
    size_t jsonFileCount = 0;
    int jsonSignatureCount = 0;
    size_t totalSignatureCount = 0;
    size_t foundSignatureCount = 0;
    size_t missingSignatureCount = 0;
    size_t requiredSignatureCount = 0;
    size_t requiredFoundSignatureCount = 0;
    size_t requiredMissingSignatureCount = 0;
    size_t optionalSignatureCount = 0;
    size_t optionalFoundSignatureCount = 0;
    size_t optionalMissingSignatureCount = 0;
    size_t validationErrorCount = 0;
    bool signatureScanRan = false;
    bool signatureScanSkipped = false;
    bool attachedToProcess = false;
    DWORD processId = 0;
    ReadOnlyDumpReport readOnlyReport;
    bool hasReadOnlyReport = false;
    SdkGenerationReport sdkReport;
    bool hasSdkReport = false;
};

class ScopedQuietAnimation {
public:
    explicit ScopedQuietAnimation(bool enabled) : enabled_(enabled) {
        if (!enabled_) {
            return;
        }

        Console::SetLogOutputEnabled(false);
        player_.Start();
    }

    ~ScopedQuietAnimation() {
        Stop();
    }

    void CompleteAndStop() {
        if (!enabled_) {
            return;
        }

        player_.CompleteAndWait();
        Console::SetLogOutputEnabled(true);
        enabled_ = false;
    }

    void Stop() {
        if (!enabled_) {
            return;
        }

        player_.Stop();
        Console::SetLogOutputEnabled(true);
        enabled_ = false;
    }

private:
    bool enabled_ = false;
    BadApplePlayer player_;
};

bool HasSignatureJsonSuffix(const std::filesystem::path& path) {
    const std::string filename = path.filename().string();
    if (filename == "cs2_signatures.json") {
        return false;
    }

    constexpr const char* suffix = "_signatures.json";
    constexpr size_t suffixLength = 16;

    return filename.size() > suffixLength &&
           filename.substr(filename.size() - suffixLength) == suffix;
}

std::wstring ToConsolePath(const std::string& path) {
    return std::filesystem::path(path).wstring();
}

void PrintUsage() {
    std::cout
        << "Usage: cs2sign.exe [signature-file-or-directory] [options]\n\n"
        << "Options:\n"
        << "  --remote-signatures\n"
        << "                     Download generated JSON signatures from the GitHub index (default).\n"
        << "  --remote-signatures-url <url>\n"
        << "                     Override the GitHub signature index URL.\n"
        << "  --local-signatures Use *_signatures.json files from the exe/current directory.\n"
        << "  --no-signatures    Skip signature scanning and run only selected dumpers.\n"
        << "  --dump-all         Run read-only schemas, interfaces, offsets, and dump_info.\n"
        << "  --dump-schemas     Dump Source 2 schema classes/enums through ReadProcessMemory.\n"
        << "  --dump-interfaces  Dump Source 2 interface registries through CreateInterface exports.\n"
        << "  --dump-offsets     Dump curated known offsets through module pattern scanning.\n"
        << "  --dump-info        Write dump_info.json with timestamp, modules, and dumper status.\n"
        << "  --emit-sdk         Generate SDK files from dump\\schemas.\n"
        << "  --output <dir>     Output directory for read-only dumpers (default: dump).\n"
        << "  --no-pause         Exit immediately instead of waiting for a key press.\n"
        << "  --version          Show cs2sign version.\n"
        << "  --help             Show this help text.\n";
}

CommandLineParseResult ParseCommandLine(int argc, char* argv[]) {
    CommandLineParseResult parseResult;
    bool hasSignatureInputPath = false;

    for (int argumentIndex = 1; argumentIndex < argc; ++argumentIndex) {
        const std::string argument = argv[argumentIndex];

        if (argument == "--help" || argument == "-h") {
            parseResult.shouldShowHelp = true;
            return parseResult;
        }

        if (argument == "--version" || argument == "-v") {
            parseResult.shouldShowVersion = true;
            return parseResult;
        }

        if (argument == "--remote-signatures") {
            parseResult.options.signatureSourceMode = SignatureSourceMode::RemoteGitHub;
            continue;
        }

        if (argument == "--local-signatures") {
            parseResult.options.signatureSourceMode = SignatureSourceMode::LocalDirectory;
            parseResult.options.signatureInputPath = ".";
            continue;
        }

        if (argument == "--remote-signatures-url") {
            if (argumentIndex + 1 >= argc) {
                parseResult.hasError = true;
                parseResult.errorMessage = "--remote-signatures-url requires a URL.";
                return parseResult;
            }

            parseResult.options.signatureSourceMode = SignatureSourceMode::RemoteGitHub;
            parseResult.options.remoteSignatureManifestUrl = argv[++argumentIndex];
            continue;
        }

        if (argument == "--no-signatures") {
            parseResult.options.shouldRunSignatureScan = false;
            continue;
        }

        if (argument == "--dump-all") {
            parseResult.options.dumpOptions.dumpSchemas = true;
            parseResult.options.dumpOptions.dumpInterfaces = true;
            parseResult.options.dumpOptions.dumpOffsets = true;
            parseResult.options.dumpOptions.dumpInfo = true;
            continue;
        }

        if (argument == "--dump-schemas") {
            parseResult.options.dumpOptions.dumpSchemas = true;
            continue;
        }

        if (argument == "--dump-interfaces") {
            parseResult.options.dumpOptions.dumpInterfaces = true;
            continue;
        }

        if (argument == "--dump-offsets") {
            parseResult.options.dumpOptions.dumpOffsets = true;
            continue;
        }

        if (argument == "--dump-info") {
            parseResult.options.dumpOptions.dumpInfo = true;
            continue;
        }

        if (argument == "--emit-sdk") {
            parseResult.options.shouldGenerateSdk = true;
            continue;
        }

        if (argument == "--output") {
            if (argumentIndex + 1 >= argc) {
                parseResult.hasError = true;
                parseResult.errorMessage = "--output requires a directory path.";
                return parseResult;
            }

            parseResult.options.dumpOptions.outputDirectory = argv[++argumentIndex];
            continue;
        }

        if (argument == "--no-pause") {
            parseResult.options.shouldPauseBeforeExit = false;
            continue;
        }

        if (!argument.empty() && argument[0] == '-') {
            parseResult.hasError = true;
            parseResult.errorMessage = "Unknown option: " + argument;
            return parseResult;
        }

        if (hasSignatureInputPath) {
            parseResult.hasError = true;
            parseResult.errorMessage = "Only one signature file or directory can be provided.";
            return parseResult;
        }

        parseResult.options.signatureInputPath = argument;
        parseResult.options.signatureSourceMode = SignatureSourceMode::LocalDirectory;
        hasSignatureInputPath = true;
    }

    return parseResult;
}

void PrintReadOnlyDumpSummary(const ReadOnlyDumpReport& report, const std::filesystem::path& outputDirectory) {
    if (!Console::IsLogOutputEnabled()) {
        return;
    }

    for (const DumperStatus& status : report.statuses) {
        const std::wstring displayName(status.name.begin(), status.name.end());
        if (status.success) {
            Console::PrintSuccess(
                displayName + L" -> " + std::to_wstring(status.itemCount) + L" item(s)"
            );
        } else {
            const std::wstring error(status.error.begin(), status.error.end());
            Console::PrintWarning(displayName + L" -> failed: " + error);
        }
    }

    Console::SetColor(Console::CYAN);
    std::cout << "  [*] Dump output: ";
    Console::SetColor(Console::YELLOW);
    std::cout << outputDirectory.string() << std::endl;
    Console::ResetColor();
}

void PrintSdkGenerationSummary(const SdkGenerationReport& report) {
    if (!Console::IsLogOutputEnabled()) {
        return;
    }

    if (!report.success) {
        const std::wstring error(report.error.begin(), report.error.end());
        Console::PrintError(L"SDK generation failed: " + error);
        return;
    }

    Console::PrintSuccess(
        L"modules -> " + std::to_wstring(report.moduleCount) +
        L", classes -> " + std::to_wstring(report.classCount) +
        L", enums -> " + std::to_wstring(report.enumCount)
    );

    Console::PrintSuccess(
        L"SDK files -> " +
        std::to_wstring(report.cppFileCount + report.csharpFileCount + report.rustFileCount + report.zigFileCount) +
        L" language file(s), 1 IDA header"
    );

    Console::SetColor(Console::CYAN);
    std::cout << "  [*] C++ SDK: ";
    Console::SetColor(Console::YELLOW);
    std::cout << report.cppDirectory.string() << std::endl;
    Console::SetColor(Console::CYAN);
    std::cout << "  [*] C# SDK: ";
    Console::SetColor(Console::YELLOW);
    std::cout << report.csharpDirectory.string() << std::endl;
    Console::SetColor(Console::CYAN);
    std::cout << "  [*] Rust SDK: ";
    Console::SetColor(Console::YELLOW);
    std::cout << report.rustDirectory.string() << std::endl;
    Console::SetColor(Console::CYAN);
    std::cout << "  [*] Zig SDK: ";
    Console::SetColor(Console::YELLOW);
    std::cout << report.zigDirectory.string() << std::endl;
    Console::SetColor(Console::CYAN);
    std::cout << "  [*] IDA header: ";
    Console::SetColor(Console::YELLOW);
    std::cout << report.idaHeader.string() << std::endl;
    Console::ResetColor();
}

void EnableAllReadOnlyDumpers(RuntimeOptions& options) {
    options.dumpOptions.dumpSchemas = true;
    options.dumpOptions.dumpInterfaces = true;
    options.dumpOptions.dumpOffsets = true;
    options.dumpOptions.dumpInfo = true;
}

void PrintConsoleOutputMenu() {
    Console::PrintHeader(L"Console Output");
    Console::SetColor(Console::WHITE);
    std::cout << "  1. Show detailed console logs\n";
    std::cout << "  2. Bad Apple mode (hide logs while running)\n";
    Console::ResetColor();

    Console::SetColor(Console::DARK_GRAY);
    std::cout << "\n  Enter output choice [1]: ";
    Console::ResetColor();
}

void PrintInteractiveMenu() {
    Console::PrintHeader(L"Menu");
    Console::SetColor(Console::WHITE);
    std::cout << "  1. Full workflow: scan signatures + read-only dump + SDK\n";
    std::cout << "  2. Signature scan only\n";
    std::cout << "  3. Read-only dump only\n";
    std::cout << "  4. Generate SDK from existing dump\\schemas\n";
    std::cout << "  5. Exit\n";
    Console::ResetColor();

    Console::SetColor(Console::DARK_GRAY);
    std::cout << "\n  Enter choice [1]: ";
    Console::ResetColor();
}

bool ConfigureConsoleOutputFromInteractiveMenu(RuntimeOptions& options) {
    PrintConsoleOutputMenu();

    std::string choice;
    std::getline(std::cin, choice);
    choice = ToLowerAscii(choice);

    options.showConsoleLogs = !(choice == "2" || choice == "b" || choice == "bad" ||
                                choice == "bad apple" || choice == "n" || choice == "no");
    Console::PrintFooter();
    return true;
}

void PrintSignatureSourceMenu() {
    Console::PrintHeader(L"Signature Source");
    Console::SetColor(Console::WHITE);
    std::cout << "  1. GitHub signatures (recommended)\n";
    std::cout << "  2. Local mode: put *_signatures.json near exe\n";
    Console::ResetColor();

    Console::SetColor(Console::DARK_GRAY);
    std::cout << "\n  Enter signature source [1]: ";
    Console::ResetColor();
}

void ConfigureSignatureSourceFromInteractiveMenu(RuntimeOptions& options) {
    PrintSignatureSourceMenu();

    std::string choice;
    std::getline(std::cin, choice);
    choice = ToLowerAscii(choice);

    if (choice == "2" || choice == "l" || choice == "local") {
        options.signatureSourceMode = SignatureSourceMode::LocalDirectory;
        options.signatureInputPath = ".";
    } else {
        options.signatureSourceMode = SignatureSourceMode::RemoteGitHub;
    }

    Console::PrintFooter();
}

bool ConfigureOptionsFromInteractiveMenu(RuntimeOptions& options) {
    options = RuntimeOptions{};
    options.signatureInputPath = ".";
    ConfigureConsoleOutputFromInteractiveMenu(options);
    ConfigureSignatureSourceFromInteractiveMenu(options);

    PrintInteractiveMenu();

    std::string choice;
    std::getline(std::cin, choice);
    if (choice.empty()) {
        choice = "1";
    }

    bool configured = true;

    if (choice == "1") {
        options.shouldRunSignatureScan = true;
        options.shouldGenerateSdk = true;
        EnableAllReadOnlyDumpers(options);
    } else if (choice == "2") {
        options.shouldRunSignatureScan = true;
    } else if (choice == "3") {
        options.shouldRunSignatureScan = false;
        EnableAllReadOnlyDumpers(options);
    } else if (choice == "4") {
        options.shouldRunSignatureScan = false;
        options.shouldGenerateSdk = true;
    } else {
        configured = false;
    }

    if (configured) {
        Console::PrintFooter();
        return true;
    }

    Console::PrintFooter();
    return false;
}

void PauseBeforeExitIfNeeded(bool shouldPauseBeforeExit) {
    if (!shouldPauseBeforeExit) {
        return;
    }

    Console::SetColor(Console::DARK_GRAY);
    std::cout << "\n  Press any key to exit...";
    Console::ResetColor();
    system("pause >nul");
}

std::vector<std::string> FindSignatureJsonFilesInDirectory(const std::filesystem::path& directory) {
    std::vector<std::string> signatureFiles;

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file() && HasSignatureJsonSuffix(entry.path())) {
            signatureFiles.push_back(entry.path().string());
        }
    }

    return signatureFiles;
}

std::vector<std::string> DiscoverSignatureFiles(
    const std::string& signatureInputPath,
    const char* executablePath
) {
    namespace fs = std::filesystem;

    const fs::path requestedPath(signatureInputPath);
    if (fs::is_directory(requestedPath)) {
        return FindSignatureJsonFilesInDirectory(requestedPath);
    }

    if (fs::is_regular_file(requestedPath)) {
        return { signatureInputPath };
    }

    fs::path executableDirectory = fs::path(executablePath).parent_path();
    if (executableDirectory.empty()) {
        executableDirectory = ".";
    }

    return FindSignatureJsonFilesInDirectory(executableDirectory);
}

std::string GetRemoteSignatureManifestUrl(const RuntimeOptions& options) {
    char environmentUrl[2048]{};
    const DWORD length = GetEnvironmentVariableA(
        "CS2SIGN_SIGNATURE_INDEX_URL",
        environmentUrl,
        static_cast<DWORD>(sizeof(environmentUrl))
    );
    if (length > 0 && length < sizeof(environmentUrl)) {
        return environmentUrl;
    }

    return options.remoteSignatureManifestUrl;
}

std::vector<std::string> ResolveSignatureFilesForOptions(
    const RuntimeOptions& options,
    const char* executablePath
) {
    if (options.signatureSourceMode == SignatureSourceMode::LocalDirectory) {
        Console::PrintInfo(L"Signature source: local *_signatures.json files");
        return DiscoverSignatureFiles(options.signatureInputPath, executablePath);
    }

    Console::PrintInfo(L"Signature source: GitHub");
    const std::string manifestUrl = GetRemoteSignatureManifestUrl(options);
    Console::PrintInfo(L"Downloading signature index...");

    const RemoteSignatureResult remoteResult = ResolveRemoteSignatureFiles({
        manifestUrl,
        GetDefaultRemoteSignatureCacheDirectory()
    });
    if (!remoteResult.success) {
        const std::wstring error(remoteResult.error.begin(), remoteResult.error.end());
        Console::PrintError(L"Remote signatures failed: " + error);
        Console::PrintWarning(L"Use Local mode and put *_signatures.json near exe if needed.");
        return {};
    }

    Console::PrintSuccess(
        L"Downloaded " + std::to_wstring(remoteResult.signatureFiles.size()) +
        L" signature file(s)"
    );
    return remoteResult.signatureFiles;
}

SignatureLoadReport LoadJsonSignatureFiles(
    SignatureScanner& scanner,
    const std::vector<std::string>& signatureFiles
) {
    SignatureLoadReport report;
    report.jsonFileCount = signatureFiles.size();

    if (signatureFiles.empty()) {
        return report;
    }

    Console::PrintInfo(L"Found " + std::to_wstring(signatureFiles.size()) + L" JSON file(s):");

    for (const auto& signatureFile : signatureFiles) {
        const int loadedCount = LoadSignaturesFromJSON(scanner, signatureFile);
        const std::wstring displayPath = ToConsolePath(signatureFile);

        if (loadedCount > 0) {
            Console::PrintSuccess(
                L"  " + displayPath + L" -> " + std::to_wstring(loadedCount) + L" signatures"
            );
            report.loadedSignatureCount += loadedCount;
            continue;
        }

        if (loadedCount == 0) {
            Console::PrintWarning(L"  " + displayPath + L" -> 0 signatures");
            continue;
        }

        Console::PrintWarning(L"  " + displayPath + L" -> failed to load");
    }

    Console::PrintSuccess(
        L"Total from JSON: " + std::to_wstring(report.loadedSignatureCount) + L" signatures"
    );
    return report;
}

void PrintNoJsonFilesWarning() {
    Console::PrintWarning(L"No *_signatures.json files found. Run the IDA plugin or use GitHub signatures.");
}

size_t CountPatternValidationErrors(const SignatureScanner& scanner) {
    size_t errorCount = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (!signature.error.empty() &&
            signature.error.find("Pattern and mask length mismatch") != std::string::npos) {
            ++errorCount;
        }
    }

    return errorCount;
}

size_t CountFoundSignatures(const SignatureScanner& scanner) {
    size_t foundCount = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (signature.found) {
            ++foundCount;
        }
    }

    return foundCount;
}

size_t CountRequiredSignatures(const SignatureScanner& scanner) {
    size_t count = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (signature.required) {
            ++count;
        }
    }

    return count;
}

size_t CountRequiredFoundSignatures(const SignatureScanner& scanner) {
    size_t count = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (signature.required && signature.found) {
            ++count;
        }
    }

    return count;
}

size_t CountOptionalSignatures(const SignatureScanner& scanner) {
    size_t count = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (!signature.required) {
            ++count;
        }
    }

    return count;
}

size_t CountOptionalFoundSignatures(const SignatureScanner& scanner) {
    size_t count = 0;

    for (const auto& signature : scanner.GetSignatures()) {
        if (!signature.required && signature.found) {
            ++count;
        }
    }

    return count;
}

void RefreshSignatureHealth(RunHealthReport& report, const SignatureScanner& scanner) {
    report.totalSignatureCount = scanner.GetSignatures().size();
    report.foundSignatureCount = CountFoundSignatures(scanner);
    report.missingSignatureCount = report.totalSignatureCount - report.foundSignatureCount;
    report.requiredSignatureCount = CountRequiredSignatures(scanner);
    report.requiredFoundSignatureCount = CountRequiredFoundSignatures(scanner);
    report.requiredMissingSignatureCount =
        report.requiredSignatureCount - report.requiredFoundSignatureCount;
    report.optionalSignatureCount = CountOptionalSignatures(scanner);
    report.optionalFoundSignatureCount = CountOptionalFoundSignatures(scanner);
    report.optionalMissingSignatureCount =
        report.optionalSignatureCount - report.optionalFoundSignatureCount;
    report.validationErrorCount = CountPatternValidationErrors(scanner);
}

std::string DetermineHealthStatus(const RunHealthReport& report) {
    if (report.validationErrorCount > 0) {
        return "bad";
    }

    if (report.signatureScanRan && report.requiredSignatureCount > 0) {
        const double foundRatio = static_cast<double>(report.requiredFoundSignatureCount) /
            static_cast<double>(report.requiredSignatureCount);
        if (foundRatio < 0.75) {
            return "bad";
        }
        if (foundRatio < 0.95) {
            return "degraded";
        }
    }

    if (report.hasReadOnlyReport) {
        for (const DumperStatus& status : report.readOnlyReport.statuses) {
            if (!status.success) {
                return "degraded";
            }
        }
    }

    if (report.hasSdkReport && !report.sdkReport.success) {
        return "degraded";
    }

    return "ok";
}

void WriteUpdateReport(
    const RunHealthReport& report,
    const std::filesystem::path& outputDirectory,
    ProcessMemoryReader& process
) {
    std::error_code errorCode;
    std::filesystem::create_directories(outputDirectory, errorCode);
    if (errorCode) {
        Console::PrintWarning(L"Failed to create update report directory: " + outputDirectory.wstring());
        return;
    }

    const std::filesystem::path reportPath = outputDirectory / "update_report.json";
    std::ofstream file(reportPath);
    if (!file.is_open()) {
        Console::PrintWarning(L"Failed to write update report: " + reportPath.wstring());
        return;
    }

    file << "{\n";
    file << "  \"generator\": \"cs2sign\",\n";
    file << "  \"generator_version\": \"" << kCs2SignVersion << "\",\n";
    file << "  \"timestamp\": \"" << CurrentTimestampUtc() << "\",\n";
    file << "  \"health\": \"" << DetermineHealthStatus(report) << "\",\n";
    file << "  \"process\": {\n";
    file << "    \"attached\": " << (report.attachedToProcess ? "true" : "false") << ",\n";
    file << "    \"pid\": " << report.processId << "\n";
    file << "  },\n";

    file << "  \"signatures\": {\n";
    file << "    \"scan_ran\": " << (report.signatureScanRan ? "true" : "false") << ",\n";
    file << "    \"scan_skipped\": " << (report.signatureScanSkipped ? "true" : "false") << ",\n";
    file << "    \"json_files\": " << report.jsonFileCount << ",\n";
    file << "    \"json_loaded\": " << report.jsonSignatureCount << ",\n";
    file << "    \"total\": " << report.totalSignatureCount << ",\n";
    file << "    \"found\": " << report.foundSignatureCount << ",\n";
    file << "    \"missing\": " << report.missingSignatureCount << ",\n";
    file << "    \"required_total\": " << report.requiredSignatureCount << ",\n";
    file << "    \"required_found\": " << report.requiredFoundSignatureCount << ",\n";
    file << "    \"required_missing\": " << report.requiredMissingSignatureCount << ",\n";
    file << "    \"optional_total\": " << report.optionalSignatureCount << ",\n";
    file << "    \"optional_found\": " << report.optionalFoundSignatureCount << ",\n";
    file << "    \"optional_missing\": " << report.optionalMissingSignatureCount << ",\n";
    file << "    \"validation_errors\": " << report.validationErrorCount << "\n";
    file << "  },\n";

    file << "  \"read_only_dumpers\": [\n";
    for (size_t index = 0; index < report.readOnlyReport.statuses.size(); ++index) {
        const DumperStatus& status = report.readOnlyReport.statuses[index];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(status.name) << "\",\n";
        file << "      \"success\": " << (status.success ? "true" : "false") << ",\n";
        file << "      \"item_count\": " << status.itemCount << ",\n";
        file << "      \"error\": \"" << EscapeJson(status.error) << "\"\n";
        file << "    }" << (index + 1 == report.readOnlyReport.statuses.size() ? "" : ",") << "\n";
    }
    file << "  ],\n";

    file << "  \"sdk\": {\n";
    file << "    \"ran\": " << (report.hasSdkReport ? "true" : "false") << ",\n";
    file << "    \"success\": " << (report.hasSdkReport && report.sdkReport.success ? "true" : "false") << ",\n";
    file << "    \"modules\": " << (report.hasSdkReport ? report.sdkReport.moduleCount : 0) << ",\n";
    file << "    \"classes\": " << (report.hasSdkReport ? report.sdkReport.classCount : 0) << ",\n";
    file << "    \"enums\": " << (report.hasSdkReport ? report.sdkReport.enumCount : 0) << ",\n";
    file << "    \"cpp_files\": " << (report.hasSdkReport ? report.sdkReport.cppFileCount : 0) << ",\n";
    file << "    \"csharp_files\": " << (report.hasSdkReport ? report.sdkReport.csharpFileCount : 0) << ",\n";
    file << "    \"rust_files\": " << (report.hasSdkReport ? report.sdkReport.rustFileCount : 0) << ",\n";
    file << "    \"zig_files\": " << (report.hasSdkReport ? report.sdkReport.zigFileCount : 0) << ",\n";
    file << "    \"error\": \"" << EscapeJson(report.hasSdkReport ? report.sdkReport.error : "") << "\"\n";
    file << "  },\n";

    file << "  \"build_number\": ";
    if (report.readOnlyReport.buildNumber) {
        file << *report.readOnlyReport.buildNumber;
    } else {
        file << "null";
    }
    file << ",\n";

    file << "  \"modules\": [\n";
    const std::vector<ProcessModule> modules = process.IsValid()
        ? process.GetModules()
        : std::vector<ProcessModule>{};
    for (size_t index = 0; index < modules.size(); ++index) {
        const ProcessModule& module = modules[index];
        file << "    {\n";
        file << "      \"name\": \"" << EscapeJson(WideToUtf8(module.name)) << "\",\n";
        file << "      \"path\": \"" << EscapeJson(WideToUtf8(module.path)) << "\",\n";
        file << "      \"base\": \"0x" << std::hex << std::uppercase << module.base << std::dec << "\",\n";
        file << "      \"size\": " << module.size << "\n";
        file << "    }" << (index + 1 == modules.size() ? "" : ",") << "\n";
    }
    file << "  ]\n";
    file << "}\n";

    if (!Console::IsLogOutputEnabled()) {
        return;
    }

    Console::SetColor(Console::CYAN);
    std::cout << "  [*] Update report: ";
    Console::SetColor(Console::YELLOW);
    std::cout << reportPath.string() << std::endl;
    Console::ResetColor();
}

void PrintScanSummary(const SignatureScanner& scanner) {
    if (!Console::IsLogOutputEnabled()) {
        return;
    }

    const size_t foundCount = CountFoundSignatures(scanner);
    const size_t requiredCount = CountRequiredSignatures(scanner);
    const size_t requiredFoundCount = CountRequiredFoundSignatures(scanner);
    const size_t optionalCount = CountOptionalSignatures(scanner);
    const size_t optionalFoundCount = CountOptionalFoundSignatures(scanner);
    const size_t validationErrorCount = CountPatternValidationErrors(scanner);

    Console::SetColor(Console::GREEN);
    std::cout << "  [+] Found: ";
    Console::SetColor(Console::YELLOW);
    std::cout << foundCount;
    Console::SetColor(Console::WHITE);
    std::cout << " / " << scanner.GetSignatures().size() << std::endl;
    Console::ResetColor();

    if (optionalCount > 0) {
        Console::SetColor(Console::CYAN);
        std::cout << "  [*] Required: ";
        Console::SetColor(Console::YELLOW);
        std::cout << requiredFoundCount;
        Console::SetColor(Console::WHITE);
        std::cout << " / " << requiredCount;
        Console::SetColor(Console::CYAN);
        std::cout << " | Optional: ";
        Console::SetColor(Console::YELLOW);
        std::cout << optionalFoundCount;
        Console::SetColor(Console::WHITE);
        std::cout << " / " << optionalCount << std::endl;
        Console::ResetColor();
    }

    if (validationErrorCount > 0) {
        Console::SetColor(Console::RED);
        std::cout << "  [-] Errors: ";
        Console::SetColor(Console::YELLOW);
        std::cout << validationErrorCount << std::endl;
        Console::ResetColor();
    }

    Console::SetColor(Console::CYAN);
    std::cout << "  [*] Results saved to: ";
    Console::SetColor(Console::YELLOW);
    std::cout << "cs2_signatures.json" << std::endl;
    Console::ResetColor();
}

void PrintQuietRunSummary(
    int exitCode,
    const RunHealthReport& report,
    const std::filesystem::path& outputDirectory
) {
    Console::PrintHeader(L"Finished");
    if (exitCode == 0) {
        Console::PrintSuccess(L"Done. Console logs were disabled during the run.");
    } else {
        Console::PrintError(L"Run failed. Check dump\\update_report.json for details.");
    }

    if (report.signatureScanRan) {
        Console::PrintInfo(
            L"Signatures: " + std::to_wstring(report.foundSignatureCount) +
            L" found / " + std::to_wstring(report.totalSignatureCount) + L" total"
        );
    } else if (report.signatureScanSkipped) {
        Console::PrintInfo(L"Signature scan: skipped");
    }

    if (report.hasReadOnlyReport) {
        size_t successCount = 0;
        for (const DumperStatus& status : report.readOnlyReport.statuses) {
            if (status.success) {
                ++successCount;
            }
        }

        Console::PrintInfo(
            L"Read-only dumpers: " + std::to_wstring(successCount) +
            L" ok / " + std::to_wstring(report.readOnlyReport.statuses.size()) + L" total"
        );
    }

    if (report.hasSdkReport) {
        if (report.sdkReport.success) {
            Console::PrintInfo(
                L"SDK: " +
                std::to_wstring(
                    report.sdkReport.cppFileCount +
                    report.sdkReport.csharpFileCount +
                    report.sdkReport.rustFileCount +
                    report.sdkReport.zigFileCount
                ) +
                L" language file(s)"
            );
        } else {
            const std::wstring error(report.sdkReport.error.begin(), report.sdkReport.error.end());
            Console::PrintWarning(L"SDK failed: " + error);
        }
    }

    Console::PrintInfo(L"Update report: " + (outputDirectory / "update_report.json").wstring());
    Console::PrintFooter();
}

int ExitWithOptionalPause(int exitCode, bool shouldPauseBeforeExit) {
    PauseBeforeExitIfNeeded(shouldPauseBeforeExit);
    return exitCode;
}
}

int main(int argc, char* argv[]) {
    const CommandLineParseResult commandLine = ParseCommandLine(argc, argv);

    if (commandLine.shouldShowHelp) {
        PrintUsage();
        return 0;
    }

    if (commandLine.shouldShowVersion) {
        std::cout << "cs2sign " << kCs2SignVersion << "\n";
        return 0;
    }

    if (commandLine.hasError) {
        std::cerr << commandLine.errorMessage << "\n\n";
        PrintUsage();
        return 1;
    }

    Console::Init();
    system("title CS2 Signature Scanner - xqzme");
    Console::PrintBanner();

    RuntimeOptions options = commandLine.options;
    if (argc == 1 && !ConfigureOptionsFromInteractiveMenu(options)) {
        return ExitWithOptionalPause(0, options.shouldPauseBeforeExit);
    }
    RunHealthReport healthReport;
    healthReport.signatureScanSkipped = !options.shouldRunSignatureScan;

    const bool hasReadOnlyDumpWork = HasReadOnlyDumpWork(options.dumpOptions);
    const bool hasSdkWork = options.shouldGenerateSdk;

    if (!options.shouldRunSignatureScan && !hasReadOnlyDumpWork && !hasSdkWork) {
        std::cerr << "--no-signatures requires at least one dump or SDK option.\n\n";
        PrintUsage();
        return ExitWithOptionalPause(1, options.shouldPauseBeforeExit);
    }

    ScopedQuietAnimation quietAnimation(!options.showConsoleLogs);
    auto finishRun = [&](int exitCode) {
        quietAnimation.CompleteAndStop();
        if (!options.showConsoleLogs) {
            PrintQuietRunSummary(exitCode, healthReport, options.dumpOptions.outputDirectory);
        }
        return ExitWithOptionalPause(exitCode, options.shouldPauseBeforeExit);
    };

    const bool requiresProcess = options.shouldRunSignatureScan || hasReadOnlyDumpWork;

    ProcessMemoryReader processMemory;
    if (requiresProcess) {
        Console::PrintHeader(L"Initialization");

        Console::PrintInfo(L"Searching for process: " + std::wstring(kTargetProcessName));
        if (!processMemory.Attach(kTargetProcessName)) {
            Console::PrintError(L"Failed to attach to " + std::wstring(kTargetProcessName) + L"!");
            Console::PrintWarning(L"Make sure CS2 is running and try again.");
            WriteUpdateReport(healthReport, options.dumpOptions.outputDirectory, processMemory);
            Console::PrintFooter();
            return finishRun(1);
        }

        healthReport.attachedToProcess = true;
        healthReport.processId = processMemory.GetProcessId();
        Console::PrintSuccess(L"Successfully attached to CS2");
        if (Console::IsLogOutputEnabled()) {
            Console::SetColor(Console::CYAN);
            std::cout << "  Process ID: ";
            Console::SetColor(Console::YELLOW);
            std::cout << processMemory.GetProcessId() << std::endl;
            Console::ResetColor();
        }
        Console::PrintFooter();
    }

    SignatureScanner scanner(processMemory);
    if (options.shouldRunSignatureScan) {
        Console::PrintHeader(L"Signature Database");

        const std::vector<std::string> signatureFiles =
            ResolveSignatureFilesForOptions(options, argv[0]);
        const SignatureLoadReport jsonLoadReport = LoadJsonSignatureFiles(scanner, signatureFiles);
        healthReport.jsonFileCount = jsonLoadReport.jsonFileCount;
        healthReport.jsonSignatureCount = jsonLoadReport.loadedSignatureCount;
        RefreshSignatureHealth(healthReport, scanner);

        if (jsonLoadReport.jsonFileCount == 0) {
            PrintNoJsonFilesWarning();
        }

        Console::PrintInfo(L"Total signatures: " + std::to_wstring(scanner.GetSignatures().size()));

        if (scanner.GetSignatures().empty() && !hasReadOnlyDumpWork) {
            Console::PrintError(L"No signatures to scan!");
            Console::PrintFooter();
            WriteUpdateReport(healthReport, options.dumpOptions.outputDirectory, processMemory);
            return finishRun(1);
        }

        if (scanner.GetSignatures().empty()) {
            Console::PrintWarning(L"No signatures to scan; continuing with selected dumpers.");
        }
        Console::PrintFooter();
    }

    if (options.shouldRunSignatureScan && !scanner.GetSignatures().empty()) {
        Console::PrintHeader(L"Memory Scanning");
        Console::PrintInfo(L"Scanning memory regions...");

        const auto memoryRegions = processMemory.GetMemoryRegions();
        if (Console::IsLogOutputEnabled()) {
            Console::SetColor(Console::CYAN);
            std::cout << "  Memory Regions: ";
            Console::SetColor(Console::YELLOW);
            std::cout << memoryRegions.size() << std::endl;
            Console::ResetColor();

            std::cout << "\n";
        }
        scanner.ScanAll();
        healthReport.signatureScanRan = true;
        RefreshSignatureHealth(healthReport, scanner);

        Console::PrintFooter();

        Console::PrintHeader(L"Scan Results");
        PrintScanSummary(scanner);
        Console::PrintFooter();
    }

    if (hasReadOnlyDumpWork) {
        Console::PrintHeader(L"Read-Only Dumpers");
        ReadOnlyDumpReport report;
        RunReadOnlyDumpers(processMemory, options.dumpOptions, report);
        PrintReadOnlyDumpSummary(report, options.dumpOptions.outputDirectory);
        healthReport.readOnlyReport = report;
        healthReport.hasReadOnlyReport = true;
        Console::PrintFooter();
    }

    if (hasSdkWork) {
        Console::PrintHeader(L"SDK Generation");
        SdkGenerationOptions sdkOptions;
        sdkOptions.schemaDirectory = options.dumpOptions.outputDirectory / "schemas";
        sdkOptions.outputDirectory = options.dumpOptions.outputDirectory / "sdk";

        const SdkGenerationReport report = GenerateSdkFromSchemas(sdkOptions);
        PrintSdkGenerationSummary(report);
        healthReport.sdkReport = report;
        healthReport.hasSdkReport = true;
        Console::PrintFooter();

        if (!report.success) {
            WriteUpdateReport(healthReport, options.dumpOptions.outputDirectory, processMemory);
            if (requiresProcess) {
                processMemory.Detach();
            }
            return finishRun(1);
        }
    }

    WriteUpdateReport(healthReport, options.dumpOptions.outputDirectory, processMemory);

    if (requiresProcess) {
        processMemory.Detach();
    }
    return finishRun(0);
}
