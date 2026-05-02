#include "ProcessMemoryReader.h"

#include <algorithm>

namespace {
bool IsReadableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    const DWORD baseProtect = protect & 0xff;
    return baseProtect == PAGE_READONLY ||
           baseProtect == PAGE_READWRITE ||
           baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READ ||
           baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}
}

ProcessMemoryReader::ProcessMemoryReader() : m_hProcess(nullptr), m_dwProcessId(0) {
}

ProcessMemoryReader::~ProcessMemoryReader() {
    Detach();
}

bool ProcessMemoryReader::Attach(const std::wstring& processName) {
    Detach();
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        if (processName == pe32.szExeFile) {
            m_dwProcessId = pe32.th32ProcessID;
            m_processName = processName;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (m_dwProcessId == 0) {
        return false;
    }

    m_hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_dwProcessId);
    return m_hProcess != nullptr;
}

void ProcessMemoryReader::Detach() {
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    m_dwProcessId = 0;
    m_processName.clear();
}

bool ProcessMemoryReader::ReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (!m_hProcess) {
        return false;
    }

    SIZE_T bytesRead = 0;
    return ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
}

bool ProcessMemoryReader::ReadPointer(uintptr_t address, uintptr_t& value) {
    value = 0;
    return Read(address, value);
}

bool ProcessMemoryReader::ReadString(uintptr_t address, std::string& value, size_t maxLength) {
    value.clear();
    if (!m_hProcess || address == 0 || maxLength == 0) {
        return false;
    }

    std::vector<char> buffer(maxLength + 1, '\0');
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            m_hProcess,
            reinterpret_cast<LPCVOID>(address),
            buffer.data(),
            maxLength,
            &bytesRead
        ) || bytesRead == 0) {
        return false;
    }

    buffer[bytesRead < buffer.size() ? bytesRead : buffer.size() - 1] = '\0';
    value.assign(buffer.data());
    return true;
}

bool ProcessMemoryReader::ReadBuffer(uintptr_t address, size_t size, std::vector<std::uint8_t>& buffer) {
    buffer.assign(size, 0);
    if (!m_hProcess || address == 0 || size == 0) {
        return false;
    }

    constexpr size_t pageSize = 0x1000;
    bool readAllPages = true;

    for (size_t offset = 0; offset < size; offset += pageSize) {
        const size_t chunkSize = (std::min)(pageSize, size - offset);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                m_hProcess,
                reinterpret_cast<LPCVOID>(address + offset),
                buffer.data() + offset,
                chunkSize,
                &bytesRead
            ) ||
            bytesRead != chunkSize) {
            readAllPages = false;
        }
    }

    return readAllPages;
}

uintptr_t ProcessMemoryReader::GetModuleBase(const std::wstring& moduleName) {
    if (!m_hProcess) {
        return 0;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    uintptr_t base = 0;
    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (moduleName == me32.szModule) {
                base = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return base;
}

bool ProcessMemoryReader::GetModuleInfo(const std::wstring& moduleName, ProcessModule& module) {
    const std::vector<ProcessModule> modules = GetModules();
    const auto match = std::find_if(modules.begin(), modules.end(), [&](const ProcessModule& candidate) {
        return candidate.name == moduleName;
    });

    if (match == modules.end()) {
        module = {};
        return false;
    }

    module = *match;
    return true;
}

std::vector<ProcessModule> ProcessMemoryReader::GetModules() {
    std::vector<ProcessModule> modules;

    if (!m_hProcess) {
        return modules;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            ProcessModule module;
            module.name = me32.szModule;
            module.path = me32.szExePath;
            module.base = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
            module.size = static_cast<size_t>(me32.modBaseSize);
            modules.push_back(module);
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return modules;
}

std::vector<MemoryRegion> ProcessMemoryReader::GetMemoryRegions() {
    std::vector<MemoryRegion> regions;
    
    if (!m_hProcess) {
        return regions;
    }

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect)) {
            
            MemoryRegion region;
            region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.protect = mbi.Protect;
            
            wchar_t moduleName[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(m_hProcess, reinterpret_cast<HMODULE>(mbi.AllocationBase), moduleName, MAX_PATH)) {
                std::wstring wstr(moduleName);
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
                region.module.resize(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &region.module[0], size_needed, NULL, NULL);
            }
            
            regions.push_back(region);
        }
        
        const uintptr_t nextAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextAddress <= address) {
            break;
        }
        address = nextAddress;
    }

    return regions;
}

