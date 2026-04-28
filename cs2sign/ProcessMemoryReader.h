#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdint>

struct MemoryRegion {
    uintptr_t base;
    size_t size;
    DWORD protect;
    std::string module;
};

struct ProcessModule {
    std::wstring name;
    std::wstring path;
    uintptr_t base = 0;
    size_t size = 0;
};

class ProcessMemoryReader {
public:
    ProcessMemoryReader();
    ~ProcessMemoryReader();

    bool Attach(const std::wstring& processName);
    void Detach();
    
    bool ReadMemory(uintptr_t address, void* buffer, size_t size);

    template <typename T>
    bool Read(uintptr_t address, T& value) {
        return ReadMemory(address, &value, sizeof(T));
    }

    bool ReadPointer(uintptr_t address, uintptr_t& value);
    bool ReadString(uintptr_t address, std::string& value, size_t maxLength = 256);
    bool ReadBuffer(uintptr_t address, size_t size, std::vector<std::uint8_t>& buffer);
    
    uintptr_t GetModuleBase(const std::wstring& moduleName);
    bool GetModuleInfo(const std::wstring& moduleName, ProcessModule& module);
    std::vector<ProcessModule> GetModules();
    std::vector<MemoryRegion> GetMemoryRegions();
    
    bool IsValid() const { return m_hProcess != nullptr; }
    DWORD GetProcessId() const { return m_dwProcessId; }
    HANDLE GetHandle() const { return m_hProcess; }

private:
    HANDLE m_hProcess;
    DWORD m_dwProcessId;
    std::wstring m_processName;
};

