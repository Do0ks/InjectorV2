#include "InjectorEngine.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <tlhelp32.h>

namespace
{
constexpr DWORD InjectionAccess =
    PROCESS_CREATE_THREAD |
    PROCESS_QUERY_LIMITED_INFORMATION |
    PROCESS_VM_OPERATION |
    PROCESS_VM_WRITE |
    SYNCHRONIZE;

struct PeInspection
{
    MachineKind machine = MachineKind::Unknown;
    bool dllImage = false;
};

class RemoteAllocation final
{
public:
    RemoteAllocation(HANDLE processHandle, SIZE_T byteCount)
        : processHandle_(processHandle),
          address_(VirtualAllocEx(processHandle, nullptr, byteCount, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
    {
    }

    RemoteAllocation(const RemoteAllocation&) = delete;
    RemoteAllocation& operator=(const RemoteAllocation&) = delete;

    ~RemoteAllocation()
    {
        free();
    }

    [[nodiscard]] LPVOID get() const noexcept
    {
        return address_;
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return address_ != nullptr;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return valid();
    }

    bool free(DWORD* errorCode = nullptr) noexcept
    {
        if (address_ == nullptr)
        {
            return true;
        }

        const BOOL freed = VirtualFreeEx(processHandle_, address_, 0, MEM_RELEASE);

        if (freed == FALSE)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }

            address_ = nullptr;
            return false;
        }

        address_ = nullptr;
        return true;
    }

    void release() noexcept
    {
        address_ = nullptr;
    }

private:
    HANDLE processHandle_ = nullptr;
    LPVOID address_ = nullptr;
};

quint16 readUInt16(const QByteArray& bytes, qsizetype offset)
{
    if (offset < 0 || offset + 1 >= bytes.size())
    {
        return 0;
    }

    return static_cast<quint16>(
        static_cast<unsigned char>(bytes.at(offset)) |
        (static_cast<unsigned char>(bytes.at(offset + 1)) << 8));
}

quint32 readUInt32(const QByteArray& bytes, qsizetype offset)
{
    if (offset < 0 || offset + 3 >= bytes.size())
    {
        return 0;
    }

    return static_cast<quint32>(
        static_cast<unsigned char>(bytes.at(offset)) |
        (static_cast<unsigned char>(bytes.at(offset + 1)) << 8) |
        (static_cast<unsigned char>(bytes.at(offset + 2)) << 16) |
        (static_cast<unsigned char>(bytes.at(offset + 3)) << 24));
}

PeInspection inspectPeHeader(const QByteArray& bytes)
{
    PeInspection inspection;

    if (bytes.size() < 0x40)
    {
        return inspection;
    }

    if (bytes.at(0) != 'M' || bytes.at(1) != 'Z')
    {
        return inspection;
    }

    const quint32 peOffset = readUInt32(bytes, 0x3C);

    if (peOffset == 0 || peOffset > static_cast<quint32>(bytes.size()))
    {
        return inspection;
    }

    const qsizetype peOffsetIndex = static_cast<qsizetype>(peOffset);

    if (peOffsetIndex + 24 > bytes.size())
    {
        return inspection;
    }

    if (bytes.at(peOffsetIndex) != 'P' || bytes.at(peOffsetIndex + 1) != 'E' || bytes.at(peOffsetIndex + 2) != '\0' || bytes.at(peOffsetIndex + 3) != '\0')
    {
        return inspection;
    }

    const quint16 machine = readUInt16(bytes, peOffsetIndex + 4);
    const quint16 characteristics = readUInt16(bytes, peOffsetIndex + 22);

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        inspection.machine = MachineKind::X86;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        inspection.machine = MachineKind::X64;
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        inspection.machine = MachineKind::Arm64;
        break;
    default:
        inspection.machine = MachineKind::Unknown;
        break;
    }

    inspection.dllImage = (characteristics & IMAGE_FILE_DLL) != 0;
    return inspection;
}

QString formatBytes(quint64 bytes)
{
    constexpr double kibibyte = 1024.0;
    constexpr double mebibyte = kibibyte * 1024.0;

    if (bytes >= static_cast<quint64>(mebibyte))
    {
        return QStringLiteral("%1 MB").arg(static_cast<double>(bytes) / mebibyte, 0, 'f', 2);
    }

    if (bytes >= static_cast<quint64>(kibibyte))
    {
        return QStringLiteral("%1 KB").arg(static_cast<double>(bytes) / kibibyte, 0, 'f', 1);
    }

    return QStringLiteral("%1 bytes").arg(bytes);
}

InjectionResult makeResult(
    bool successful,
    const QString& title,
    const QString& message,
    const QStringList& details)
{
    InjectionResult result;
    result.success = successful;
    result.title = title;
    result.message = message;
    result.details = details;
    return result;
}

InjectionResult failure(const QString& title, const QString& message, const QStringList& details = {})
{
    return makeResult(false, title, message, details);
}

InjectionResult success(const QString& title, const QString& message, const QStringList& details = {})
{
    return makeResult(true, title, message, details);
}

LPTHREAD_START_ROUTINE resolveRemoteLoadLibraryW(DWORD processId, QStringList& details, QString* errorMessage)
{
    const HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");

    if (kernel32Module == nullptr)
    {
        *errorMessage = QStringLiteral("Local kernel32.dll could not be located: %1").arg(ProcessScanner::windowsErrorMessage(GetLastError()));
        return nullptr;
    }

    const FARPROC loadLibraryW = GetProcAddress(kernel32Module, "LoadLibraryW");

    if (loadLibraryW == nullptr)
    {
        *errorMessage = QStringLiteral("Local LoadLibraryW could not be located: %1").arg(ProcessScanner::windowsErrorMessage(GetLastError()));
        return nullptr;
    }

    const auto localKernelBase = reinterpret_cast<quintptr>(kernel32Module);
    const auto localLoadLibraryAddress = reinterpret_cast<quintptr>(loadLibraryW);

    if (localLoadLibraryAddress < localKernelBase)
    {
        *errorMessage = QStringLiteral("Local LoadLibraryW address was outside kernel32.dll.");
        return nullptr;
    }

    const quintptr loadLibraryOffset = localLoadLibraryAddress - localKernelBase;
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId));

    if (!snapshot)
    {
        details << QStringLiteral("LoadLibraryW address: using local kernel32.dll fallback because target modules could not be enumerated");
        return reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW);
    }

    MODULEENTRY32W moduleEntry{};
    moduleEntry.dwSize = sizeof(moduleEntry);

    if (Module32FirstW(snapshot.get(), &moduleEntry) == FALSE)
    {
        details << QStringLiteral("LoadLibraryW address: using local kernel32.dll fallback because target module scan was empty");
        return reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW);
    }

    do
    {
        const QString moduleName = QString::fromWCharArray(moduleEntry.szModule);

        if (moduleName.compare(QStringLiteral("kernel32.dll"), Qt::CaseInsensitive) != 0)
        {
            continue;
        }

        const auto remoteKernelBase = reinterpret_cast<quintptr>(moduleEntry.modBaseAddr);
        const auto remoteLoadLibraryAddress = remoteKernelBase + loadLibraryOffset;
        details << QStringLiteral("LoadLibraryW address: resolved from target kernel32.dll");
        return reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteLoadLibraryAddress);
    } while (Module32NextW(snapshot.get(), &moduleEntry) != FALSE);

    details << QStringLiteral("LoadLibraryW address: using local kernel32.dll fallback because target kernel32.dll was not found");
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW);
}
}

DllInspection InjectorEngine::inspectDll(const QString& dllPath)
{
    DllInspection inspection;
    const QString trimmedPath = dllPath.trimmed();
    inspection.path = trimmedPath;

    if (trimmedPath.isEmpty())
    {
        inspection.errorMessage = QStringLiteral("No DLL selected.");
        return inspection;
    }

    const QFileInfo fileInfo(trimmedPath);
    inspection.path = fileInfo.absoluteFilePath();
    inspection.fileName = fileInfo.fileName();

    if (!fileInfo.exists() || !fileInfo.isFile())
    {
        inspection.errorMessage = QStringLiteral("The selected DLL does not exist.");
        return inspection;
    }

    if (fileInfo.suffix().compare(QStringLiteral("dll"), Qt::CaseInsensitive) != 0)
    {
        inspection.errorMessage = QStringLiteral("The selected file is not a DLL.");
        return inspection;
    }

    if (fileInfo.size() <= 0)
    {
        inspection.errorMessage = QStringLiteral("The selected DLL is empty.");
        return inspection;
    }

    QFile file(inspection.path);

    if (!file.open(QIODevice::ReadOnly))
    {
        inspection.errorMessage = QStringLiteral("Could not open DLL for inspection: %1").arg(file.errorString());
        return inspection;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);

    while (!file.atEnd())
    {
        const QByteArray block = file.read(1024 * 1024);

        if (block.isEmpty() && file.error() != QFileDevice::NoError)
        {
            inspection.errorMessage = QStringLiteral("Could not read DLL for hashing: %1").arg(file.errorString());
            return inspection;
        }

        hash.addData(block);
    }

    inspection.sha256 = QString::fromLatin1(hash.result().toHex());
    inspection.size = static_cast<quint64>(fileInfo.size());

    if (!file.seek(0))
    {
        inspection.errorMessage = QStringLiteral("Could not rewind DLL for PE inspection.");
        return inspection;
    }

    const QByteArray header = file.read(qMin<qint64>(fileInfo.size(), 1024 * 1024));
    const PeInspection peInspection = inspectPeHeader(header);
    inspection.machine = peInspection.machine;

    if (inspection.machine == MachineKind::Unknown)
    {
        inspection.errorMessage = QStringLiteral("The DLL does not have a recognizable PE machine type.");
        return inspection;
    }

    if (!peInspection.dllImage)
    {
        inspection.errorMessage = QStringLiteral("The selected PE image is not marked as a DLL.");
        return inspection;
    }

    inspection.valid = true;
    return inspection;
}

InjectionResult InjectorEngine::validate(const InjectionRequest& request)
{
    QStringList details;

    if (request.processId == 0)
    {
        return failure(QStringLiteral("No process selected"), QStringLiteral("Select a target process before continuing."));
    }

    if (request.processId == GetCurrentProcessId())
    {
        return failure(QStringLiteral("Invalid target"), QStringLiteral("The injector cannot target itself."));
    }

    const ProcessRecord process = ProcessScanner::queryProcess(request.processId);

    if (process.processId == 0 || process.sessionId == 0)
    {
        return failure(QStringLiteral("Invalid target"), QStringLiteral("The selected process is not a user-session process."));
    }

    if (!process.canQuery)
    {
        return failure(QStringLiteral("Target blocked"), QStringLiteral("The selected process could not be opened for basic inspection."));
    }

    details << QStringLiteral("Target: %1 (PID %2)").arg(process.name, QString::number(process.processId));
    details << QStringLiteral("Target architecture: %1").arg(machineKindName(process.architecture));
    details << QStringLiteral("Target session: %1").arg(process.sessionId);

    if (process.ownedByCurrentUser)
    {
        details << QStringLiteral("Target owner: %1").arg(ProcessScanner::currentUserName());
    }
    else
    {
        details << QStringLiteral("Target owner: not current user");
    }

    details << QStringLiteral("Target path: %1").arg(process.path.isEmpty() ? QStringLiteral("Unavailable") : process.path);

    const DllInspection dll = inspectDll(request.dllPath);

    if (!dll.valid)
    {
        return failure(QStringLiteral("DLL check failed"), dll.errorMessage, details);
    }

    details << QStringLiteral("DLL: %1").arg(dll.fileName);
    details << QStringLiteral("DLL path: %1").arg(dll.path);
    details << QStringLiteral("DLL size: %1").arg(formatBytes(dll.size));
    details << QStringLiteral("DLL architecture: %1").arg(machineKindName(dll.machine));
    details << QStringLiteral("DLL SHA-256: %1").arg(dll.sha256);

    const MachineKind injectorArchitecture = ProcessScanner::currentProcessArchitecture();

    if (process.architecture == MachineKind::Unknown)
    {
        return failure(QStringLiteral("Architecture check failed"), QStringLiteral("The target architecture could not be determined."), details);
    }

    if (process.architecture != injectorArchitecture)
    {
        return failure(QStringLiteral("Architecture mismatch"), QStringLiteral("This build can only load DLLs into same-architecture targets."), details);
    }

    if (dll.machine != process.architecture)
    {
        return failure(QStringLiteral("DLL mismatch"), QStringLiteral("The DLL architecture does not match the target process architecture."), details);
    }

    UniqueHandle processHandle(OpenProcess(InjectionAccess, FALSE, request.processId));

    if (!processHandle)
    {
        return failure(QStringLiteral("Access denied"), QStringLiteral("The target process could not be opened with the required access rights: %1").arg(ProcessScanner::windowsErrorMessage(GetLastError())), details);
    }

    DWORD targetExitCode = 0;

    if (GetExitCodeProcess(processHandle.get(), &targetExitCode) == FALSE)
    {
        return failure(QStringLiteral("Target state unavailable"), QStringLiteral("Could not verify that the target process is still running: %1").arg(ProcessScanner::windowsErrorMessage(GetLastError())), details);
    }

    if (targetExitCode != STILL_ACTIVE)
    {
        return failure(QStringLiteral("Target exited"), QStringLiteral("The selected process is no longer running."), details);
    }

    details << QStringLiteral("Required access: available");
    return success(QStringLiteral("Validation passed"), QStringLiteral("The selected DLL and process passed the safety checks."), details);
}

InjectionResult InjectorEngine::inject(const InjectionRequest& request)
{
    InjectionResult validation = validate(request);

    if (!validation.success)
    {
        return validation;
    }

    const std::wstring dllPath = QFileInfo(request.dllPath).absoluteFilePath().toStdWString();
    const SIZE_T remotePathSize = (dllPath.size() + 1) * sizeof(wchar_t);

    UniqueHandle processHandle(OpenProcess(InjectionAccess, FALSE, request.processId));

    if (!processHandle)
    {
        return failure(QStringLiteral("OpenProcess failed"), ProcessScanner::windowsErrorMessage(GetLastError()), validation.details);
    }

    RemoteAllocation remotePath(processHandle.get(), remotePathSize);

    if (!remotePath)
    {
        return failure(QStringLiteral("VirtualAllocEx failed"), ProcessScanner::windowsErrorMessage(GetLastError()), validation.details);
    }

    validation.details << QStringLiteral("Remote path bytes: %1").arg(remotePathSize);

    SIZE_T bytesWritten = 0;
    const bool memoryWritten = WriteProcessMemory(processHandle.get(), remotePath.get(), dllPath.c_str(), remotePathSize, &bytesWritten) != FALSE;

    if (!memoryWritten || bytesWritten != remotePathSize)
    {
        const DWORD errorCode = GetLastError();

        if (!memoryWritten)
        {
            return failure(QStringLiteral("WriteProcessMemory failed"), ProcessScanner::windowsErrorMessage(errorCode), validation.details);
        }

        return failure(QStringLiteral("WriteProcessMemory incomplete"), QStringLiteral("Only wrote %1 of %2 bytes.").arg(bytesWritten).arg(remotePathSize), validation.details);
    }

    QString loadLibraryError;
    LPTHREAD_START_ROUTINE loadLibraryAddress = resolveRemoteLoadLibraryW(request.processId, validation.details, &loadLibraryError);

    if (loadLibraryAddress == nullptr)
    {
        return failure(QStringLiteral("LoadLibraryW lookup failed"), loadLibraryError, validation.details);
    }

    DWORD remoteThreadId = 0;
    UniqueHandle remoteThread(CreateRemoteThread(processHandle.get(), nullptr, 0, loadLibraryAddress, remotePath.get(), 0, &remoteThreadId));

    if (!remoteThread)
    {
        const DWORD errorCode = GetLastError();
        return failure(QStringLiteral("CreateRemoteThread failed"), ProcessScanner::windowsErrorMessage(errorCode), validation.details);
    }

    validation.details << QStringLiteral("Remote thread ID: %1").arg(remoteThreadId);

    const DWORD waitResult = WaitForSingleObject(remoteThread.get(), 10000);

    if (waitResult == WAIT_TIMEOUT)
    {
        validation.details << QStringLiteral("Remote path cleanup: skipped because the loader thread is still running");
        remotePath.release();
        return failure(QStringLiteral("Remote thread timed out"), QStringLiteral("The remote loader thread did not finish within 10 seconds."), validation.details);
    }

    if (waitResult == WAIT_FAILED)
    {
        return failure(QStringLiteral("Remote thread wait failed"), ProcessScanner::windowsErrorMessage(GetLastError()), validation.details);
    }

    DWORD remoteExitCode = 0;

    if (GetExitCodeThread(remoteThread.get(), &remoteExitCode) == FALSE)
    {
        const DWORD errorCode = GetLastError();
        return failure(QStringLiteral("Thread result unavailable"), ProcessScanner::windowsErrorMessage(errorCode), validation.details);
    }

    DWORD cleanupError = ERROR_SUCCESS;

    if (remotePath.free(&cleanupError))
    {
        validation.details << QStringLiteral("Remote path cleanup: released");
    }
    else
    {
        validation.details << QStringLiteral("Remote path cleanup failed: %1").arg(ProcessScanner::windowsErrorMessage(cleanupError));
    }

    if (remoteExitCode == 0)
    {
        return failure(QStringLiteral("LoadLibraryW failed"), QStringLiteral("The target process returned a null module handle."), validation.details);
    }

    validation.title = QStringLiteral("Injection complete");
    validation.message = QStringLiteral("The DLL was loaded by the target process.");
    validation.details << QStringLiteral("Remote loader exit code: 0x%1").arg(QString::number(remoteExitCode, 16).toUpper());
    return validation;
}
