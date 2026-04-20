#include "ProcessScanner.h"

#include <QtCore/QByteArray>
#include <QtCore/QHash>
#include <QtCore/QSet>

#include <algorithm>
#include <tlhelp32.h>

namespace
{
struct WindowRecord
{
    DWORD processId = 0;
    QString title;
};

struct WindowScanContext
{
    QVector<WindowRecord> records;
    bool applicationsOnly = false;
};

QString wideStringToQString(const wchar_t* text)
{
    return QString::fromWCharArray(text);
}

QString queryProcessPath(HANDLE processHandle)
{
    DWORD bufferLength = 32768;
    QVector<wchar_t> pathBuffer(static_cast<int>(bufferLength));

    if (QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &bufferLength) == FALSE)
    {
        return {};
    }

    return QString::fromWCharArray(pathBuffer.data(), static_cast<int>(bufferLength));
}

UniqueHandle openToken(HANDLE handle, DWORD access)
{
    HANDLE rawToken = nullptr;

    if (OpenProcessToken(handle, access, &rawToken) == FALSE)
    {
        return {};
    }

    return UniqueHandle(rawToken);
}

QByteArray tokenInformation(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS informationClass)
{
    DWORD requiredLength = 0;
    GetTokenInformation(tokenHandle, informationClass, nullptr, 0, &requiredLength);

    if (requiredLength == 0)
    {
        return {};
    }

    QByteArray tokenBuffer(static_cast<int>(requiredLength), 0);

    if (GetTokenInformation(tokenHandle, informationClass, tokenBuffer.data(), requiredLength, &requiredLength) == FALSE)
    {
        return {};
    }

    return tokenBuffer;
}

QByteArray currentUserSid()
{
    UniqueHandle tokenHandle = openToken(GetCurrentProcess(), TOKEN_QUERY);

    if (!tokenHandle)
    {
        return {};
    }

    const QByteArray tokenBuffer = tokenInformation(tokenHandle.get(), TokenUser);

    if (tokenBuffer.isEmpty())
    {
        return {};
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
    const DWORD sidLength = GetLengthSid(tokenUser->User.Sid);
    QByteArray sidBuffer(static_cast<int>(sidLength), 0);

    if (CopySid(sidLength, sidBuffer.data(), tokenUser->User.Sid) == FALSE)
    {
        return {};
    }

    return sidBuffer;
}

bool isOwnedByCurrentUser(HANDLE processHandle)
{
    static const QByteArray ownerSid = currentUserSid();

    if (ownerSid.isEmpty())
    {
        return false;
    }

    UniqueHandle processToken = openToken(processHandle, TOKEN_QUERY);

    if (!processToken)
    {
        return false;
    }

    const QByteArray tokenBuffer = tokenInformation(processToken.get(), TokenUser);

    if (tokenBuffer.isEmpty())
    {
        return false;
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
    auto* currentUserSidPointer = reinterpret_cast<PSID>(const_cast<char*>(ownerSid.constData()));
    return EqualSid(tokenUser->User.Sid, currentUserSidPointer) != FALSE;
}

MachineKind machineKindFromPeMachine(USHORT machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        return MachineKind::X86;
    case IMAGE_FILE_MACHINE_AMD64:
        return MachineKind::X64;
    case IMAGE_FILE_MACHINE_ARM64:
        return MachineKind::Arm64;
    default:
        return MachineKind::Unknown;
    }
}

MachineKind queryProcessArchitecture(HANDLE processHandle)
{
    using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

    const HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    IsWow64Process2Function isWow64Process2 = nullptr;

    if (kernelModule != nullptr)
    {
        isWow64Process2 = reinterpret_cast<IsWow64Process2Function>(
            GetProcAddress(kernelModule, "IsWow64Process2"));
    }

    if (isWow64Process2 != nullptr)
    {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

        if (isWow64Process2(processHandle, &processMachine, &nativeMachine) != FALSE)
        {
            if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN)
            {
                return machineKindFromPeMachine(processMachine);
            }

            return machineKindFromPeMachine(nativeMachine);
        }
    }

    BOOL isWow64 = FALSE;

    if (IsWow64Process(processHandle, &isWow64) == FALSE)
    {
        return MachineKind::Unknown;
    }

    if (isWow64 != FALSE)
    {
        return MachineKind::X86;
    }

    return ProcessScanner::currentProcessArchitecture();
}

QString windowTitle(HWND windowHandle)
{
    const int titleLength = GetWindowTextLengthW(windowHandle);

    if (titleLength <= 0)
    {
        return {};
    }

    std::wstring title(static_cast<size_t>(titleLength) + 1, L'\0');
    const int copiedLength = GetWindowTextW(windowHandle, title.data(), titleLength + 1);

    if (copiedLength <= 0)
    {
        return {};
    }

    title.resize(static_cast<size_t>(copiedLength));
    return QString::fromStdWString(title).trimmed();
}

BOOL CALLBACK enumerateWindowsCallback(HWND windowHandle, LPARAM parameter)
{
    auto* context = reinterpret_cast<WindowScanContext*>(parameter);

    if (IsWindowVisible(windowHandle) == FALSE)
    {
        return TRUE;
    }

    if (context->applicationsOnly && GetWindow(windowHandle, GW_OWNER) != nullptr)
    {
        return TRUE;
    }

    QString title = windowTitle(windowHandle);

    if (title.isEmpty() || title == QStringLiteral("Program Manager"))
    {
        return TRUE;
    }

    DWORD processId = 0;
    GetWindowThreadProcessId(windowHandle, &processId);

    if (processId == 0)
    {
        return TRUE;
    }

    context->records.push_back({ processId, title });
    return TRUE;
}

QVector<WindowRecord> visibleWindows(bool applicationsOnly)
{
    WindowScanContext context{};
    context.applicationsOnly = applicationsOnly;
    EnumWindows(enumerateWindowsCallback, reinterpret_cast<LPARAM>(&context));
    return context.records;
}

QString executableNameFromPath(const QString& path)
{
    const qsizetype slashIndex = std::max(path.lastIndexOf('\\'), path.lastIndexOf('/'));

    if (slashIndex < 0)
    {
        return path;
    }

    return path.mid(slashIndex + 1);
}

ProcessRecord buildProcessRecord(DWORD processId, const QString& title, const QHash<DWORD, QString>& names)
{
    ProcessRecord record;
    record.processId = processId;
    record.windowTitle = title;
    ProcessIdToSessionId(processId, &record.sessionId);
    record.name = names.value(processId);

    UniqueHandle processHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));

    if (!processHandle)
    {
        return record;
    }

    record.canQuery = true;
    record.path = queryProcessPath(processHandle.get());
    record.architecture = queryProcessArchitecture(processHandle.get());
    record.ownedByCurrentUser = isOwnedByCurrentUser(processHandle.get());

    if (record.name.isEmpty() && !record.path.isEmpty())
    {
        record.name = executableNameFromPath(record.path);
    }

    return record;
}

void scanProcessList(QVector<ProcessRecord>& records, const QHash<DWORD, QString>& names)
{
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

    if (!snapshot)
    {
        return;
    }

    PROCESSENTRY32W processEntry{};
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot.get(), &processEntry) == FALSE)
    {
        return;
    }

    do
    {
        DWORD sessionId = 0;
        ProcessIdToSessionId(processEntry.th32ProcessID, &sessionId);

        if (sessionId == 0)
        {
            continue;
        }

        ProcessRecord record = buildProcessRecord(processEntry.th32ProcessID, QString(), names);

        if (record.name.isEmpty())
        {
            record.name = wideStringToQString(processEntry.szExeFile);
        }

        records.push_back(record);
    } while (Process32NextW(snapshot.get(), &processEntry) != FALSE);
}

void scanWindowList(
    QVector<ProcessRecord>& records,
    ProcessScope scope,
    const QHash<DWORD, QString>& names)
{
    const bool applicationsOnly = scope == ProcessScope::Applications;
    const QVector<WindowRecord> windows = visibleWindows(applicationsOnly);
    QSet<QString> seenRows;

    for (const WindowRecord& window : windows)
    {
        const QString rowKey = QString::number(window.processId) + QLatin1Char('|') + window.title;

        if (seenRows.contains(rowKey))
        {
            continue;
        }

        seenRows.insert(rowKey);
        records.push_back(buildProcessRecord(window.processId, window.title, names));
    }
}
}

QString machineKindName(MachineKind machineKind)
{
    switch (machineKind)
    {
    case MachineKind::X86:
        return QStringLiteral("x86");
    case MachineKind::X64:
        return QStringLiteral("x64");
    case MachineKind::Arm64:
        return QStringLiteral("ARM64");
    default:
        return QStringLiteral("Unknown");
    }
}

QVector<ProcessRecord> ProcessScanner::scan(ProcessScope scope)
{
    QVector<ProcessRecord> records;
    const QHash<DWORD, QString> names = processNames();

    if (scope == ProcessScope::Processes)
    {
        scanProcessList(records, names);
    }
    else
    {
        scanWindowList(records, scope, names);
    }

    std::sort(records.begin(), records.end(), [](const ProcessRecord& left, const ProcessRecord& right) {
        const QString leftName = left.name.isEmpty() ? left.windowTitle : left.name;
        const QString rightName = right.name.isEmpty() ? right.windowTitle : right.name;
        return QString::localeAwareCompare(leftName.toLower(), rightName.toLower()) < 0;
    });

    return records;
}

ProcessRecord ProcessScanner::queryProcess(DWORD processId, const QString& windowTitle)
{
    return buildProcessRecord(processId, windowTitle, processNames());
}

MachineKind ProcessScanner::currentProcessArchitecture()
{
#if defined(_M_X64) || defined(__x86_64__)
    return MachineKind::X64;
#elif defined(_M_IX86) || defined(__i386__)
    return MachineKind::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return MachineKind::Arm64;
#else
    return MachineKind::Unknown;
#endif
}

QString ProcessScanner::currentUserName()
{
    DWORD bufferLength = 256;
    QVector<wchar_t> userNameBuffer(static_cast<int>(bufferLength));

    if (GetUserNameW(userNameBuffer.data(), &bufferLength) == FALSE)
    {
        return QStringLiteral("Current user");
    }

    return QString::fromWCharArray(userNameBuffer.data()).trimmed();
}

QString ProcessScanner::windowsErrorMessage(DWORD errorCode)
{
    if (errorCode == ERROR_SUCCESS)
    {
        return QStringLiteral("No error");
    }

    wchar_t* messageBuffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        nullptr);

    if (length == 0 || messageBuffer == nullptr)
    {
        return QStringLiteral("Windows error %1").arg(errorCode);
    }

    QString message = QString::fromWCharArray(messageBuffer, static_cast<int>(length)).trimmed();
    LocalFree(messageBuffer);
    return QStringLiteral("%1 (0x%2)").arg(message, QString::number(errorCode, 16).toUpper());
}

QHash<DWORD, QString> ProcessScanner::processNames()
{
    QHash<DWORD, QString> names;
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

    if (!snapshot)
    {
        return names;
    }

    PROCESSENTRY32W processEntry{};
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot.get(), &processEntry) == FALSE)
    {
        return names;
    }

    do
    {
        names.insert(processEntry.th32ProcessID, wideStringToQString(processEntry.szExeFile));
    } while (Process32NextW(snapshot.get(), &processEntry) != FALSE);

    return names;
}
