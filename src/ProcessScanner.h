#pragma once

#include "WinHandle.h"

#include <QtCore/QHash>
#include <QtCore/QString>
#include <QtCore/QVector>

enum class MachineKind
{
    Unknown,
    X86,
    X64,
    Arm64
};

enum class ProcessScope
{
    Applications,
    Processes,
    Windows
};

struct ProcessRecord
{
    DWORD processId = 0;
    DWORD sessionId = 0;
    QString name;
    QString path;
    QString windowTitle;
    MachineKind architecture = MachineKind::Unknown;
    bool ownedByCurrentUser = false;
    bool canQuery = false;
};

QString machineKindName(MachineKind machineKind);

class ProcessScanner final
{
public:
    static QVector<ProcessRecord> scan(ProcessScope scope);
    static ProcessRecord queryProcess(DWORD processId, const QString& windowTitle = QString());
    static MachineKind currentProcessArchitecture();
    static QString currentUserName();
    static QString windowsErrorMessage(DWORD errorCode);

private:
    static QHash<DWORD, QString> processNames();
};
