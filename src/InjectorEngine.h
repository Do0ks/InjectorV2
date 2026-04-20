#pragma once

#include "ProcessScanner.h"

#include <QtCore/QString>
#include <QtCore/QStringList>

struct DllInspection
{
    QString path;
    QString fileName;
    QString sha256;
    QString errorMessage;
    quint64 size = 0;
    MachineKind machine = MachineKind::Unknown;
    bool valid = false;
};

struct InjectionRequest
{
    DWORD processId = 0;
    QString dllPath;
};

struct InjectionResult
{
    bool success = false;
    QString title;
    QString message;
    QStringList details;
};

class InjectorEngine final
{
public:
    static DllInspection inspectDll(const QString& dllPath);
    static InjectionResult validate(const InjectionRequest& request);
    static InjectionResult inject(const InjectionRequest& request);
};
