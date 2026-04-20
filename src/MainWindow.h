#pragma once

#include "ProcessScanner.h"

#include <QtCore/QPoint>
#include <QtCore/QStringList>
#include <QtGui/QIcon>
#include <QtWidgets/QMainWindow>

class QListWidget;
class QPushButton;

class MainWindow final : public QMainWindow
{
public:
    explicit MainWindow(QWidget* parent = nullptr);

private:
    void buildInterface();
    void applyTheme();
    void selectProcess();
    void browseForDll();
    void injectDll();
    void appendLog(const QString& message, const QIcon& icon = QIcon(), bool startsNewGroup = true, int contentIndent = 0);
    void appendLogDivider();
    void appendLogDetail(const QString& message, int contentIndent = 0);
    void appendLogDetails(const QStringList& details);
    void appendInjectionDetails(const QStringList& details);
    void showLogContextMenu(const QPoint& position);
    void updateActionState();

    QPushButton* selectProcessButton_ = nullptr;
    QPushButton* browseDllButton_ = nullptr;
    QPushButton* injectDllButton_ = nullptr;
    QListWidget* logList_ = nullptr;

    DWORD selectedProcessId_ = 0;
    ProcessRecord selectedProcess_{};
    QIcon selectedProcessIcon_;
    QString selectedDllPath_;
};
