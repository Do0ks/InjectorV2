#include "MainWindow.h"

#include "../res/resource.h"
#include "InjectorEngine.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QEvent>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QSize>
#include <QtCore/QStringList>
#include <QtGui/QClipboard>
#include <QtGui/QColor>
#include <QtGui/QContextMenuEvent>
#include <QtGui/QFont>
#include <QtGui/QFontDatabase>
#include <QtGui/QIcon>
#include <QtGui/QPainter>
#include <QtGui/QPixmap>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QFileIconProvider>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMenu>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStyle>
#include <QtWidgets/QStyleOption>
#include <QtWidgets/QStylePainter>
#include <QtWidgets/QTabBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>

namespace
{
constexpr int LogMessageRole = Qt::UserRole + 1;
constexpr int InjectionDetailIndent = 12;

QString processText(const ProcessRecord& process, ProcessScope scope)
{
    const QString preferredName = scope == ProcessScope::Processes
        ? process.name
        : process.windowTitle;
    const QString displayName = preferredName.trimmed().isEmpty()
        ? process.name
        : preferredName;

    return QStringLiteral("%1 (PID: %2)").arg(displayName, QString::number(process.processId));
}

QString formatLogBytes(quint64 bytes)
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

bool isRedundantInjectionDetail(const QString& detail)
{
    const QStringList redundantPrefixes = {
        QStringLiteral("Target:"),
        QStringLiteral("Target architecture:"),
        QStringLiteral("Target session:"),
        QStringLiteral("Target owner:"),
        QStringLiteral("Target path:"),
        QStringLiteral("DLL:"),
        QStringLiteral("DLL path:"),
        QStringLiteral("DLL size:"),
        QStringLiteral("DLL architecture:"),
        QStringLiteral("DLL SHA-256:")
    };

    for (const QString& prefix : redundantPrefixes)
    {
        if (detail.startsWith(prefix, Qt::CaseInsensitive))
        {
            return true;
        }
    }

    return false;
}

QString formatLogTitleWord(const QString& word)
{
    static const QStringList preservedWords = {
        QStringLiteral("DLL"),
        QStringLiteral("PID"),
        QStringLiteral("ID"),
        QStringLiteral("SHA-256"),
        QStringLiteral("LoadLibraryW")
    };

    for (const QString& preservedWord : preservedWords)
    {
        if (word.compare(preservedWord, Qt::CaseInsensitive) == 0)
        {
            return preservedWord;
        }
    }

    QString formattedWord = word.toLower();

    if (!formattedWord.isEmpty())
    {
        formattedWord[0] = formattedWord[0].toUpper();
    }

    return formattedWord;
}

QString formatLogTitle(const QString& title)
{
    QStringList formattedWords;

    for (const QString& word : title.split(QLatin1Char(' '), Qt::SkipEmptyParts))
    {
        formattedWords << formatLogTitleWord(word);
    }

    return formattedWords.join(QLatin1Char(' '));
}

struct LogMessageParts
{
    QString title;
    QString value;
    bool statusTitle = false;
};

LogMessageParts splitLogMessage(const QString& message)
{
    LogMessageParts parts{};
    QString trimmedMessage = message.trimmed();
    const int colonIndex = trimmedMessage.indexOf(QLatin1Char(':'));

    if (colonIndex >= 0)
    {
        parts.title = formatLogTitle(trimmedMessage.left(colonIndex).trimmed());
        parts.value = trimmedMessage.mid(colonIndex + 1).trimmed();
        return parts;
    }

    if (trimmedMessage.endsWith(QLatin1Char('.')))
    {
        trimmedMessage.chop(1);
    }

    parts.title = formatLogTitle(trimmedMessage);
    parts.statusTitle = parts.title == QStringLiteral("Injection Successful") || parts.title == QStringLiteral("Injection Failed");
    return parts;
}

QString copyTextForLogMessage(const LogMessageParts& parts)
{
    if (parts.statusTitle)
    {
        return parts.title + QStringLiteral("!!");
    }

    if (parts.value.isEmpty())
    {
        return parts.title + QLatin1Char(':');
    }

    return parts.title + QStringLiteral(": ") + parts.value;
}

QString fontAwesomeFamily()
{
    static bool loaded = false;
    static QString fontFamily;

    if (loaded)
    {
        return fontFamily;
    }

    loaded = true;

    const QDir applicationDirectory(QCoreApplication::applicationDirPath());
    const QStringList candidatePaths = {
        applicationDirectory.filePath(QStringLiteral("fa-solid-900.ttf")),
        applicationDirectory.filePath(QStringLiteral("../../Release/Build/fa-solid-900.ttf"))
    };

    for (const QString& candidatePath : candidatePaths)
    {
        if (!QFileInfo::exists(candidatePath))
        {
            continue;
        }

        const int fontId = QFontDatabase::addApplicationFont(candidatePath);

        if (fontId < 0)
        {
            continue;
        }

        const QStringList families = QFontDatabase::applicationFontFamilies(fontId);

        if (!families.isEmpty())
        {
            fontFamily = families.first();
            break;
        }
    }

    return fontFamily;
}

QPixmap fontAwesomePixmap(uint codepoint, const QColor& color, const QSize& size)
{
    QPixmap pixmap(size);
    pixmap.fill(Qt::transparent);

    const QString family = fontAwesomeFamily();

    if (family.isEmpty())
    {
        return pixmap;
    }

    QFont iconFont(family);
    iconFont.setPixelSize(static_cast<int>(size.height() * 0.82));
    iconFont.setWeight(QFont::Black);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::TextAntialiasing);
    painter.setPen(color);
    painter.setFont(iconFont);
    painter.drawText(pixmap.rect(), Qt::AlignCenter, QString(QChar(static_cast<char16_t>(codepoint))));

    return pixmap;
}

QIcon fontAwesomeIcon(
    uint codepoint,
    QColor normalColor = QColor(QStringLiteral("#e0e0e0")),
    QColor disabledColor = QColor(QStringLiteral("#655b55")),
    QColor selectedColor = QColor(QStringLiteral("#0e0e0e")))
{
    if (fontAwesomeFamily().isEmpty())
    {
        return {};
    }

    const QSize iconSize(64, 64);
    QIcon icon;
    icon.addPixmap(fontAwesomePixmap(codepoint, normalColor, iconSize), QIcon::Normal, QIcon::Off);
    icon.addPixmap(fontAwesomePixmap(codepoint, normalColor.lighter(118), iconSize), QIcon::Active, QIcon::Off);
    icon.addPixmap(fontAwesomePixmap(codepoint, disabledColor, iconSize), QIcon::Disabled, QIcon::Off);
    icon.addPixmap(fontAwesomePixmap(codepoint, selectedColor, iconSize), QIcon::Selected, QIcon::Off);
    icon.addPixmap(fontAwesomePixmap(codepoint, selectedColor, iconSize), QIcon::Normal, QIcon::On);
    icon.addPixmap(fontAwesomePixmap(codepoint, selectedColor, iconSize), QIcon::Active, QIcon::On);
    return icon;
}

void applyButtonIcon(
    QPushButton* button,
    uint codepoint,
    QColor normalColor = QColor(QStringLiteral("#d26e41")),
    QColor disabledColor = QColor(QStringLiteral("#655b55")))
{
    const QIcon icon = fontAwesomeIcon(codepoint, normalColor, disabledColor, normalColor);

    if (icon.isNull())
    {
        return;
    }

    button->setIcon(icon);
    button->setIconSize(QSize(18, 18));
}

class CenteredIconTabBar final : public QTabBar
{
public:
    explicit CenteredIconTabBar(QWidget* parent = nullptr)
        : QTabBar(parent)
    {
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QStylePainter painter(this);

        for (int index = 0; index < count(); ++index)
        {
            QStyleOptionTab option;
            initStyleOption(&option, index);

            painter.drawControl(QStyle::CE_TabBarTabShape, option);
            drawCenteredLabel(&painter, option, index);
        }
    }

private:
    QColor textColorForTab(const QStyleOptionTab& option) const
    {
        if (option.state.testFlag(QStyle::State_Selected))
        {
            return QColor(QStringLiteral("#0e0e0e"));
        }

        if (option.state.testFlag(QStyle::State_MouseOver))
        {
            return QColor(QStringLiteral("#e0e0e0"));
        }

        return QColor(QStringLiteral("#a6a5a2"));
    }

    QIcon::Mode iconModeForTab(const QStyleOptionTab& option) const
    {
        if (option.state.testFlag(QStyle::State_Selected))
        {
            return QIcon::Selected;
        }

        if (option.state.testFlag(QStyle::State_MouseOver))
        {
            return QIcon::Active;
        }

        return QIcon::Normal;
    }

    void drawCenteredLabel(QPainter* painter, const QStyleOptionTab& option, int index) const
    {
        const QRect tabRectangle = option.rect.adjusted(0, 0, 0, -1);
        const QSize iconDimensions = iconSize();
        const QString currentTabText = tabText(index);
        const int labelSpacing = 4;
        const int textWidth = painter->fontMetrics().horizontalAdvance(currentTabText);
        const int groupWidth = iconDimensions.width() + labelSpacing + textWidth;
        const int groupLeft = tabRectangle.left() + (tabRectangle.width() - groupWidth) / 2;
        const int groupTop = tabRectangle.top() + (tabRectangle.height() - iconDimensions.height()) / 2;

        const bool selected = option.state.testFlag(QStyle::State_Selected);
        const QIcon::State iconState = selected ? QIcon::On : QIcon::Off;
        const QPixmap iconPixmap = tabIcon(index).pixmap(iconDimensions, iconModeForTab(option), iconState);

        painter->drawPixmap(groupLeft, groupTop, iconPixmap);

        const QRect textRectangle(
            groupLeft + iconDimensions.width() + labelSpacing,
            tabRectangle.top(),
            textWidth,
            tabRectangle.height());

        painter->save();
        painter->setPen(textColorForTab(option));
        painter->drawText(textRectangle, Qt::AlignVCenter | Qt::AlignLeft, currentTabText);
        painter->restore();
    }
};

class ProcessTabWidget final : public QTabWidget
{
public:
    explicit ProcessTabWidget(QWidget* parent = nullptr)
        : QTabWidget(parent)
    {
        setTabBar(new CenteredIconTabBar(this));
    }
};

class LogRowWidget final : public QWidget
{
public:
    LogRowWidget(
        const LogMessageParts& parts,
        const QIcon& icon,
        const QString& copyText,
        int contentIndent,
        QWidget* parent = nullptr)
        : QWidget(parent),
          parts_(parts),
          icon_(icon),
          copyText_(copyText),
          contentIndent_(contentIndent)
    {
        setObjectName(QStringLiteral("LogRow"));
        setAttribute(Qt::WA_TranslucentBackground);
        setMouseTracking(true);
    }

protected:
    bool event(QEvent* widgetEvent) override
    {
        if (widgetEvent->type() == QEvent::Enter)
        {
            hovered_ = true;
            update();
        }
        else if (widgetEvent->type() == QEvent::Leave)
        {
            hovered_ = false;
            update();
        }

        return QWidget::event(widgetEvent);
    }

    void contextMenuEvent(QContextMenuEvent* event) override
    {
        if (copyText_.isEmpty())
        {
            return;
        }

        QMenu menu(this);
        QAction* copyAction = menu.addAction(QStringLiteral("Copy Row"));
        QAction* selectedAction = menu.exec(event->globalPos());

        if (selectedAction == copyAction)
        {
            QApplication::clipboard()->setText(copyText_);
        }

        event->accept();
    }

    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::TextAntialiasing);

        const QRect rowRectangle = rect();
        const int horizontalPadding = 6;
        const int iconSize = 18;
        const int iconSpacing = 7;

        if (hovered_)
        {
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(210, 110, 65, 42));
            painter.drawRoundedRect(rowRectangle.adjusted(1, 1, -1, -1), 4, 4);
        }

        const int iconTop = rowRectangle.top() + (rowRectangle.height() - iconSize) / 2;
        const QPixmap iconPixmap = icon_.pixmap(QSize(iconSize, iconSize));

        if (!iconPixmap.isNull())
        {
            painter.drawPixmap(horizontalPadding, iconTop, iconPixmap);
        }

        QFont titleFont = font();
        titleFont.setBold(true);

        if (parts_.statusTitle && titleFont.pointSizeF() > 0.0)
        {
            titleFont.setPointSizeF(titleFont.pointSizeF() + 1.0);
        }

        const QFont valueFont = font();
        const QFontMetrics titleMetrics(titleFont);
        const QFontMetrics valueMetrics(valueFont);
        const int textHeight = qMax(titleMetrics.height(), valueMetrics.height());
        const int baseline = rowRectangle.top() + (rowRectangle.height() - textHeight) / 2 + titleMetrics.ascent();
        const int textLeft = horizontalPadding + contentIndent_ + iconSize + iconSpacing;
        const QString titleText = parts_.title + (parts_.statusTitle ? QStringLiteral("!!") : QStringLiteral(":"));

        painter.setPen(QColor(QStringLiteral("#e0e0e0")));
        painter.setFont(titleFont);
        painter.drawText(textLeft, baseline, titleText);

        if (parts_.value.isEmpty())
        {
            return;
        }

        const int valueLeft = textLeft + titleMetrics.horizontalAdvance(titleText) + 5;
        const int valueWidth = rowRectangle.right() - valueLeft - horizontalPadding;

        if (valueWidth <= 0)
        {
            return;
        }

        painter.setFont(valueFont);
        painter.drawText(valueLeft, baseline, valueMetrics.elidedText(parts_.value, Qt::ElideRight, valueWidth));
    }

private:
    LogMessageParts parts_;
    QIcon icon_;
    QString copyText_;
    int contentIndent_ = 0;
    bool hovered_ = false;
};

QIcon fallbackFileIcon()
{
    return QApplication::style()->standardIcon(QStyle::SP_FileIcon);
}

QIcon iconForPath(const QString& path)
{
    const QString trimmedPath = path.trimmed();

    if (trimmedPath.isEmpty())
    {
        return fallbackFileIcon();
    }

    static QFileIconProvider iconProvider;
    static QHash<QString, QIcon> iconCache;

    const QString cacheKey = trimmedPath.toLower();
    const auto cachedIcon = iconCache.constFind(cacheKey);

    if (cachedIcon != iconCache.constEnd())
    {
        return cachedIcon.value();
    }

    QIcon icon = iconProvider.icon(QFileInfo(trimmedPath));

    if (icon.isNull())
    {
        icon = fallbackFileIcon();
    }

    iconCache.insert(cacheKey, icon);
    return icon;
}

QIcon iconForProcess(const ProcessRecord& process)
{
    return iconForPath(process.path);
}

QWidget* createLogDividerWidget(QWidget* parent)
{
    auto* container = new QWidget(parent);
    container->setObjectName(QStringLiteral("LogDividerContainer"));

    auto* layout = new QHBoxLayout(container);
    layout->setContentsMargins(6, 5, 6, 5);
    layout->setSpacing(0);

    auto* line = new QFrame(container);
    line->setObjectName(QStringLiteral("LogDivider"));
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Plain);
    line->setFixedHeight(1);

    layout->addWidget(line);
    return container;
}

QIcon logDetailSpacerIcon()
{
    static QIcon icon;

    if (icon.isNull())
    {
        QPixmap pixmap(QSize(18, 18));
        pixmap.fill(Qt::transparent);
        icon.addPixmap(pixmap);
    }

    return icon;
}

void applyNativeWindowIcon(QWidget* window)
{
    const HINSTANCE moduleHandle = GetModuleHandleW(nullptr);
    const HWND windowHandle = reinterpret_cast<HWND>(window->winId());

    const auto largeIcon = reinterpret_cast<HICON>(LoadImageW(
        moduleHandle,
        MAKEINTRESOURCEW(IDI_INJECT_ICON),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON),
        LR_DEFAULTCOLOR | LR_SHARED));

    const auto smallIcon = reinterpret_cast<HICON>(LoadImageW(
        moduleHandle,
        MAKEINTRESOURCEW(IDI_INJECT_ICON),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR | LR_SHARED));

    if (largeIcon != nullptr)
    {
        SendMessageW(windowHandle, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(largeIcon));
    }

    if (smallIcon != nullptr)
    {
        SendMessageW(windowHandle, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
    }
}

class ProcessDialog final : public QDialog
{
public:
    explicit ProcessDialog(QWidget* parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle(QStringLiteral("Select Process"));
        setModal(true);
        setFixedSize(520, 560);
        setObjectName(QStringLiteral("ProcessDialog"));

        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(16, 14, 16, 16);
        layout->setSpacing(12);

        auto* headerLayout = new QVBoxLayout();
        headerLayout->setSpacing(3);

        auto* titleLabel = new QLabel(QStringLiteral("Select Process"), this);
        titleLabel->setObjectName(QStringLiteral("DialogTitle"));

        auto* subtitleLabel = new QLabel(QStringLiteral("Double-click a row to select the target process"), this);
        subtitleLabel->setObjectName(QStringLiteral("DialogSubtitle"));

        headerLayout->addWidget(titleLabel);
        headerLayout->addWidget(subtitleLabel);

        auto* toolbarLayout = new QHBoxLayout();
        toolbarLayout->setSpacing(8);

        searchEdit_ = new QLineEdit(this);
        searchEdit_->setObjectName(QStringLiteral("SearchBox"));
        searchEdit_->setPlaceholderText(QStringLiteral("Search by name, PID, title, or path"));
        searchEdit_->setClearButtonEnabled(true);

        const QColor accentColor(QStringLiteral("#d26e41"));
        const QColor disabledIconColor(QStringLiteral("#655b55"));
        const QColor selectedIconColor(QStringLiteral("#0e0e0e"));
        const QIcon searchIcon = fontAwesomeIcon(0xf002, accentColor, disabledIconColor, accentColor);

        if (!searchIcon.isNull())
        {
            searchEdit_->addAction(searchIcon, QLineEdit::LeadingPosition);
        }

        auto* refreshButton = new QPushButton(QStringLiteral("Refresh"), this);
        refreshButton->setObjectName(QStringLiteral("SecondaryButton"));
        refreshButton->setFixedWidth(86);
        applyButtonIcon(refreshButton, 0xf2f1);

        toolbarLayout->addWidget(searchEdit_, 1);
        toolbarLayout->addWidget(refreshButton);

        tabs_ = new ProcessTabWidget(this);
        tabs_->setElideMode(Qt::ElideNone);
        tabs_->tabBar()->setExpanding(false);
        tabs_->tabBar()->setUsesScrollButtons(false);

        applicationsList_ = createList();
        processesList_ = createList();
        windowsList_ = createList();

        tabs_->setIconSize(QSize(18, 18));
        tabs_->addTab(
            applicationsList_,
            fontAwesomeIcon(0xf2d0, accentColor, disabledIconColor, selectedIconColor),
            QStringLiteral("Applications"));
        tabs_->addTab(
            processesList_,
            fontAwesomeIcon(0xf2db, accentColor, disabledIconColor, selectedIconColor),
            QStringLiteral("Processes"));
        tabs_->addTab(
            windowsList_,
            fontAwesomeIcon(0xf2d2, accentColor, disabledIconColor, selectedIconColor),
            QStringLiteral("Windows"));

        layout->addLayout(headerLayout);
        layout->addLayout(toolbarLayout);
        layout->addWidget(tabs_);
        populateList(applicationsList_, ProcessScope::Applications);

        connect(searchEdit_, &QLineEdit::textChanged, this, [this] {
            filterCurrentList();
        });

        connect(refreshButton, &QPushButton::clicked, this, [this] {
            populateCurrentList();
        });

        connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) {
            if (index == 0 && applicationsList_->count() == 0)
            {
                populateList(applicationsList_, ProcessScope::Applications);
            }
            else if (index == 1 && processesList_->count() == 0)
            {
                populateList(processesList_, ProcessScope::Processes);
            }
            else if (index == 2 && windowsList_->count() == 0)
            {
                populateList(windowsList_, ProcessScope::Windows);
            }

            filterCurrentList();
        });

        applyNativeWindowIcon(this);
    }

    DWORD selectedProcessId() const
    {
        return selectedProcessId_;
    }

    QString selectedProcessText() const
    {
        return selectedProcessText_;
    }

    QIcon selectedProcessIcon() const
    {
        return selectedProcessIcon_;
    }

private:
    QListWidget* createList()
    {
        auto* list = new QListWidget(this);
        list->setSelectionMode(QAbstractItemView::SingleSelection);
        list->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        list->setTextElideMode(Qt::ElideRight);
        list->setIconSize(QSize(18, 18));

        connect(list, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem* item) {
            selectItem(item);
        });

        connect(list, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) {
            selectItem(item);
        });

        return list;
    }

    void populateList(QListWidget* list, ProcessScope scope)
    {
        list->clear();
        const QVector<ProcessRecord> processes = ProcessScanner::scan(scope);

        for (const ProcessRecord& process : processes)
        {
            auto* item = new QListWidgetItem(iconForProcess(process), processText(process, scope), list);
            item->setData(Qt::UserRole, static_cast<quint32>(process.processId));
            item->setToolTip(process.path.isEmpty() ? item->text() : process.path);
        }

        if (list->count() > 0)
        {
            list->setCurrentRow(0);
        }

        filterCurrentList();
    }

    void populateCurrentList()
    {
        switch (tabs_->currentIndex())
        {
        case 0:
            populateList(applicationsList_, ProcessScope::Applications);
            break;
        case 1:
            populateList(processesList_, ProcessScope::Processes);
            break;
        default:
            populateList(windowsList_, ProcessScope::Windows);
            break;
        }
    }

    void filterCurrentList()
    {
        QListWidget* list = currentList();

        if (list == nullptr || searchEdit_ == nullptr)
        {
            return;
        }

        const QString needle = searchEdit_->text().trimmed().toLower();

        for (int index = 0; index < list->count(); ++index)
        {
            QListWidgetItem* item = list->item(index);
            const QString searchableText = item->text().toLower() + QLatin1Char(' ') + item->toolTip().toLower();
            item->setHidden(!needle.isEmpty() && !searchableText.contains(needle));
        }
    }

    QListWidget* currentList() const
    {
        switch (tabs_->currentIndex())
        {
        case 0:
            return applicationsList_;
        case 1:
            return processesList_;
        default:
            return windowsList_;
        }
    }

    void selectItem(QListWidgetItem* item)
    {
        if (item == nullptr)
        {
            return;
        }

        selectedProcessId_ = item->data(Qt::UserRole).toUInt();
        selectedProcessText_ = item->text();
        selectedProcessIcon_ = item->icon();
        accept();
    }

    QTabWidget* tabs_ = nullptr;
    QLineEdit* searchEdit_ = nullptr;
    QListWidget* applicationsList_ = nullptr;
    QListWidget* processesList_ = nullptr;
    QListWidget* windowsList_ = nullptr;
    DWORD selectedProcessId_ = 0;
    QString selectedProcessText_;
    QIcon selectedProcessIcon_;
};
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    buildInterface();
    applyTheme();
}

void MainWindow::buildInterface()
{
    setWindowTitle(QStringLiteral("DLL Injector"));
    setFixedSize(500, 390);

    auto* centralWidget = new QWidget(this);
    auto* layout = new QVBoxLayout(centralWidget);
    layout->setContentsMargins(16, 14, 16, 16);
    layout->setSpacing(12);

    auto* headerLayout = new QVBoxLayout();
    headerLayout->setSpacing(2);

    auto* titleLabel = new QLabel(QStringLiteral("DLL Injector"), centralWidget);
    titleLabel->setObjectName(QStringLiteral("WindowTitle"));

    auto* subtitleLabel = new QLabel(QStringLiteral("Select a target process and DLL"), centralWidget);
    subtitleLabel->setObjectName(QStringLiteral("WindowSubtitle"));

    headerLayout->addWidget(titleLabel);
    headerLayout->addWidget(subtitleLabel);

    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);

    selectProcessButton_ = new QPushButton(QStringLiteral(" Select Process"), centralWidget);
    browseDllButton_ = new QPushButton(QStringLiteral(" Browse DLL"), centralWidget);
    injectDllButton_ = new QPushButton(QStringLiteral(" Inject DLL"), centralWidget);
    browseDllButton_->setObjectName(QStringLiteral("BrowseDllButton"));
    injectDllButton_->setObjectName(QStringLiteral("PrimaryButton"));

    applyButtonIcon(selectProcessButton_, 0xf140);
    applyButtonIcon(browseDllButton_, 0xf07c, QColor(QStringLiteral("#d26e41")), QColor(QStringLiteral("#a6a5a2")));
    applyButtonIcon(injectDllButton_, 0xf48e, QColor(QStringLiteral("#0e0e0e")), QColor(QStringLiteral("#a6a5a2")));

    selectProcessButton_->setFixedSize(132, 34);
    browseDllButton_->setFixedSize(132, 34);
    injectDllButton_->setFixedSize(132, 34);

    buttonLayout->addStretch(1);
    buttonLayout->addWidget(selectProcessButton_);
    buttonLayout->addWidget(browseDllButton_);
    buttonLayout->addWidget(injectDllButton_);
    buttonLayout->addStretch(1);

    logList_ = new QListWidget(centralWidget);
    logList_->setObjectName(QStringLiteral("ActivityLog"));
    logList_->setSelectionMode(QAbstractItemView::NoSelection);
    logList_->setFocusPolicy(Qt::NoFocus);
    logList_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    logList_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    logList_->setTextElideMode(Qt::ElideRight);
    logList_->setIconSize(QSize(18, 18));
    logList_->viewport()->setContextMenuPolicy(Qt::CustomContextMenu);

    layout->addLayout(headerLayout);
    layout->addLayout(buttonLayout);
    layout->addWidget(logList_, 1);

    setCentralWidget(centralWidget);
    applyNativeWindowIcon(this);

    connect(selectProcessButton_, &QPushButton::clicked, this, [this] {
        selectProcess();
    });
    connect(browseDllButton_, &QPushButton::clicked, this, [this] {
        browseForDll();
    });
    connect(injectDllButton_, &QPushButton::clicked, this, [this] {
        injectDll();
    });
    connect(logList_->viewport(), &QWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showLogContextMenu(position);
    });

    updateActionState();
}

void MainWindow::applyTheme()
{
    qApp->setStyle(QStringLiteral("Fusion"));
    qApp->setFont(QFont(QStringLiteral("Segoe UI Variable Text"), 9));
    qApp->setStyleSheet(QStringLiteral(R"(
        QWidget {
            background: #0a181e;
            color: #e0e0e0;
            font-family: "Segoe UI Variable Text", "Segoe UI";
            font-size: 9.25pt;
        }

        QPushButton {
            background: #322628;
            color: #e0e0e0;
            border: 1px solid #655b55;
            border-radius: 5px;
            padding: 5px 8px;
            font-size: 9pt;
            font-weight: 500;
        }

        QPushButton#PrimaryButton {
            background: #d26e41;
            color: #0e0e0e;
            border-color: #d26e41;
            font-weight: 700;
        }

        QPushButton#PrimaryButton:hover {
            background: #e07949;
            border-color: #e07949;
        }

        QPushButton:disabled {
            background: #11191d;
            color: #655b55;
            border-color: #243238;
        }

        QPushButton#PrimaryButton:disabled {
            background: #322628;
            color: #a6a5a2;
            border-color: #655b55;
        }

        QPushButton#BrowseDllButton:disabled {
            background: #322628;
            color: #a6a5a2;
            border-color: #655b55;
        }

        QPushButton:hover {
            background: #3b2d2f;
            border-color: #d26e41;
        }

        QPushButton:pressed {
            background: #d26e41;
            color: #0e0e0e;
        }

        QPushButton#SecondaryButton {
            padding: 7px 10px;
            min-height: 20px;
        }

        QLabel#WindowTitle {
            background: transparent;
            color: #e0e0e0;
            font-size: 17pt;
            font-weight: 700;
        }

        QLabel#WindowSubtitle {
            background: transparent;
            color: #a6a5a2;
            font-size: 9pt;
        }

        QLabel#SectionLabel {
            background: transparent;
            color: #e0e0e0;
            font-size: 10pt;
            font-weight: 700;
        }

        QDialog#ProcessDialog {
            background: #0a181e;
        }

        QLabel#DialogTitle {
            background: transparent;
            color: #e0e0e0;
            font-size: 16pt;
            font-weight: 700;
        }

        QLabel#DialogSubtitle {
            background: transparent;
            color: #a6a5a2;
            font-size: 9pt;
        }

        QLineEdit#SearchBox {
            background: #10171b;
            color: #e0e0e0;
            border: 1px solid #322628;
            border-radius: 6px;
            padding: 7px 10px;
            selection-background-color: #d26e41;
            selection-color: #0e0e0e;
            min-height: 20px;
        }

        QLineEdit#SearchBox:focus {
            border-color: #d26e41;
        }

        QPlainTextEdit, QListWidget {
            background: #0e0e0e;
            color: #e0e0e0;
            border: 1px solid #655b55;
            border-radius: 7px;
            selection-background-color: #d26e41;
            selection-color: #0e0e0e;
            font-family: "Segoe UI Variable Text", "Segoe UI";
            font-size: 9.25pt;
        }

        QListWidget {
            border-color: #322628;
            padding: 8px;
            outline: none;
        }

        QListWidget#ActivityLog {
            padding: 10px;
        }

        QListWidget::item {
            min-height: 26px;
            padding: 4px 9px;
            border-radius: 5px;
        }

        QListWidget#ActivityLog::item {
            min-height: 23px;
            padding: 2px 6px;
        }

        QWidget#LogDividerContainer {
            background: transparent;
        }

        QWidget#LogRow {
            background: transparent;
        }

        QFrame#LogDivider {
            background: #d26e41;
            border: none;
            max-height: 1px;
        }

        QListWidget::item:hover {
            background: #111b20;
        }

        QListWidget#ActivityLog::item:hover {
            background: transparent;
        }

        QListWidget::item:selected {
            background: #d26e41;
            color: #0e0e0e;
        }

        QTabWidget::pane {
            border: 1px solid #322628;
            border-radius: 7px;
            background: #0e0e0e;
            top: -1px;
        }

        QTabWidget::tab-bar {
            alignment: center;
        }

        QTabBar::tab {
            background: #322628;
            color: #a6a5a2;
            border: 1px solid #322628;
            border-bottom: 1px solid #322628;
            padding: 8px 10px 7px 10px;
            margin-left: 2px;
            margin-right: 2px;
            min-width: 0;
            width: 130px;
            font-size: 9pt;
            font-weight: 500;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            border-bottom-left-radius: 0;
            border-bottom-right-radius: 0;
        }

        QTabBar::tab:selected {
            background: #d26e41;
            color: #0e0e0e;
            border-color: #d26e41;
            border-bottom-color: #d26e41;
            margin-bottom: -1px;
        }

        QTabBar::tab:hover:!selected {
            background: #3b2d2f;
            color: #e0e0e0;
        }

        QScrollBar:vertical {
            background: #0e0e0e;
            width: 11px;
        }

        QScrollBar::handle:vertical {
            background: #655b55;
            border-radius: 5px;
            min-height: 26px;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
    )"));
}

void MainWindow::selectProcess()
{
    logList_->clear();
    selectedProcessId_ = 0;
    selectedProcess_ = ProcessRecord();
    selectedProcessIcon_ = QIcon();
    selectedDllPath_.clear();
    updateActionState();

    ProcessDialog dialog(this);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    selectedProcessId_ = dialog.selectedProcessId();
    selectedProcess_ = ProcessScanner::queryProcess(selectedProcessId_);
    selectedProcessIcon_ = dialog.selectedProcessIcon();
    const QString selectedProcessDisplay = dialog.selectedProcessText().trimmed().isEmpty()
        ? QStringLiteral("PID: %1").arg(selectedProcessId_)
        : dialog.selectedProcessText();
    const QString ownerText = selectedProcess_.canQuery
        ? (selectedProcess_.ownedByCurrentUser ? ProcessScanner::currentUserName() : QStringLiteral("Not current user"))
        : QStringLiteral("Unavailable");

    appendLog(QStringLiteral("Selected process: %1").arg(selectedProcessDisplay), selectedProcessIcon_);
    appendLogDetail(QStringLiteral("PID: %1").arg(selectedProcessId_));
    appendLogDetail(QStringLiteral("Owner: %1").arg(ownerText));
    appendLogDetail(QStringLiteral("Architecture: %1").arg(machineKindName(selectedProcess_.architecture)));
    appendLogDetail(QStringLiteral("Session: %1").arg(selectedProcess_.sessionId == 0 ? QStringLiteral("Unavailable") : QString::number(selectedProcess_.sessionId)));
    appendLogDetail(QStringLiteral("Path: %1").arg(selectedProcess_.path.isEmpty() ? QStringLiteral("Unavailable") : selectedProcess_.path));
    updateActionState();
}

void MainWindow::browseForDll()
{
    const QString dllPath = QFileDialog::getOpenFileName(this, QStringLiteral("Select DLL to Inject"), QString(), QStringLiteral("DLL Files (*.dll);;All Files (*.*)"));

    if (dllPath.isEmpty())
    {
        return;
    }

    selectedDllPath_ = dllPath;
    const QIcon selectedDllIcon = iconForPath(selectedDllPath_);
    const QFileInfo dllFileInfo(selectedDllPath_);
    const DllInspection selectedDllInspection = InjectorEngine::inspectDll(selectedDllPath_);
    appendLog(selectedDllInspection.valid
        ? QStringLiteral("Selected DLL: %1 (%2)").arg(dllFileInfo.fileName(), machineKindName(selectedDllInspection.machine))
        : QStringLiteral("Selected DLL: %1").arg(selectedDllPath_),
        selectedDllIcon);

    if (selectedDllInspection.valid)
    {
        appendLogDetail(QStringLiteral("Architecture: %1").arg(machineKindName(selectedDllInspection.machine)));
        appendLogDetail(QStringLiteral("Size: %1").arg(formatLogBytes(selectedDllInspection.size)));
        appendLogDetail(QStringLiteral("Path: %1").arg(selectedDllInspection.path));
        appendLogDetail(QStringLiteral("SHA-256: %1").arg(selectedDllInspection.sha256));
    }
    else if (!selectedDllInspection.errorMessage.isEmpty())
    {
        appendLogDetail(QStringLiteral("DLL warning: %1").arg(selectedDllInspection.errorMessage));
    }

    updateActionState();
}

void MainWindow::injectDll()
{
    if (selectedProcessId_ == 0)
    {
        appendLog(QStringLiteral("Error: No target process selected."));
        return;
    }

    if (selectedDllPath_.isEmpty())
    {
        appendLog(QStringLiteral("Error: No DLL selected."));
        return;
    }

    InjectionRequest request;
    request.processId = selectedProcessId_;
    request.dllPath = selectedDllPath_;

    const InjectionResult result = InjectorEngine::inject(request);

    if (result.success)
    {
        appendLog(QStringLiteral("Injection successful."), selectedProcessIcon_);
        appendInjectionDetails(result.details);
    }
    else
    {
        appendLog(QStringLiteral("Injection failed."), selectedProcessIcon_);
        appendLogDetail(QStringLiteral("Error: %1").arg(result.message));
        appendInjectionDetails(result.details);
    }
}

void MainWindow::appendLog(const QString& message, const QIcon& icon, bool startsNewGroup, int contentIndent)
{
    if (startsNewGroup && logList_->count() > 0)
    {
        appendLogDivider();
    }

    const LogMessageParts parts = splitLogMessage(message);
    const QString copyText = copyTextForLogMessage(parts);

    auto* item = new QListWidgetItem(logList_);
    item->setData(LogMessageRole, copyText);
    item->setSizeHint(QSize(0, 24));
    item->setToolTip(copyText);
    logList_->setItemWidget(item, new LogRowWidget(parts, icon, copyText, contentIndent, logList_));
    logList_->scrollToBottom();
}

void MainWindow::appendLogDivider()
{
    auto* item = new QListWidgetItem(logList_);
    item->setFlags(Qt::NoItemFlags);
    item->setSizeHint(QSize(0, 11));
    logList_->setItemWidget(item, createLogDividerWidget(logList_));
}

void MainWindow::appendLogDetail(const QString& message, int contentIndent)
{
    appendLog(message, logDetailSpacerIcon(), false, contentIndent);
}

void MainWindow::appendLogDetails(const QStringList& details)
{
    if (details.isEmpty())
    {
        return;
    }

    appendLogDetail(QStringLiteral("Injection details:"), InjectionDetailIndent);

    for (const QString& detail : details)
    {
        appendLogDetail(detail, InjectionDetailIndent);
    }
}

void MainWindow::appendInjectionDetails(const QStringList& details)
{
    QStringList filteredDetails;

    for (const QString& detail : details)
    {
        if (!isRedundantInjectionDetail(detail))
        {
            filteredDetails << detail;
        }
    }

    appendLogDetails(filteredDetails);
}

void MainWindow::showLogContextMenu(const QPoint& position)
{
    QListWidgetItem* item = logList_->itemAt(position);

    if (item == nullptr)
    {
        return;
    }

    const QString copyText = item->data(LogMessageRole).toString();

    if (copyText.isEmpty())
    {
        return;
    }

    QMenu menu(this);
    QAction* copyAction = menu.addAction(QStringLiteral("Copy Row"));
    QAction* selectedAction = menu.exec(logList_->viewport()->mapToGlobal(position));

    if (selectedAction == copyAction)
    {
        QApplication::clipboard()->setText(copyText);
    }
}

void MainWindow::updateActionState()
{
    browseDllButton_->setEnabled(selectedProcessId_ != 0);
    injectDllButton_->setEnabled(selectedProcessId_ != 0 && !selectedDllPath_.isEmpty());
}
