#include "MainWindow.h"

#include <QtWidgets/QApplication>

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);

    MainWindow mainWindow;
    mainWindow.show();

    return application.exec();
}
