#include "mainwindow.h"
#include <QApplication>
#include "./common/Qt_common_api.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    MainWindow w;
    w.show();
	
    return a.exec();
}
