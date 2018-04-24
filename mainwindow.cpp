#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "global.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    
    Draw_comboBox_NIC();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Draw_comboBox_NIC(void )
{
	QString aa;
	
	gwinpcap_application.FindAllNicDevs();
	
	for (int i = gwinpcap_application.m_NICnum-1;i >= 0;i--)
	{
		//aa.sprintf("www.%d", i);
		//Qt_printf("%s:%d description-len=%d %d  %s\r\n", __FUNCTION__, __LINE__, strlen(gwinpcap_application.m_NICDevice[i].m_Description), i, gwinpcap_application.m_NICDevice[i].m_Description);
		aa = QString(QLatin1String(gwinpcap_application.m_NICDevice[i].m_Description));
		ui->comboBox_NIC->addItem(aa);
	}
	
	return;
}
