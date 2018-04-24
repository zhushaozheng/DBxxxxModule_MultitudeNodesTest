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
	
	gwinpcap_application.m_CurNIC = ui->comboBox_NIC->currentIndex();
	
	Dropbeats_InitErrorHandle(Dropbeats_NICInit());
	
	return;
}

int MainWindow::Dropbeats_NICInit()
{
	uint16 vFilter[12] = {VS_SW_VER::eMMTypeCnf, VS_MODULE_OPERATION::eMMTypeCnf, VS_RS_DEV::eMMTypeCnf
					, VS_NW_INFO_STATS::eMMTypeCnf, VS_ACCESS_LEVEL_CONTROL::eMMTypeCnf
					, VS_WR_MOD::eMMTypeCnf, VS_RD_MOD::eMMTypeCnf, VS_MOD_NVM::eMMTypeCnf
					, VS_PRODUCT_TEST_MODE::eMMTypeCnf, VS_FAC_DEFAULTS::eMMTypeCnf
					, VS_Transparent::eMMTypeReq, VS_Transparent::eMMTypeCnf};
	
	if (!gwinpcap_application.OpenChannel(vFilter, 12)) {
		return eStatus_NIC_Failed;
	}

	gwinpcap_application.DispatchAllPacketsInBuffer();

	return eStatus_Success;
}

void MainWindow::Dropbeats_InitErrorHandle(int aStatus)
{
	/*Error Handle:*/
	switch (aStatus)
	{
		case eStatus_MAC_InvaldLength:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("扫描得到的MAC地址长度不为12!"));
			Qt_printf("扫描得到的MAC地址长度不为12!");
			
			break;
		case eStatus_MAC_InvaldChar:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("扫描得到的MAC地址中包含非法字符!"));
			Qt_printf("扫描得到的MAC地址中包含非法字符!");
			
			break;
		case eStatus_MAC_InvaldMAC:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("扫描得到的MAC地址为非法MAC地址!"));
			Qt_printf("扫描得到的MAC地址为非法MAC地址!");
			
			break;
		case eStatus_COM_NotFound:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("串口打开失败:无效!"));
			Qt_printf("串口打开失败:无效!");
			
			break;
		case eStatus_COM_AccessDenied:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("串口打开失败:被占用!"));
			Qt_printf("串口打开失败:被占用!");
			
			break;
		case eStatus_NIC_Failed:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("网卡打开失败"));
			//gWpcapInterface.closeChannel();
			Qt_printf("网卡打开失败");
			
			break;
		case eStatus_DeviceIdentify_InvaldLength:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("合法的DeviceIdentify长度:8-64char"));
			//gWpcapInterface.closeChannel();
			Qt_printf("合法的DeviceIdentify长度:8-64char");
			
			break;
		case eStatus_DeviceIdentify_InvaldChar:
			//Dropbeats_CloseTest();
			//AfxMessageBox(_T("DeviceIdentify包含非法字符"));
			//gWpcapInterface.closeChannel();
			Qt_printf("DeviceIdentify包含非法字符");
			
			break;
		default:
			
			break;
	}

	return;
}

void MainWindow::on_comboBox_NIC_currentIndexChanged(int index)
{
	if (gwinpcap_application.m_CurNIC != index)
	{
		if (gwinpcap_application.IfChannelOpen())
		{
			gwinpcap_application.CloseChannel();
		}
		
		gwinpcap_application.m_CurNIC = index;
		
		//Qt_printf("%s:%d index=%d(%d) %s %s", __FUNCTION__, __LINE__, index, gwinpcap_application.m_NICDevice[gwinpcap_application.m_CurNIC].m_Name, gwinpcap_application.m_NICDevice[gwinpcap_application.m_CurNIC].m_Description);
		
		Dropbeats_InitErrorHandle(Dropbeats_NICInit());
	}
}
