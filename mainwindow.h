#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

public:
	void Draw_comboBox_NIC(void );
	int Dropbeats_NICInit();
	void Dropbeats_InitErrorHandle(int aStatus);
public:
	enum {
		eStatus_Success = 0,
		eStatus_MAC_InvaldLength = 1,
		eStatus_MAC_InvaldChar = 2,
		eStatus_MAC_InvaldMAC = 3,
		eStatus_COM_NotFound = 4,
		eStatus_COM_AccessDenied = 5,
		eStatus_NIC_Failed = 6,
		eStatus_DeviceIdentify_InvaldLength = 7,
		eStatus_DeviceIdentify_InvaldChar = 8,
	};
private slots:
    void on_comboBox_NIC_currentIndexChanged(int index);
};

#endif // MAINWINDOW_H
