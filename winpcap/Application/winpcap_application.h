#ifndef WINPCAP_APPLICATION_H
#define WINPCAP_APPLICATION_H

#include <pcap.h>
#include <ntddndis.h>
#include <packet32.h>

#include "Qt_common_api.h"
#include "mme_define.h"
#include <QThread>
#include <QMutex>

class winpcap_application : public QThread
{
public:
	winpcap_application();
	~winpcap_application();
	virtual void run();
private:	
	class CNICDevice
	{
	public:
		enum { eMaxNicDev = 32 };
	public:
		CNICDevice(void) {};
		~CNICDevice(void) {};

	public:
		char m_Name[MAX_PATH];
		char m_Description[64];
		CCMACAddress m_NICMac;
		bool m_bValid;
	};	
public:
	enum {eChannelTimeout = 1000};
	enum {eMaxReceiveBufSz = 1000};
	enum {eMinEthSz = 64};
	enum {eMaxPibFileSz = 20*eKilobyte};
	enum {ePibOffset_MacAddr = 0x3CC};
	enum {ePibOffset_DAKAddr = 0x3CC+6};
	enum {ePibOffset_NMKAddr = 0x424};
	enum {efirmwareWriteSize = 1024};
	enum {ePibOffset_DB6000_SizeH = 5, ePibOffset_DB6000_SizeL = 4,};
	enum {ePibOffset_DB6000_MacAddr = 0xC};
	enum {ePibOffset_DB6000_NMKAddr = 0x64};
	enum {ePibOffset_DB6000_CheckSum = 0x8};
public:
	pcap_if_t* m_pAllNIC;
	pcap_t* m_pHandler;
	char m_errbuf[PCAP_ERRBUF_SIZE];
public:
	void InitAllBuff();
	bool FindAllNicDevs();
	bool OpenChannel(uint16 *apMMEFilter, uint8 aMMEFilterLen);
	void CloseChannel();
	bool IfChannelOpen();
	void SaveToRecvBuffer(const u_char * apData, int aLen);
	void DispatchPacket(CCMMEFrame aMMEFrame);
	void DispatchAllPacketsInBuffer(void);
	
	CNICDevice m_NICDevice[CNICDevice::eMaxNicDev];
	int	m_CurNIC;
	int	m_NICnum;
	//-****The Send MME Frame****-//
	CCMMEFrame m_SendMME;
	int m_SendSize;
	//-****The receive and dispatch buffers****-//
	CCMMEFrame	m_RecvBuffer[eMaxReceiveBufSz];
	CCMMEFrame	m_DispatchBuffer[eMaxReceiveBufSz];
	unsigned int m_LastRecvBufferPos;
	unsigned int m_LastDispatchBufferPos;
	//-****Receive MME Filter****-//
	uint16	m_MMEFilter[32];
	uint8	m_MMEFilterLen;
	
	QMutex m_winpcap_mutex;
};

#endif // WINPCAP_APPLICATION_H
