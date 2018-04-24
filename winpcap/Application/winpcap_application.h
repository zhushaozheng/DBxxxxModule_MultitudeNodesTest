#ifndef WINPCAP_APPLICATION_H
#define WINPCAP_APPLICATION_H

#include <pcap.h>
#include <ntddndis.h>
#include <packet32.h>

#include "Qt_common_api.h"
#include "mme_define.h"

class winpcap_application
{
public:
	winpcap_application();
	~winpcap_application();
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
		BOOL m_bValid;
	};
	
	pcap_if_t* m_pAllNIC;
	pcap_t* m_pHandler;
	char m_errbuf[PCAP_ERRBUF_SIZE];

public:
	BOOL FindAllNicDevs();
	
	CNICDevice m_NICDevice[CNICDevice::eMaxNicDev];
	int	m_CurNIC;
	int	m_NICnum;
};

#endif // WINPCAP_APPLICATION_H
