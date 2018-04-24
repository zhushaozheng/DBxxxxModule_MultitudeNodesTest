#include "winpcap_application.h"
#include "Qt_common_api.h"

winpcap_application::winpcap_application()
{
	m_pAllNIC = NULL;
	m_pHandler = NULL;
	m_NICnum = 0;
	m_CurNIC = 0;
}

winpcap_application::~winpcap_application()
{
	pcap_freealldevs(m_pAllNIC);
}

BOOL winpcap_application::FindAllNicDevs()
{
	if (pcap_findalldevs(&m_pAllNIC, m_errbuf) == -1)
	{
		return false;
	}
	
	pcap_if_t *vCurNIC;
	LPADAPTER vlpAdapter = 0;
	PPACKET_OID_DATA vpOidData;
	BOOLEAN vStatus;
	
	vpOidData = (PPACKET_OID_DATA )malloc(6 + sizeof(PACKET_OID_DATA));
	if (vpOidData == NULL)
	{
		return false;
	}
	
	m_NICnum=0;
	
	for (vCurNIC = m_pAllNIC; vCurNIC; vCurNIC = vCurNIC->next)
	{
		memcpy(m_NICDevice[m_NICnum].m_Name, vCurNIC->name, strlen(vCurNIC->name));
		
		if (vCurNIC->description)
		{
			//Qt_printf("%s:%d description-len=%d %d  %s\r\n", __FUNCTION__, __LINE__, strlen(vCurNIC->description), m_NICnum, vCurNIC->description);
			memcpy(m_NICDevice[m_NICnum].m_Description, vCurNIC->description, strlen(vCurNIC->description));
		}
		else
		{
			char vDescription[] = "NO DESCRIPTION";
			memcpy(m_NICDevice[m_NICnum].m_Description, vDescription, strlen(vDescription));
		}
		m_NICDevice[m_NICnum].m_bValid = true;
		
		vlpAdapter = PacketOpenAdapter(vCurNIC->name);
		if (!vlpAdapter || (vlpAdapter->hFile == INVALID_HANDLE_VALUE))
		{
			return false;
		}
		else
		{
			//-****Retrieve the adapter MAC querying the NIC driver****-//
			vpOidData->Oid = OID_802_3_CURRENT_ADDRESS;
			vpOidData->Length = 6;
			ZeroMemory(vpOidData->Data, 6);
			
			vStatus = PacketRequest(vlpAdapter, false, vpOidData);
			if ( vStatus )
			{
				m_NICDevice[m_NICnum].m_NICMac = vpOidData->Data;
			}
			else
			{
				Qt_printf("%s:%d\r\n", __FUNCTION__, __LINE__);
				//AfxMessageBox(_T("错误：获取本机网卡MAC地址失败。"));
			}
			
			PacketCloseAdapter( vlpAdapter );
		}
		
		m_NICnum ++;
	}
	
	free( vpOidData );
	
	return true;
}
