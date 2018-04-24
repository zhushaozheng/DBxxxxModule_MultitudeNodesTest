#include "winpcap_application.h"
#include "Qt_common_api.h"

winpcap_application::winpcap_application()
{
	m_pAllNIC = NULL;
	m_pHandler = NULL;
	m_NICnum = 0;
	m_CurNIC = 0;
	m_LastDispatchBufferPos = 0;
	m_LastRecvBufferPos = 0;
	m_MMEFilterLen = 0;
	
	start();
}

winpcap_application::~winpcap_application()
{
	pcap_freealldevs(m_pAllNIC);
}

void winpcap_application::InitAllBuff()
{
	m_LastDispatchBufferPos = 0;
	m_LastRecvBufferPos = 0;
	ZeroMemory(m_RecvBuffer, sizeof(CCMMEFrame)*eMaxReceiveBufSz);
	ZeroMemory(m_DispatchBuffer, sizeof(CCMMEFrame)*eMaxReceiveBufSz);
}

void winpcap_application::SaveToRecvBuffer(const u_char * apData, int aLen)
{
	CCMMEFrame vRecvMMEFrame;
	
	if (aLen > sizeof(vRecvMMEFrame))
	{
		return;
	}
	//Qt_printf("%s:%d\r\n", __FUNCTION__, __LINE__);
	memset(&vRecvMMEFrame, 0, sizeof(vRecvMMEFrame));
	memcpy(&vRecvMMEFrame, apData, aLen);
	//Qt_printf_buffer("buffer", (uint8*)apData, aLen);
	//if (vRecvMMEFrame.mGeneric_Reg.mEtherType == cHPAV_Ethertype
		//|| vRecvMMEFrame.mGeneric_Reg.mEtherType == 0xee88) {
		m_winpcap_mutex.lock();
		
		uint16 vMMType = vRecvMMEFrame.mGeneric_Reg.mMMTYPE;
		bool vbIsValidMMEType = true;
		
		for (uint8 i=0; i<m_MMEFilterLen; i++)
		{
			if (vMMType == m_MMEFilter[i])
			{
				vbIsValidMMEType = true;
				
				break;
			}
		}
		
		if (vbIsValidMMEType)
		{
			if (m_LastRecvBufferPos >= eMaxReceiveBufSz)
			{
				m_LastRecvBufferPos = 0;
				//AfxMessageBox(_T("RecvBuffer Overrun"));
				m_winpcap_mutex.unlock();
				
				return;
			}
			
			memcpy( &m_RecvBuffer[m_LastRecvBufferPos], &vRecvMMEFrame, sizeof(vRecvMMEFrame) );
			m_LastRecvBufferPos++;
		}
		
		m_winpcap_mutex.unlock();
	//}
}

void winpcap_application::run()
{
	if (!m_pHandler) {
		return;
	}
	
	struct pcap_pkthdr *vpheader;
	int vRet = 0;
	const u_char *vpkt_data;
	
	while (1)
	{
		msleep(10);
		
		if (IfChannelOpen())
		{
			vRet = pcap_next_ex(m_pHandler, &vpheader, &vpkt_data);
		}
		
		if (vRet < 0 || !IfChannelOpen()) {
			//-****realse the resource****-//
			m_winpcap_mutex.unlock();
			
			//-****end thread****-//
			exit();
		}
		else {
			if (vRet == 0)
			{
				continue;
			}
			
			SaveToRecvBuffer(vpkt_data, vpheader->len);	
		}
	}
}

bool winpcap_application::FindAllNicDevs()
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
				Qt_printf("%s:%d 错误：获取本机网卡MAC地址失败。\r\n", __FUNCTION__, __LINE__);
				//AfxMessageBox(_T("错误：获取本机网卡MAC地址失败。"));
			}
			
			PacketCloseAdapter( vlpAdapter );
		}
		
		m_NICnum ++;
	}
	
	free( vpOidData );
	
	return true;
}

bool winpcap_application::OpenChannel(uint16 *apMMEFilter, uint8 aMMEFilterLen)
{
	/* Open the adapter */
	if ((m_pHandler = pcap_open_live(	
		m_NICDevice[m_CurNIC].m_Name,   	// name of the device
		65536,			                // portion of the packet to capture. It doesn't matter in this case 
		1,				                // promiscuous mode (nonzero means promiscuous)
		eChannelTimeout,			    // read timeout
		m_errbuf		                // error buffer
		)) == NULL)
	{
		return false;
	}
	
	static struct bpf_insn bpf_insn [] =
	{
		#if 1
		{BPF_LD + BPF_H + BPF_ABS, 0, 0, 12},
		{BPF_JMP + BPF_JEQ + BPF_K, 2, 0, 0x88e1},
		{BPF_LD + BPF_H + BPF_ABS, 0, 0, 12},
		{BPF_JMP + BPF_JEQ + BPF_K, 0, 2, 0x88ee},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 0},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 10, 0},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 1},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 8, 0},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 2},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 6, 0},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 3},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 4, 0},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 4},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 2, 0},
		//{BPF_LD + BPF_B + BPF_ABS, 0, 0, 5},
		//{BPF_JMP + BPF_JEQ + BPF_K, 4, 0, 0},
		//{BPF_LD + BPF_W + BPF_ABS, 0, 0, 0},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 4, 0xFFFFFFFF},
		//{BPF_LD + BPF_H + BPF_ABS, 0, 0, 4},
		//{BPF_JMP + BPF_JEQ + BPF_K, 0, 2, 0xFFFF},
		{BPF_LD + BPF_W + BPF_LEN, 0, 0, 0},
		{BPF_RET + BPF_A, 0, 0, 0},
		{BPF_RET + BPF_K, 0, 0, 0},
		#endif
		#if 0
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 3, 0),
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 3),
		BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
		BPF_STMT(BPF_RET + BPF_A, 0),
		BPF_STMT(BPF_RET + BPF_K, 0),
		#endif
	};
	
	struct bpf_program bpf_program;
	bpf_program.bf_len = sizeof (bpf_insn)/sizeof (struct bpf_insn);
	bpf_program.bf_insns = bpf_insn;
	
	//bpf_insn [1].code = BPF_JMP + BPF_JEQ + BPF_K;
	//bpf_insn [1].jt = 0;
	//bpf_insn [1].jf = 18;
	//bpf_insn [1].k = 0x88e1;
	//bpf_insn [1].jt = 3;
	//bpf_insn [1].jf = 0;
	
	//bpf_insn [3].k = 0x88ee;
	//bpf_insn [3].jt = 0;
	//bpf_insn [3].jf = 3;
	//bpf_insn [6].k = 0;
	//bpf_insn [3].k = mNICDevice[m_CurNIC].mNICMac.mByte[0];
	//bpf_insn [5].k = mNICDevice[m_CurNIC].mNICMac.mByte[1];
	//bpf_insn [7].k = mNICDevice[m_CurNIC].mNICMac.mByte[2];
	//bpf_insn [9].k = mNICDevice[m_CurNIC].mNICMac.mByte[3];
	//bpf_insn [11].k = mNICDevice[m_CurNIC].mNICMac.mByte[4];
	//bpf_insn [13].k = mNICDevice[m_CurNIC].mNICMac.mByte[5];
	
	if (pcap_setfilter (m_pHandler, &bpf_program) < 0)
	{
		return false;
	}
	
	if (pcap_setmintocopy (m_pHandler, eMinEthSz) < 0)
	{
		return false;
	}
	
	m_MMEFilterLen = aMMEFilterLen;
	memcpy(m_MMEFilter, apMMEFilter, sizeof(uint16)*m_MMEFilterLen);

	start();

	return true;
}

void winpcap_application::CloseChannel()
{
	if (m_pHandler) {
		pcap_close(m_pHandler);
	}
	
	m_pHandler = NULL;
	
	//terminate();
	//wait();
	exit();
	
	//-****Initialize all buffers****-//
	InitAllBuff();
}

bool winpcap_application::IfChannelOpen()
{
	if (m_pHandler) {
		return true;
	}
	else {
		return false;
	}
}

void winpcap_application::DispatchPacket(CCMMEFrame aMMEFrame)
{
	CCMMEFrame vMMEFrame = aMMEFrame;
	if (vMMEFrame.mRegular_V0.mEtherType == 0xe188
		|| vMMEFrame.mRegular_V0.mEtherType == 0xee88) {
		switch (vMMEFrame.mGeneric_Reg.mMMTYPE) {
			case VS_SW_VER::eMMTypeCnf: {
				//gDUTMACAddress = aMMEFrame.mOSA;
				//gGoldenMACAddress = aMMEFrame.mOSA;
				//gModule.DispatchMME_VS_SW_VER(vMMEFrame.mRegular_V0.mMMEntry.mVS_SW_VER.CNF, aMMEFrame.mOSA);
				Qt_printf("%s:%d Rx:VS_SW_VER::eMMTypeCnf\r\n", __FUNCTION__, __LINE__);
				break;
			}
			case VS_NW_INFO_STATS::eMMTypeCnf: {
				//gModule.DispatchMME_VS_NW_INFO_STATS(vMMEFrame.mRegular_V0.mMMEntry.mVS_NW_INFO_STATS.CNF, aMMEFrame.mOSA);
				Qt_printf("%s:%d Rx:VS_NW_INFO_STATS::eMMTypeCnf\r\n", __FUNCTION__, __LINE__);
				break;
			}
			case VS_RS_DEV::eMMTypeCnf: {
				//gModule.DispatchMME_VS_RS_DEV(vMMEFrame.mRegular_V0.mMMEntry.mVS_RS_DEV.CNF);
				Qt_printf("%s:%d Rx:VS_RS_DEV::eMMTypeCnf\r\n", __FUNCTION__, __LINE__);
				break;
			}
			case VS_Transparent::eMMTypeReq: {
				//if (!gModule.mISMainDevice ) {
					//gModule.DispatchMME_VS_Transparent_Req(aMMEFrame.mOSA);
				//}
				Qt_printf("%s:%d Rx:VS_Transparent::eMMTypeReq\r\n", __FUNCTION__, __LINE__);
				break;
			}
			case VS_Transparent::eMMTypeCnf: {
				//if (gModule.mISMainDevice ) {
					//gModule.DispatchMME_VS_Transparent_Cnf(vMMEFrame.mRegular_V0.mMMEntry.mVS_Transparent.CNF, aMMEFrame.mOSA);
				//}
				Qt_printf("%s:%d Rx:VS_Transparent::eMMTypeCnf\r\n", __FUNCTION__, __LINE__);
				break;
			}
			default:
				break;
		}
	}
	
	return;
}

void winpcap_application::DispatchAllPacketsInBuffer(void)
{
	unsigned int i;
	unsigned int loop_count;
	
	//If Dispatch buffer is empty, copy Recv buffer to Dispatch buffer
	if ((m_LastDispatchBufferPos == 0) && (m_LastRecvBufferPos != 0)) {
		m_winpcap_mutex.lock();
		
		ZeroMemory(m_DispatchBuffer, sizeof(m_DispatchBuffer));
		memcpy(m_DispatchBuffer, m_RecvBuffer, m_LastRecvBufferPos*sizeof(CCMMEFrame));
		m_LastDispatchBufferPos = m_LastRecvBufferPos;
		ZeroMemory(m_RecvBuffer, m_LastRecvBufferPos*sizeof(CCMMEFrame));
		m_LastRecvBufferPos = 0;
		
		m_winpcap_mutex.unlock();
	}
	
	//Dispatch all packets in Dispatch buffer
	loop_count = m_LastDispatchBufferPos;
	m_winpcap_mutex.lock();
	
	for (i = 0; i<loop_count; i++) {
		DispatchPacket(m_DispatchBuffer[i]);
	}
	
	m_winpcap_mutex.unlock();
	m_LastDispatchBufferPos = 0;
}
