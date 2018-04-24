#ifndef MME_DEFINE_H
#define MME_DEFINE_H

#include "Qt_common_api.h"

#define VS_NW_INFO_STATS_TEMP_EXTEND_PHYRATE_MEMBER_VAR

enum {
	eKilobyte = 1024,
	eMegabyte = eKilobyte * 1024,
	eKilobits = 1024,
	eMegabits = eKilobits * 1024
};

/*===========================================================================*
*                        GLOBAL DEFINITIONS & MACROS
=============================================================================*/
//-* Version Defines *-//
class EEVersions
{
public:
	enum {
		eHPAV	= 0x00,	//HPAV Version Supported
		eMME	= 0x00,	//MME Version Supported - remove when is out OLD_MME_TEMPLATE
		eMME_V0	= 0x00,	//MME Version Supported
		eMME_V1	= 0x01,	//MME Version Supported
		eSACK	= 0x0	//SACK Version Supported
	};
};
//-* Protocol Defines *-//
enum ProtocolDefines
{
	cBytesPerWord		=	4,
	cNibblePerWord		=	8,
	cBitsPerByte		=	8,

	//-****TEIs****-//
	cBroadcastTEI		=	0xff,
	cInvalid_TEI		=	0x00,
	c1stValid_TEI		=	0x01,
	cLastValid_TEI		=	0xfe,
	eNumValidTeis		=	cLastValid_TEI - c1stValid_TEI + 1,

	//-****NID & SNID & HFID****-//
	cSNIDMask			=	0x0f,//4bit SNID
	cMax_SNIDs			=	16,
	cNIDSz				=	7,
	cHFIDSz				=	64,

	//-****Ethernet****-//
	cMACAddressSz		=	6,
	cOUISz				=	3,
	cEtherTypeSz		=	2,
	cVLANTagSz			=	4,
	cVLANTagValue		=	0x81000001,
	cIPv4AddresSz		=	4,
	cIPv6AddresSz		=	16,
	cIPv6AddresPerWord	=	cIPv6AddresSz/cBytesPerWord,
	cIPPortSz			=	2,
	cVlanTagSz			=	4,
	cMinEnetFrmSz		=	60,	//64 minus CRC
	cMaxRegEnetFrmSz	=	1514,
	cMaxEnetFrmSz		=	1518,//1514 plus VLAN tag

	//-****Topology****-//
	cMaxTEIsInNet		=	256,
	cMaxNetworks		=	3,

	//-****MME Types****-//
	cHPAV_Ethertype		= 0xe188,	//0x88e1
	cMME_Category_Mask	= 0xe000,
	cMME_ManSpcfc_Mask	= 0x8000,
	cMME_VenSpcfc_Mask	= 0xA000,
	cMME_CategoryType_Mask	= 0xFFFC
};

// MME Type - 2 LSB's
enum { eReq = 0x0000, eCnf = 0x0001, eInd = 0x0002, eRsp = 0x0003 };

// MME Type - 3 MSB's
enum { eCC = 0x0000, eCP = 0x2000, eNN = 0x4000, eCM = 0x6000, eMS = 0x8000, eVS = 0xA000, eDB = 0xC000, };
			//0b000        0b001         0b010         0b011         0b100         0b101

#ifdef WIN32
	#define __packed
	#pragma pack(push, mmes, 1)
#endif

//////////////////////////////////////////////////////////////////////
// CCMACAddress Class
//////////////////////////////////////////////////////////////////////
__packed class CCMACAddress//48 bit MAC Address
{
public://all members are public for aggregate objects

	//- Structs and Enums -//
	__packed class CCOUI//First 3 bytes of the MAC Address
	{
	public:
		//- Variables -//
		uint8 mOUIByte[cOUISz];

		//- Operators -//
		bool operator == ( const CCOUI& rCOU) const
		{//equal operator
			return( (memcmp( &this->mOUIByte[0] , &rCOU, cOUISz ) == 0) ? true : false);
		}

		bool operator != ( const CCOUI& rCOU ) const
		{//not equal operator
			return !(*this == rCOU);
		}
		void operator = ( const uint8 *aBytes )
		{//copy from array of Bytes
			memcpy( &mOUIByte[0], &aBytes[0], cOUISz );
		}
	};

	//- Variables -//
	uint8 mByte[cMACAddressSz];//6 individual bytes of the MAC Address

	//- Methods -//
	inline const uint8 * GetMACAddressAsArrayOfBytes() const
	{
	    return mByte;
	}

	inline int IsBroadcast() const {
		if ( mByte[0] != 0xff ) {
			return false;
		}
		if ( mByte[1] != 0xff ) {
			return false;
		}
		if ( mByte[2] != 0xff ) {
			return false;
		}
		if ( mByte[3] != 0xff ) {
			return false;
		}
		if ( mByte[4] != 0xff ) {
			return false;
		}
		if ( mByte[5] != 0xff ) {
			return false;
		}
		return true;
	}


	inline bool IsMulticast()const//Test to see if this is a Multicast address
	{
		if (IsBroadcast())
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	inline bool IsPauseDA()const//Test to see if this is the Pause DA
	{
		if ( (mByte[0] == 0x01) //01:80:c2:00:00:01
			&& (mByte[1] == 0x80)
			&& (mByte[2] == 0xc2)
			&& (mByte[3] == 0x00)
			&& (mByte[4] == 0x00)
			&& (mByte[5] == 0x01))
		{
			return(true);
		}
		else
		{
			return(false);
		}
	}

	inline CCOUI GetOUI()const//return the OUI
	{
		return( *(CCOUI*) &mByte[0]);
	};

	inline int32 CompareTo( const CCMACAddress& rCMA ) const
	{//compares current address to another
		//returns 0 if equal; returns > 0 if current > other; returns <0 if current < other
		return( (int32) memcmp( this , &rCMA, cMACAddressSz ));
	}

	inline void Clear() {
		int vI = cMACAddressSz - 1;
		do {
			mByte[vI] = 0;
		} while ( --vI >= 0 );
	}
	
	//- Operators -//

private:
	// Catch substitutes:
	void operator = ( int );
public:

	void operator = ( const uint8 *aBytes )
	{//copy from array of Bytes
		int vI = cMACAddressSz - 1;
		do {
			mByte[vI] = aBytes[vI];
		} while ( --vI >= 0 );
	}

	bool operator == ( const CCMACAddress& rCMA) const
	{//equal operator
		return *this == rCMA.mByte;
	}

	bool operator != ( const CCMACAddress& rCMA ) const
	{//not equal operator
        return !(*this == rCMA);
	}
	bool operator == ( const uint8 *aBytes) const
	{//equal operator
		for ( int vI = cMACAddressSz - 1; vI >=0; vI-- ) {
			if ( mByte[vI] != aBytes[vI] ) {
				return false;
			}
		}
		return true;
	}

	bool operator != ( const uint8 *aBytes ) const
	{//not equal operator
        return !(*this == aBytes );
	}

	bool operator < ( const CCMACAddress& rCMA ) const
	{//byte-wise less than
		int vResult = CompareTo( rCMA );
		return( (vResult < 0) ? true : false);
	}

	bool operator > ( const CCMACAddress& rCMA ) const
	{//byte-wise greater than
		int vResult = CompareTo( rCMA );
		return( (vResult > 0) ? true : false);
	}

	CCMACAddress operator & ( const CCMACAddress& rCMA ) const
	{//AND with a MASK
		CCMACAddress NewAddress;
		NewAddress.mByte[0] = (uint8)(mByte[0] & rCMA.mByte[0]);
		NewAddress.mByte[1] = (uint8)(mByte[1] & rCMA.mByte[1]);
		NewAddress.mByte[2] = (uint8)(mByte[2] & rCMA.mByte[2]);
		NewAddress.mByte[3] = (uint8)(mByte[3] & rCMA.mByte[3]);
		NewAddress.mByte[4] = (uint8)(mByte[4] & rCMA.mByte[4]);
		NewAddress.mByte[5] = (uint8)(mByte[5] & rCMA.mByte[5]);
		return( NewAddress );
	}

};

//Power Meter ID is just like MAC Address
typedef CCMACAddress CCPowerMeterID;

//OUI
const CCMACAddress::CCOUI cIntellonOUI = { 0x00, 0xb0, 0x52 };

//Default MAC Addresses
const CCMACAddress cDefaultRomoteMACAddress = { 0x00, 0x03, 0x7f, 0x00, 0xdb, 0xe1 }; 
const CCMACAddress cDefaultLocalMACAddress = { 0x00, 0xb0, 0x52, 0x00, 0x00, 0x01 };
const CCMACAddress cSoftloaderLocalMACAddress = { 0x00, 0xb0, 0x52, 0x00, 0x00, 0x02 };
const CCMACAddress cInvalidPIBLocalMACAddress = { 0x00, 0xb0, 0x52, 0x00, 0x00, 0x03 };
const CCMACAddress cInvalidHwInitializationLocalMACAddress = { 0x00, 0xb0, 0x52, 0x00, 0x00, 0x04 };
const CCMACAddress cOtherLocalMACAddress = { 0x00, 0xb0, 0x52, 0x01, 0x02, 0xee };
const CCMACAddress cInvalidMACAddress = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const CCMACAddress cBroadcastMACAddress = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

//////////////////////////////////////////////////////////////////////
// CCNetworkID Class
//////////////////////////////////////////////////////////////////////
class EESecurityMode
{
public:
	enum tMode {
		eSimpleConnect	= 0,
		eSecureSecurity	= 1,
		e1stRSVD		= 2//used to validate Parameter block
	};
};
__packed class CCNetworkID//54 bit Network ID and 2 rsvd bits
{
public:
	//- Variables -//
	enum { eSecurityByteMask = 0x3F, eNIDNibbleMask = 0x0F, eSecurityMode = 0x30 };

	__packed class CCSecurityByField
	{
	public:
		uint8	mNIDNibble		:4;
		uint8	mSecurityMode	:2;
		uint8	mHybridMode		:2;
	};

	__packed class CCNIDByField
	{
	public:
		uint8			mNIDByField_Byte[cNIDSz-1];
		__packed union
		{
			uint8				mSecurityByte;
			CCSecurityByField	mSecurityByField;
		};
	};

	__packed union
	{
		CCNIDByField	mByField;
		uint8			mByte[cNIDSz];//7 individual bytes of the Network ID
	};

	//- Methods -//
	__packed uint8* GetArrayPtr() { return &mByte[0]; }

	void SetSecurityMode( EESecurityMode::tMode aSecurityMode )
	{
		uint32 NewSecurityByte = mByField.mSecurityByte;

		NewSecurityByte &= eNIDNibbleMask;//get current NIDNibble from security byte

		NewSecurityByte |= (aSecurityMode << 4);//shift security mode into High Nibble

		mByField.mSecurityByte = (uint8) NewSecurityByte;//save new security byte
	}

	EESecurityMode::tMode GetSecurityMode()
	{
		return (EESecurityMode::tMode) mByField.mSecurityByField.mSecurityMode;
	}

	//- Operators -//
	void operator = ( const uint8 *aBytes )
	{//copy from array of Bytes
		memcpy( &mByte[0], &aBytes[0], cNIDSz );
	}

	bool operator == ( const CCNetworkID& rCNI) const
	{//equal operator
		return( (memcmp( this , &rCNI, cNIDSz ) == 0) ? true : false);
	}

	bool operator != ( const CCNetworkID& rCNI ) const
	{//not equal operator
        return !(*this == rCNI);
	}
};

// Vendor Specific
// ------------------------------------------------------------
class EEModuleID
{
	//used by VS_ST_MAC, VS_WR_MOD, VS_RD_MOD, VS_MOD_NVM
public:
	enum
	{
		eSoftLoader			= 0x00,
		eFirmware			= 0x01,
		ePib                = 0x02,
		eFirmwareAndPib		= 0x03,
		ePibMerge           = 0x04,
		e1stRSVDModuleID    = 0x05,
		eModuleOperation	= 0x08,
		eForceFlashWrite    = 0x10,
		eDoNotReboot   		= 0x020,
		eUseAltSections     = 0x040,
		eForceToSection     = 0x080
	};


	enum
	{
		eSoftloaderPibAddress = 0x00200000, // Reserve 16KB of external memory
		eSoftloaderPibMaxSize = 16 * eKilobyte
	};

};

//0xA000	VS_SW_VER (REQ, CNF)
__packed class VS_SW_VER
{
public:
	enum {
		eMMType = 0x0000,					// VS_SW_VER
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eVerSz = 253,						// Firmware Version String Size, determined by version.inc
		eVerSzBootRom = 64					// Bootrom Version String Size
	};

	enum { eSuccess = 0x00, eFail = 0x01 };
	enum {
		//Legacy IDs
		eUnknown  = 0x00,
		eINT6000	= 0x01,
		eINT6300	= 0x02,
		eINT6400	= 0x03,
		eAr7400		= 0x04,
		eAr6405		= 0x05,
		eAr6400		= 0x06,
		//Supported IDs. See ProductInfo.cpp/h
		eQca7420    = 0x20,
		eQca6410    = 0x21,
		eQca6411    = 0x21,
		eQca7000    = 0x22
	};
	enum { eNoUpdate = 0, eCanUpdate = 1 };
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint32              mCookie;        // message ID
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
		uint8			mDeviceID;			// DeviceID
		uint8			mVersionLen;		// Version String length
		char			mVersion[eVerSz];	// Firmware Version String
		uint8			res;
		uint32			mIdent;				// Identification register value. See ProductInfo.cpp/h
		uint32			mSteppingNum;		// Stepping num register value
		uint32			mChipSequenceNumber;
		uint32			mChipPackage;
		uint32			mChipOptions;
	};

	__packed class CnfBootRom
	{
	public:
		CCMACAddress::CCOUI	mOUI;					// OUI
		uint8			mStatus;					// Success = 0
		uint8			mDeviceID;					// DeviceID
		uint8			mVersionLen;				// Version String length
		char			mVersion[eVerSzBootRom];	// Bootrom Version String
		uint8			mRSVD;
		uint32			mIdent;						// Identification register value
		uint32			mSteppingNum;				// Stepping num register value
		uint32          mCookie;					// message ID
	};

	__packed union { Req REQ; Cnf CNF; CnfBootRom CNFBOOTROM; };
};

//0xA01C	VS_RS_DEV (REQ, CNF)
__packed class VS_RS_DEV
{
public:
	enum {
		eMMType = 0x001C,					// VS_RS_DEV
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf	// .Cnf
	};
	enum { eSuccess = 0x00, eFail = 0x01 };

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA048	VS_FR_LBK (REQ, CNF)
__packed class VS_FR_LBK
{
public:
	enum {
		eMMType = 0x0048,					// VS_RD_MOD
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eMaxDataSz = 1038 // bytes
	};

	enum { eSuccess = 0x00,
	        eFail = 0x01,
		eInvalidDuration = 0x20,
		eInvalidLength = 0x12,
		eAlreadySet = 0x24
		  };


	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mDuration;			// Time duration
		uint8           mRes;
		uint16			mLength;			// Number of octets in frame
		uint8           mData[eMaxDataSz];
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mDuration;			// Time duration
		uint8           mRes;
		uint16			mLength;			// Number of octets in frame
		uint8           mData[eMaxDataSz];
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA074	VS_NW_INFO_STATS (REQ, CNF)
__packed class VS_NW_INFO_STATS
{
public:
	enum {
		eMMType = 0x0074,					// VS_NW_INFO_STATS
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf	// .Cnf
	};

	#if defined (VS_NW_INFO_STATS_TEMP_EXTEND_PHYRATE_MEMBER_VAR)
		enum { eMaxSTAs = 60 };
	#else
		enum { eMaxSTAs = 96 };
	#endif

	/*CCMMESubFrame_V0::eMMEHeaderSz(17) + Cnf::eBaseSize(24)
	 + CCSTAInfo::eArrayUnitSize(15) * eMaxSTAs(96) << 1514*/
	__packed class CCNWInfo
	{
	public:
		CCNetworkID		mNID;
		uint8			mSNID;
		uint8			mTEI;
		uint8			mStationRole;
		CCMACAddress	mCCoAddress;
		uint8			mAccess;
		uint8			mNumCordNWs;
	};

	__packed class CCSTAInfo
	{
	public:
		CCMACAddress	mSTAAddress;
		uint8			mSTATEI;
		CCMACAddress	mSTA1stBrgAddress;
		#if defined (VS_NW_INFO_STATS_TEMP_EXTEND_PHYRATE_MEMBER_VAR)
			//TEMP - increase phy rate to 2 bytes to support 7400 rates
			uint16			mAvgTxPhyRate_Mbps;
			uint16			mAvgRxPhyRate_Mbps;
		#else
			uint8			mAvgTxPhyRate_Mbps;
			uint8			mAvgRxPhyRate_Mbps;
		#endif

		enum {
			#if defined (VS_NW_INFO_STATS_TEMP_EXTEND_PHYRATE_MEMBER_VAR)
				eAvgPhyRate_FieldSaturated	= 0xffff
			#else
				eAvgPhyRate_FieldSaturated	= 0xff
			#endif
		};
	};

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI		mOUI;	// OUI
		uint8					mFirstTEI;
	};

	__packed class Cnf
	{
	public:
		enum { eBaseSize = 25, eArrayUnitSize = sizeof(CCSTAInfo) };

		CCMACAddress::CCOUI		mOUI;			// OUI
		uint8					mFirstTEI;
		uint8					mInAVLN;
		CCNWInfo	            mNWInfo;
		uint8					mCCoTEI;
		uint8					mNumSTAs;
		CCSTAInfo				mStaInfos[eMaxSTAs];
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA0B0	VS_MODULE_OPERATION (REQ, CNF)
__packed class VS_MODULE_OPERATION
{
public:
	enum {
		eMMType = 0x00B0,					// VS_MODULE_OPERATION
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf	// .Cnf
	};

	//enum { eMaxDataLen = 1400, eMaxModPerSession = 100, eMaxModOpPerMME = 5 };
	enum { eMaxDataLen = 1400, eMaxModPerSession = 10, eMaxModOpPerMME = 1};//TODO: Temporary set

	class EEModule_Operation
	{
	public:
		enum tID
		{
			eReadMod_Memory		= 0x00,
			eReadMod_NVM		= 0x01,
			eStartWriteSession	= 0x10,
			eWriteMod_Memory	= 0x11,
			eCommitMod_NVM		= 0x12
		};
		enum tSubType
        {
           eSoftloaderSubType		= EEModule_Operation::eStartWriteSession << 16 | EEModuleID::eSoftLoader,
           ePibReadMemSubType		= EEModule_Operation::eReadMod_Memory << 16 | EEModuleID::ePib,
           ePibReadNvmSubType		= EEModule_Operation::eReadMod_NVM    << 16 | EEModuleID::ePib,
           ePibUpdateSubType		= EEModule_Operation::eStartWriteSession << 16 | EEModuleID::ePib,
           eFWAndPibUpdateSubType	= EEModule_Operation::eStartWriteSession << 16 | EEModuleID::eFirmwareAndPib,
           ePibMergeSubType			= EEModule_Operation::eStartWriteSession << 16 | EEModuleID::ePibMerge,
           eModuleOperationSubType	= EEModuleID::eModuleOperation
        };
		enum NVM_eCustomModuleIds {
			eCustomModuleId_MdioInitialization			= 0x1000,
			eCustomModuleId_UARTAsycSerialComm			= 0x2000,
			eCustomModuleId_MACAddressEnumIDTable		= 0x3000,
			eCustomModuleId_AdvPowerManagementModule	= 0x4000,
			#ifdef ENABLE_TR069_STACK
				//[NK] Kept the legacy ID below
			#endif
			eCustomModuleId_NetMgmt_TR069				= 0x4001,

			eCustomModuleId_ForwardConfiguration        = 0x7000,
			eCustomModuleId_Firmware					= 0x7001,
			eCustomModuleId_Pib							= 0x7002,
			eCustomModuleId_SoftwareLoader				= 0x7003,
			eCustomModuleId_RawNvmData   				= 0x7004,
			eCustomModuleId_PibMerge					= 0x7005,

			//TODO: update CCFrmRtr::AuthorizedUpdateMatrix when PIB and FW are added to this - ref:Selective Upgrade feature spec
			eCustomModuleId_PermittedFromAnySource0 = 0x8f00,
			eCustomModuleId_PermittedFromAnySource1 = 0x8f01,
	
			eCustomModuleId_Invalid                 = 0xffff,
		};
	};

	__packed class CCommit_Code
	{
	public:
		__packed struct tCommitAsBitField
		{
		uint32	mForceToBlankNVM	: 1;
		uint32	mDoNoReset			: 1;
		uint32	mRsvd2				: 1;
		uint32	mRsvd3				: 1;
		uint32	mRsvd4				: 1;
		uint32	mRsvd5				: 1;
		uint32	mRsvd6				: 1;
		uint32	mRsvd7				: 1;
		uint32	mRsvdW1_2			: 23;
		uint32  mReplaceFactoryPib  : 1;
		};
		__packed union
		{
			tCommitAsBitField mCode;
			uint32 mCommitAsWord;
		};

	};

	class EEModule_Status
	{
	public:
		enum tStatus
		{
			//Success
			eSuccess				= 0x00,//Success
			//MME Parameter Issues
			eInvalid_NumModOps		= 0x10,//Invalid Number of Module Operations
			eInvalid_ModOperation	= 0x11,//Invalid Module Operation ID
			eInvalid_Session_ID		= 0x12,//Invalid Session ID
			eInvalid_NumModules		= 0x13,//Invalid_ Num Module Operation Specific Data
			eModule_ID_NotFound		= 0x14,//Module ID not Found
			eInvalid_ModuleLen		= 0x15,//Invalid Module Length
			eInvalid_ModIdx			= 0x16,//Invalid Module Index
			eInvalid_DataLen		= 0x17,//Invalid Data Length
			eInvalid_ModOffset		= 0x18,//Unexpected Offset
			eInvalid_CommitActionCode = 0x19,//Invalid Commit Code
			eBlocked_PreviousCommit	= 0x1A,//Operation Block by previous Commit
			eDuplicate_ModuleID		= 0x1B,//Duplicate Module ID/SubID
			eInvalid_ModuleID		= 0x1C,//Invalid Module ID/SubID
			eInvalid_ModLenDataLenMismatch = 0x1C,//The MME frame Length does not match Module LEN
			//NVM Issues
			eNVM_NotPresent			= 0x20,//NVM not Present
			eNVM_Small				= 0x21,//NVM too small
			eUnsupportedFlash		= 0x22,//Unsupported Flash
			eFailToLockNVM			= 0x23, //Fail to lock NVM
			eFailToWriteToNvmCollision = 0x24, //Fail to Write to Nvm
			//Module Issues
			eInvalid_Module_CheckSum = 0x30,//Invalid Module checksum
			eModule_Error			= 0x31,//Individual Module Error
			eModuleNotAvailableInNvmOrMem = 0x32,//The expected module is not available in Nvm or Memory.
			//Intellon Module Issues
			eInvalid_Header_CheckSum = 0x40,//Invalid Header Checksum
			eInvalid_FW_ImageCheckSum = 0x41,//Invalid FW Checksum
			eFW_ImageTooLarge		= 0x42,//Invalid FW Checksum
			eSoftLoaderTooLarge		= 0x43,//Soft-loader is too large
			eInvalid_PIB_CheckSum	= 0x44,//Invalid PIB Checksum
			eNoFWVersion			= 0x45,//No Firmware Version
			eCommitFW_WO_PIB		= 0x46,//FW Commit but no PIB
			eMajorVersion_Mismatch	= 0x47,//Major Version Mismatch
			eMinorVersion_Mismatch	= 0x48,//Minor Version Mismatch
			eInvalid_PIB			= 0x50,//Invalid PIB
			eDAKNotZero				= 0x51,//DAK not zero
			eMAC_MisMatch			= 0x52,//MAC mismatch
			eDAK_MisMatch			= 0x53,//DAK mismatch
			eMfgHFID_MisMatch		= 0x54,//Mfg HFID mismatch
			eBadBind_FactoryPIB		= 0x55,//Bad bind to FAC. Default PIB
			eBadBind_TemplatePIB	= 0x56,//Bad bind to template PIB
			eBadBind_WorkingPIB		= 0x57,//Bad bind to working PIB
			eBadBind_ScratchPIB		= 0x58,//Bad Bind Scratch PIB
			eCSGenErr_ScratchPIB	= 0x59,//Error Generating Checksum Scratch PIB
			eCSGenErr_O1PIB			= 0x5a,//Checksum Error O1 PIB
			eCSGenErr_O2PIB			= 0x5b,//Checksum Error O2 PIB
			eCSGenErr_WorkingPIB	= 0x5c,//Checksum Error Working PIB
			// State Issues
			eUnexpectedModOperation = 0x61,
			eNotEnoughResoures 		= 0x62,
			eModuleDataReceivedOutOfOrder = 0x63,
			eNoPibVersion			= 0x64,
			// Module Update Issues
			eModuleLengthMismatchWithModuleInfo = 0x70,
			eMissingNvmSoftloaderInFlash = 0x71,
			eCookieMismatch              = 0x72,
			eBlocked_PreviousRead        = 0x73,
			// Miscellaneous Issues
			eUnknownError			= 0xFF,
		};
	};

	__packed class CStatusWord
	{
	public:
		uint16	mStatus;		// Success = 0
		uint16	mErrorCode;
	};

	//-**************************-//
	__packed class CModOpDataHdr
	{
	public:
		uint16	mModOperation;
		uint16	mModOpDataLen;
		uint32	mRSVD;
	};

	//-*Read Module Operation*-//
	__packed class CRead_Req_Data
	{
	public:
		CModOpDataHdr	mDataHdr;
		uint16			mModule_ID;
		uint16			mModule_SubID;
		uint16			mDataLen;
		uint32			mModOffset;
	};
	__packed class CRead_Cnf_Data
	{
	public:
		enum { eBaseSize = (sizeof(CModOpDataHdr) + 10) };

		CModOpDataHdr	mDataHdr;
		uint16			mModule_ID;
		uint16			mModule_SubID;
		uint16			mDataLen;
		uint32			mModOffset;
		uint8			mData[eMaxDataLen];
	};

	//-*Start Write Session Module Operation*-//
	__packed class CModuleInfo
	{
	public:
		uint16			mModule_ID;
		uint16			mModule_SubID;
		uint32			mModule_Len;
		uint32			mModule_CheckSum;
	};
	__packed class CStart_Req_Data
	{
	public:
		enum { eBaseSize = (sizeof(CModOpDataHdr) + 5) };

		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		uint8			mNumModules;
		CModuleInfo		mModuleInfo[eMaxModPerSession];
	};
	__packed class CStart_Cnf_Data
	{
	public:
		enum { eBaseSize = (sizeof(CModOpDataHdr) + 5) };

		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		uint8			mNumModules;
		CStatusWord		mModStatus[eMaxModPerSession];
	};

	//-*Write Module Operation*-//
	__packed class CWrite_Req_Data
	{
	public:
		enum { eBaseSize = (sizeof(CModOpDataHdr) + 15) };

		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		uint8			mModIndex;
		uint16			mModule_ID;
		uint16			mModule_SubID;
		uint16			mDataLen;
		uint32			mModOffest;
		uint8			mData[eMaxDataLen];
	};
	__packed class CWrite_Cnf_Data
	{
	public:
		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		uint8			mModIndex;
		uint16			mModule_ID;
		uint16			mModule_SubID;
		uint16			mDataLen;
		uint32			mModOffest;
	};

	//-*Commit Module Operation*-//
	__packed class CCommit_Req_Data
	{
	public:
		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		CCommit_Code	mCommitActionCode;
		uint32			mPrivate;
	};
	__packed class CCommit_Cnf_Data
	{
	public:
		enum {  eBaseSize = (sizeof(CModOpDataHdr) + 9) };

		CModOpDataHdr	mDataHdr;
		uint32			mSession_ID;
		CCommit_Code	mCommitActionCode;
		uint8			mNumModules;
		CStatusWord		mModStatus[eMaxModPerSession];
	};
	//-**************************-//

	__packed class Req
	{
	public:
		enum { eBaseSize = 8 };

		CCMACAddress::CCOUI	mOUI;			// OUI
		uint32				mRSVD;
		uint8				mNumModOps;
		__packed union UUModOpData
		{
			CModOpDataHdr		mHeader;
			CRead_Req_Data		mRead_OpData;
			CStart_Req_Data		mStart_OpData;
			CWrite_Req_Data		mWrite_OpData;
			CCommit_Req_Data	mCommit_OpData;
		} mModOpData;
	};

	__packed class Cnf
	{
	public:
		enum { eBaseSize = 12 };

		CCMACAddress::CCOUI	mOUI;			// OUI
		CStatusWord			mMMEStatus;
		uint32				mRSVD;
		uint8				mNumModOps;
		__packed union UUModOpData
		{
			CModOpDataHdr		mHeader;
			CRead_Cnf_Data		mRead_OpData;
			CStart_Cnf_Data		mStart_OpData;
			CWrite_Cnf_Data		mWrite_OpData;
			CCommit_Cnf_Data	mCommit_OpData;
		} mModOpData;
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA308, vendor-specific MME, VS_AVLN_TOPO(REQ/CNF),
//CCo receive request from host and response.
__packed class VS_AVLN_TOPO
{
public:
	enum {
		eMMType = 0x0308,					// VS_AVLN_TOPO
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
	};

	enum {
		SUB_CMD_GET_TREE = 0x01,
		SUB_CMD_TRACE = 0x02,
		//add new command below
	};

	//command response result
	//LSB 1 bit: if it is successful or not.
	//MSB 1 bit: if has another MME followed, "1" mean yes, "0" mean no
	//			and it is the last MME. the Get tree Cnf may use two MMEs.
	enum {
		eCmdRspMask = 0x01,
		eSuccess = 0x00,
		eFail = 0x01,

		eMmeNumMask= 0x80,
		eMmeNumBitSet = 0x80,

	};

	//for mStatus
	//LSB 1 bit: "1" mean it is authentication, "0" mean association.
	//other 7 bits are reserved
	enum {
		eAssoStatusMask = 0x01,
		eAssociation = 0x00,
		eAuthentication = 0x01,
	};

	//used by Cnf as data
	__packed class STAInfo
	{
	public:
		CCMACAddress	mMacAddress;	//STA's Mac Address
		uint8	mSTATEI;		// STA's TEI
		uint8	mNumOfHSTA;		// num of HSTA under it
		uint8	mStatus;		//Status of the STA.
	};

	enum {
		eSTAInfoSize = sizeof(STAInfo),	// 9 bytes

		eFixPartSizeOfReq = 4,	// OUI + command  = 3 + 1
		eFixPartSizeOfCnf = 5,	// ONU + command + cmd rsp  = 3 + 1 + 1

		eMaxDataSizeOfReq =  1491, //CCMMENTRY::eMaxMmeData - eFixPartSizeOfReq = 1495-4
		eMaxDataSizeOfRsp =  1490, //CCMMENTRY::eMaxMmeData - eFixPartSizeOfCnf = 1495-5

		eFixPartSizeOfGetTreeRsp = 12,	// OUI + command + cmd rsp + MAC + numOfSTA = 3+1+1+6+1= 12
		eFixPartSizeOfTraceRsp = 12,	// OUI + command + cmd rsp + MAC + numOfSTA = 3+1+1+6+1= 12

		eMaxSTAInfoSizeOfGetTree =  1483, //CCMMENTRY::eMaxMmeData - eFixPartSizeOfGetTreeRsp = 1495-12
		eMaxSTAInfoSizeOfTrace =  1483, //CCMMENTRY::eMaxMmeData - eFixPartSizeOfTraceRsp = 1495-12

		eMaxNumOfSTAPerMMEOfGetTree = eMaxSTAInfoSizeOfGetTree/eSTAInfoSize, // 1483/9 = 164
		eMaxNumOfSTAPerMMEOfTrace = eMaxSTAInfoSizeOfTrace/eSTAInfoSize,//1483/9 = 164
	};

	__packed class GetTreeReqData
	{
	public:
		CCMACAddress	mRootMac;
	};

	__packed class GetTreeCnfData
	{
	public:
		CCMACAddress	mRootMac;
		uint8	mNumOfSTA;
		STAInfo	mSTAInfo[eMaxNumOfSTAPerMMEOfGetTree];
	};

	__packed class TraceReqData
	{
	public:
		CCMACAddress	mHstaMac;
	};

	__packed class TraceCnfData
	{
	public:
		CCMACAddress	mHstaMac;
		uint8	mNumOfSTA;
		STAInfo	mSTAInfo[eMaxNumOfSTAPerMMEOfTrace];
	};

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	    mOUI;			// OUI
		uint8					mCmd;			//command type
		__packed union UUSubCmdReqData
		{
			GetTreeReqData		mGetTree_ReqData;
			TraceReqData		mTrace_ReqData;
		} mSubCmdReqData;
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;				// OUI
		uint8					mCmd;				//command type
		uint8					mCmdRsp;			//command response result
		__packed union UUSubCmdCnfData
		{
			GetTreeCnfData		mGetTree_CnfData;
			TraceCnfData		mTrace_CnfData;
		} mSubCmdCnfData;
	};

	__packed union {
		Req	REQ;
		Cnf	CNF;
	};
};

//0xA400	VS_UART_CMD
__packed class VS_UART_CMD
{
public:
	enum {
		eMMType = 0x0400,					// VS_UART_CMD
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
	};

	enum {
		eMaxFrameSz = 1495,
		eOUISz = 3,
		eMaxDataSz = eMaxFrameSz - eOUISz - 6 - sizeof(uint16),		//1484
	};

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint16 mLength;
		uint8 mData[eMaxDataSz];
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8	mIsThereMoreMMEs;
		uint8	mTotalSegments;
		uint8	mSegmentIndex;
		uint8	mRsvd[3];
		uint16	mLength;
		uint8	mData[eMaxDataSz];
	};

	__packed union { Req REQ; Cnf CNF;};
};

//0xA404	VS_UART_CMD_BCAST, this MME doesn't need CNF, CNF will be VS_UART_CMD::Cnf
__packed class VS_UART_CMD_BCAST
{
public:
	enum {
		eMMType = 0x0404,					// VS_UART_CMD_BCAST
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
	};

	enum {
		eMaxFrameSz = 1495,
		eOUISz = 3,
		eMaxDataSz = eMaxFrameSz - eOUISz - cMACAddressSz - sizeof(uint16),		//1484
	};

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint16 mLength;
		uint8 mData[eMaxDataSz];
	};

	__packed union { Req REQ;};
};

//0xA408	VS_UART_CMD_EXTEND
__packed class VS_UART_CMD_EXTEND
{
public:
	enum {
		eMMType = 0x0408,
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
	};

	__packed class C3762CommandInfo
	{
	public:
		
		uint8	mControl;
		uint8	mResource[6];
		CCMACAddress	mSA;
		uint8	mAFN;
		uint8	mDT1;
		uint8	mDT2;
		uint8	mData0;
		uint8	mIsResponseOfReadStatusWords;
	};
	
	enum {
		eMaxFrameSz = 1495,
		eOUISz = 3,
		eMaxDataSz = eMaxFrameSz - eOUISz - 5 - sizeof(C3762CommandInfo) - sizeof(uint16)
	};
	
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8	m645Control;
		uint32	m645DI;
		C3762CommandInfo	m3762Info;
		uint16	mLength;
		uint8	mData[eMaxDataSz];
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		C3762CommandInfo		m3762Info;
		uint16	mLength;
		uint8	mData[eMaxDataSz];
	};

	__packed union { Req REQ; Cnf CNF;};
};

//0xA40c	VS_EJECT_STATION
__packed class VS_EJECT_STATION
{
public:
	enum {
		eMMType = 0x040c,
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
	};
	
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		CCMACAddress			mStationMAC;
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8				mStatus;
	};

	__packed union { Req REQ; Cnf CNF;};
};

//0xA414 VS_GET_PHASE
__packed class VS_GET_PHASE
{
public:
	enum 
	{
		eMMType = 0x0414,
		eMMTypeReq = eVS | eMMType | eReq, // .Req
		eMMTypeCnf = eVS | eMMType | eCnf, // .Cnf
		eMMTypeInd = eVS | eMMType | eInd  // .Ind
	};

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI mOUI; // OUI
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI mOUI; // OUI
		uint8 mPhaseStatus;
		uint8 mDiffInMillisecondsBetweenZCAndBP;
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA420	VS_SG_DEV_OP_INFO (REQ, CNF, IND, RSP )
__packed class VS_SG_DEV_OP_INFO
{
public:
	enum
	{
		eMMType = 0x0420,					// VS_SG_DEV_OP_INFO
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eMMTypeInd	= eVS | eMMType | eInd,	// .Ind
		eMMTypeRsp	= eVS | eMMType | eRsp	// .Rsp
	};

	enum {
		eMaxFrameSz = 79 - 12 - 5,
		eOUISz = 3,
		//eMaxMeterNum = ((eMaxFrameSz - eOUISz - 4)/cMACAddressSz),		//9
		eMaxMeterNum = 5
	};
	
	__packed class CCollectorReport
	{
	public:
		uint8		 mMeterNum;
		CCMACAddress mMeterID[eMaxMeterNum];
	};

	enum {
		eOP_GetDevInfo = 0x00,
		eOP_CollectorReport = 0x21,
		eOP_CollectorSearchAndReport = 0x22
	};

	enum
	{
		eDevType_NULL = 0x00,
		eDevType_SmartMeter = 0x10,
		eDevType_Collector_1 = 0x20,
		eDevType_Collector_2 = 0x21
	};
	enum
	{
		eDevStatus_Default = 0x00,
		eDevStatus_InvalidOperation = 0xFF,
		
		eDevStatus_Collector_NoSearch = 0x20,
		eDevStatus_Collector_Searching = 0x21,
		eDevStatus_Collector_Searched = 0x22
	};
	enum
	{
		eMaxMeterNumOfCollector = 32
	};
	
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8               mOP;
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8				mOP;
		uint8               mDevType;
		uint8               mStatus;
	};

	__packed class Ind
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8               mDevType;
		uint8               mIndNum;
		uint8               mIndIndex;
		CCollectorReport    mReport;
	};

	__packed class Rsp
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8               mDevType;
		uint8               mIndNum;
		uint8               mIndIndex;
	};

	__packed union { Req REQ; Cnf CNF; Ind IND; Rsp RSP; };
};

//0xA148	VS_ACCESS_LEVEL_CONTROL (REQ, CNF)
__packed class VS_ACCESS_LEVEL_CONTROL
//This MME is used by INT6000 bootloading, DO NOT change
{
public:
	enum {
		eMMType = 0x0148,					// VS_ACCESS_LEVEL_CONTROL
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf	// .Cnf
		
	};

	enum {
		eMaxDataSz = 1024,			
	  	eDAKKeyLength  = 16,
		eMaxKeyLength  = 16
	};

	enum {
		ePTSAccessLevel = 1,
		eDAKKeyAccessType = 1
	};

    //Retrun Codes
	enum {
        eSuccess            = 0,
        eInvalidKeyLength   = 1,
        eInvalidKey         = 2,
        eInvalidAccessType  = 3,
        eInvalidLevelontrol = 4    
        };

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint32			mReserved0;			// Reserved
		uint8			mLevelControl;		// Device Level Control
        uint16          mReserved1;         //Reserved 
        uint8           mAccessType;        //Access key type provided
        uint16          mReserved2;         //Reserved
        uint16          mKeyLength;         //Length of key provied 
		uint8			mKeyData[eMaxKeyLength];   // Key Data 
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint16			mReserved0;			// Reserved
		uint16			mResponseCode;	    // Success = 0
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA020	VS_WR_MOD (REQ, CNF)
__packed class VS_WR_MOD
{
public:
	enum {
		eMMType = 0x0020,					// VS_WR_MOD
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eMaxDataSz = 1024
	};
	enum { eSuccess = 0x00,
		   eInvalidModuleID = 0x10,
		   eInvalidLength = 0x12,
		   eInvalidChkSum = 0x14,
		   eInvalidOffset = 0x20,
		   eBlocked       = 0x40,
		   eFailToLockNVM       = 0x50 //Fail to lock NVM
		  };

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mModuleID;			// Module ID
		uint8			mRSVD;				// Reserved
		uint16			mLength;			// Length in bytes to transfer
		uint32			mOffset;			// Offset into Module
		uint32			mChkSum;			// Checksum
		uint8			mData[eMaxDataSz];	// Write Data
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
		uint8			mModuleID;			// Module ID
		uint8			mRSVD;				// Reserved
		uint16			mLength;			// Length in bytes to transferred
		uint32			mOffset;			// Offset into Module
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA024	VS_RD_MOD (REQ, CNF)
__packed class VS_RD_MOD
{
public:
	enum {
		eMMType = 0x0024,					// VS_RD_MOD
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eMaxDataSz = 1024 // bytes
	};
	enum { eSuccess = VS_WR_MOD::eSuccess,
		   eInvalidModuleID = VS_WR_MOD::eInvalidModuleID,
		   eInvalidLength = VS_WR_MOD::eInvalidLength,
		   eInvalidChkSum = VS_WR_MOD::eInvalidChkSum,
		   eInvalidOffset = VS_WR_MOD::eInvalidOffset,
		   eFailToLockNVM = VS_WR_MOD::eFailToLockNVM,
		   eNoFlash = 0x60
		  };

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mModuleID;			// Module ID
		uint8			mRSVD;				// Reserved
		uint16			mLength;			// Number of bytes to read
		uint32			mOffset;			// Offset into Module
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
		uint8			mRes1[3];			// Reserved
		uint8			mModuleID;			// Module ID
		uint8			mRSVD;				// reserved
		uint16			mLength;			// Number of bytes to read
		uint32			mOffset;			// Offset into Module
		uint32			mChkSum;			// Checksum
		uint8			mData[eMaxDataSz];	// Data
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA028	VS_MOD_NVM (REQ, CNF)
__packed class VS_MOD_NVM
{
public:
	enum {
		eMMType = 0x0028,					// VS_MOD_NVM
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf,	// .Cnf
		eMaxDataSz = 1024
	};
	enum NvmErrorCode{
        eSuccess =               0x00,
        eInvalidModId =          0x10,
        eNVMNotPresent =         0x14,
        eNVMTooSmall =           0x18,
        eNVMHdrChkSum =          0x1C,
        eNVMSecChkSum =          0x20,
	    eInvalidPIB  =           0x24,
        eSlTooLarge  =           0x28,
        eNVMfileTooLarge =       0x2C,
        eFwButNoPib =            0x42,
        eBadPibChecksum=         0x44,
        eDakMismatch =           0x46,
        eMacMismatch =           0x48,
        eMfgHfidMismatch =       0x50,
        eBadBindFacDef =         0x52,
        eBadBindTemplatePib =    0x54,
        eBadBindWorkingPib =     0x56,
        eErrorGenChecksumSPib =  0x58,
        eBadBindScratchPib =     0x5A,
        eNoFirmwareVersion =     0x5C,
        eVersionMismatch =       0x5E,
        eErrorGenChecksumWPib =  0x60,
        eInvalidFWVersion =      0x66,
        eUnsupportedOldFW =      0x68,
        eNoFirmware =		     0x6A,
        eNVMNoSpaceFor2FW =		 0x6C,
		eNoBoundParamBlock =     0x70		
    };
    typedef __packed struct _tOptionBitFields
    {
    	uint32	mbBit0							: 1;
		uint32	mLegacyFWUpgrade				: 1; // FW Upgrade replaces Factory PIB with Supplied PIB (legacy method)
    	uint32	mbReservedBits					: 30;
    } tOptionBitFields;
    typedef __packed union _uOptionBitFields
    {
    	tOptionBitFields	mOptionBitFields;
    	uint32				mUINT32_Word;
    } uOption;
    
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mModuleID;			// Module ID
		uOption			mOption; //Option Bit Fields
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
		uint8			mModuleID;			// Module ID
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xC002	VS_PRODUCT_TEST_MODE (REQ, CNF)
__packed class VS_PRODUCT_TEST_MODE
{
public:
	enum {
		eMMType = 0x0002,					// VS_PRODUCT_TEST_MODE
		eMMTypeReq	= eDB | eMMType | eReq,	// .Req
		eMMTypeCnf	= eDB | eMMType | eCnf,	// .Cnf
	};

	enum { eSuccess = 0x00, eFail = 0x01 };
	enum {
		eProductTestMode_LowGPIO = 0x00,
		eProductTestMode_HighGPIO = 0x01,
		eProductTestMode_Exit = 0x02,
	};
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8	mProductTestMode;
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8			mStatus;			// Success = 0
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xA07C	VS_FAC_DEFAULTS (REQ, CNF)
__packed class VS_FAC_DEFAULTS {
public:
	enum {
		eMMType = 0x007C,					// VS_FAC_DEFAULTS
		eMMTypeReq	= eVS | eMMType | eReq,	// .Req
		eMMTypeCnf	= eVS | eMMType | eCnf	// .Cnf
	};
	enum { 	eSuccess = 0x00, eFailure = 0x01, eFailToLockNVM = 0x2 };

	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		uint8				mStatus;		// Success = 0
	};

	__packed union { Req REQ; Cnf CNF; };
};

//0xF000	VS_Transparent (REQ, CNF)
__packed class VS_Transparent
{
public:
	enum {
		eMMType = 0x0000,					// VS_Transparent
		eMMTypeReq	= 0xF000 | eMMType | eReq,	// .Req
		eMMTypeCnf	= 0xF000 | eMMType | eCnf,	// .Cnf
	};

	enum { eSuccess = 0x00, eFail = 0x01 };
	__packed class Req
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
	};

	__packed class Cnf
	{
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		char			mDeviceIdentify[64];	// Device Identify String
	};
	
	__packed union { Req REQ; Cnf CNF; };
};

class CCMMENTRY
{
public:
	enum { 	eMaxMmeData = 1495 };//1518 - 23(Max MME header)

public:
	__packed union {					// MME Payloads
		VS_SW_VER					mVS_SW_VER;					// Get Device/SW version
		VS_RS_DEV					mVS_RS_DEV;					// Reset Device
		VS_FR_LBK					mVS_FR_LBK;					// Frame Multiple Loopback
		VS_NW_INFO_STATS			mVS_NW_INFO_STATS;			// Network Information & Statistics
		VS_MODULE_OPERATION		mVS_MODULE_OPERATION;		// Module Operation
		VS_AVLN_TOPO				mVS_AVLN_TOPO;			    // AVLN Topology MME
		VS_UART_CMD				mVS_UART_CMD;		        // UART command via MME
		VS_UART_CMD_BCAST			mVS_UART_CMD_BCAST;	        // UART command by broadcast
		VS_UART_CMD_EXTEND			mVS_UART_CMD_EXTEND;
		VS_EJECT_STATION			mVS_EJECT_STATION;
		VS_GET_PHASE				mVS_GET_PHASE;
		VS_SG_DEV_OP_INFO			mVS_SG_DEV_OP_INFO;
		VS_ACCESS_LEVEL_CONTROL	mVS_ACCESS_LEVEL_CONTROL;
		VS_WR_MOD					mVS_WR_MOD;
		VS_RD_MOD					mVS_RD_MOD;
		VS_MOD_NVM					mVS_MOD_NVM;
		VS_PRODUCT_TEST_MODE		mVS_PRODUCT_TEST_MODE;
		VS_FAC_DEFAULTS			mVS_FAC_DEFAULTS;
		VS_Transparent				mVS_Transparent;

		//max size
		uint8					mMaxSizeBuffer[eMaxMmeData];//1518 - 23(Max MME header)
	};
};
__packed class CCMMESubFrame_V0
{
public:
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
	CCMMENTRY		mMMEntry;			// MME Payloads

public:
	enum { eMMEHeaderSz = 17 };
};
__packed class CCMMESubFrame_V1
{
public:
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
	uint16			mFMI;				// FMI bits 0-3 and FN_MI bits 4-7 and FMSN bits 8-15
	CCMMENTRY		mMMEntry;			// MME Payloads

public:
	enum { eMMEHeaderSz = 19 };
};
__packed class CCMMESubFrame_VX
{
public:
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
};
__packed class CCMMESubFrame_V0_VLAN
{
public:
	uint8			mVLANTag[cVLANTagSz];//VLAN Tag
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
	CCMMENTRY		mMMEntry;			// MME Payloads

public:
	enum { eMMEHeaderSz = 21 };
};
__packed class CCMMESubFrame_V1_VLAN
{
public:
	uint8			mVLANTag[cVLANTagSz];//VLAN Tag
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
	uint16			mFMI;				// FMI bits 0-3 and FN_MI bits 4-7 and FMSN bits 8-15
	CCMMENTRY		mMMEntry;			// MME Payloads

public:
	enum { eMMEHeaderSz = 23 };
};
__packed class CCMMESubFrame_VX_VLAN
{
public:
	uint8			mVLANTag[cVLANTagSz];//VLAN Tag
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
};

/*0xA400:VS_Enable_ProductTest_Uart (REQ, CNF)*/
__packed class VS_Enable_ProductTest_Uart {
public:
	enum {
		eMMType = 0xA400,
		eMMTypeReq	= eVS | eMMType | eReq,
		eMMTypeCnf	= eVS | eMMType | eCnf
	};
	
	enum { eMMEHeaderSz = 17 };

public:
	uint16			mEtherType;			// IEEE-assigned Ethertype
	uint8			mMMV;				// MME version
	uint16			mMMTYPE;			// MME type
	
	__packed class Req {
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		bool mActionType;					//0:Disable;1:Enable
	};


	__packed class Cnf {
	public:
		CCMACAddress::CCOUI	mOUI;			// OUI
		bool mActionType;					//0:Disable;1:Enable
	};

	__packed union {
		Req REQ;
		Cnf CNF;
	};
};

__packed class CCMMEFrame
{
public:
	CCMACAddress	mODA;				// Original destination address
	CCMACAddress	mOSA;				// Original source address
	__packed union {
		CCMMESubFrame_V0		mRegular_V0;
		CCMMESubFrame_V1		mRegular_V1;
		CCMMESubFrame_V0_VLAN	mVLAN_V0;
		CCMMESubFrame_V1_VLAN	mVLAN_V1;
		CCMMESubFrame_VX		mGeneric_Reg;
		CCMMESubFrame_VX_VLAN	mGeneric_VLAN;
		VS_Enable_ProductTest_Uart mVS_Enable_ProductTest_Uart;
	};
};

#endif // MME_DEFINE_H
