#include "module.h"
#include "global.h"

CCModule::CCModule()
{	
	start();
}

CCModule::~CCModule()
{
	exit();
}

void CCModule::run()
{
	while(1)
	{
		if (gwinpcap_application.IfChannelOpen()) {
			gwinpcap_application.DispatchAllPacketsInBuffer();
		}
	}
	
}