#include <QDebug>
#include "Qt_common_api.h"

int Qt_printf(const char *apFormat, ...)
{
	char vBuffer[500];
	int i = 0;
	va_list vList;
	
	va_start(vList, apFormat);
	i = vsprintf(vBuffer, apFormat, vList);
	va_end(vList);
	
	qDebug() << vBuffer;
	
	return i;
}
