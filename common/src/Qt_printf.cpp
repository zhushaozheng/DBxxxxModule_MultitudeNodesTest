#include <QDebug>
#include "Qt_common_api.h"

/*
Function name:Qt_printf.
Function prototype:int printf (char * format,args, ...).
Function:printf chars to output device based on format. 
Return:Num of char that printf;return negative when error. 
Details:format can a string or the address of one string.
*/
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
