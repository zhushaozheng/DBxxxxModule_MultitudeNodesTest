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

void Qt_printf_buffer(char *buff_name, uint8 *pbuff, uint32 buf_len)
{
    uint32 i;
      
    Qt_printf("%s: len = %d\n", buff_name, buf_len);
    
    Qt_printf("%s content:\n", buff_name);
    for (i = 0; i < buf_len; i++)
    {
        if ((i % 16) == 0)
        {
            Qt_printf("\n");
        }
        Qt_printf("%02x ", *(pbuff + i));
    }
    
    Qt_printf("\n\n");
    
    return;
}
