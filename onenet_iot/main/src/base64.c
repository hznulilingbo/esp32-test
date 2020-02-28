#include <stdio.h>
#include <string.h>
#include "base64.h"

unsigned char base64_encode(unsigned char *str, unsigned char *res)
{
    long len;
    long str_len;
    int i,j;
//定义base64编码表
    char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//计算经过base64编码后的字符串长度
    str_len=strlen((char *)str);
    if(str_len % 3 == 0)
        len=str_len/3*4;
    else
        len=(str_len/3+1)*4;

    if(len >= strlen((char *)res))
    {
        return 1;
    }
    res[len]='\0';

//以3个8位字符为一组进行编码
    for(i=0,j=0;i<len-2;j+=3,i+=4)
    {
        res[i]=base64_table[str[j]>>2];
		//取出第一个字符的前6位并找出对应的结果字符
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)];
		//将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)];
		//将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
        res[i+3]=base64_table[str[j+2]&0x3f];
    }

    switch(str_len % 3)
    {
        case 1:
            res[i-2]='=';
            res[i-1]='=';
            break;
        case 2:
            res[i-1]='=';
            break;
    }

    return 0;
}
