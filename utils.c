#include "utils.h"
#include <stdio.h>


void hex_dump(unsigned char *addres, unsigned int len)
{
printf("[0]\t");
for(int i=0;i<len;i++)
{
printf("%02x  ",addres[i]);
if((i+1)%8==0)
{
if((i+1)%16==0)printf("\n[+%d]\t",i+1);
else printf("    ");
}

}
printf("\n");
}


void print_binary(unsigned int v) {
    unsigned int mask = ~(~(unsigned int) 0 >> 1U);
    while (mask) {
        putchar('0'+!!(v&mask));
        mask >>= 1U;
    }
    putchar('\n');
}
