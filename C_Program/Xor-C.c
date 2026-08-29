#include<stdio.h> 
#include <string.h>

void main() 
{
    char key[] = {0x04, 0x4F, 0x81, 0xAB, 0xFE, 0x7B, 0xE0, 0xCC, 0x46, 0x35, 0xEE};
    char msg[] = "AAAAAA";

int scr = 0;
    
    int keylen = strlen(key);
    int msglen = strlen(msg);
    
    for (int i=0;i<msglen;i++) 
    {
        scr = scr + (msg[i] ^ key[i]);
    } 
    printf("Encrypt: %s", msg);
    printf("\nScore for the crackme: %d", scr);





}