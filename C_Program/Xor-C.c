#include<stdio.h> 
#include <string.h>

void main() 
{
    char key[] = "hi";
    char msg[] = "msghi_starling";

    int keylen = strlen(key);
    int msglen = strlen(msg);
    
    for (int i=0;i<msglen;i++) 
    {
        msg[i] = msg[i] ^ key[i % keylen];
    } printf("Encrypt: %s", msg);

    for (int i=0;i<msglen;i++) 
    {
        msg[i] = msg[i] ^ key[i % keylen];
    } printf("\nDecrypt: %s", msg);
}