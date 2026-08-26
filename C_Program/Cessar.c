#include <stdio.h>

int main(void)
{
    char msg[] = "abc";

    for (int i=0; msg[i] != '\0'; i++) 
    {
        msg[i] = msg[i]+1; 
    } 
    printf("%s\n", msg);
    return 0;
}