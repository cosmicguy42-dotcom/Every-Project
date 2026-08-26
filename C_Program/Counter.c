#include <stdio.h>


int main(void)
{
    char txt[] = "hallamaaaaaaaaaaaaaaaaaaaaaaaaaaamm";
    int a = 0;
    int *pa = &a; 

    for (int i=0; txt[i] != '\0'; i++) 
    {
        if (txt[i] == 'a') { *pa += 1; }
        else { *pa+=0; }

    }

    printf("%d", a);

    return 0;
}