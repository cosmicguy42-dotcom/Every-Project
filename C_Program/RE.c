#include<stdio.h>

int main() 
{
    int tr = 0;
    int *ptr = &tr;
    char msg[] = "data";




    for (int i=0;msg[i]!='\0';i++) {
        if (msg[i] == 'a') {
            *ptr=1;
            break;
        }
        else { *ptr = 0;}
    }

    printf("number of 'a' in %s: %i", msg, tr);
    
    
    if (tr == 1) {printf("\n%s as an 'a' in it", msg); }
    else {printf("\n%s as not any 'a' in it", msg); }

    return 0;
}




