#include<stdio.h>

int main()
{
    // MAX = 2147483647;
    int finder = 577787471;
    int tf = 0;

    int *ptf = &tf;

    if (finder < 0){printf("Chose a number positif");
        *ptf+=1;}
    else if (finder == 0){printf("Chose a number different than 0");
        *ptf+=1;}

    if (tf < 1) {
        for (int i=0;i<=10;i++) 
        {
            if (i != 0 && i != 1 && i != finder){
                if (finder % i == 0) 
                {
                    printf("\n%i is not a prime number\n", finder);
                    *ptf += 1;
                    break;
                }
            }
        }
        if (tf < 1){printf("\n%i is a prime\n", finder);}
    }

    printf("\n");
}


