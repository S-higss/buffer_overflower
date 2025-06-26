#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void function2() {
    printf("Function 2 called!\n");
    exit(0); // Exit the program
}

void function1(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("Function 1 returned normally\n");
}

int main() {
    char input[100];
    printf("Enter input: ");
    scanf("%s", input);
    function1(input);
    return 0;
}
