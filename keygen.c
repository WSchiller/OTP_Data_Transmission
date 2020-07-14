/*******************************************************************************
** OTP: key generator 
** Description: The keygen program produces a key of a specified length from the 
		command line argument. The key can contain random uppercase 
		letters and a space character. Each character is printed to
		stdout, one by one until end of key length where a newline 
		completes the key.
*******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {	
   // Check at least 2 arguments were passed from command line
   if (argc < 2) {
	fprintf(stderr, "Too few arguments!");  // Print error message to stderr
	exit(0);  // Terminate program successfully
   }
 
   srand(time(NULL));  // Seed random number generator
   char capLetter;  //  The random capital letter generated or space
	
   // Convert C-string to integer	
   int keyLength = atoi(argv[1]);  // keyLength specified from argument 1 on command line

   for (int i = 0; i < keyLength; i++) {
   	// Generate random capital letters A - Z using ASCII
	// Uppercase alphabet is 65 - 90.  See below for 91
	capLetter = 0;  // initialize and reset
	capLetter = 65 + (rand() % 27 );
		
	// Substitute ASCII decimal 91 with space character 32
	if (capLetter == 91) {
		capLetter = 32;
	}
		
	printf("%c", capLetter);  // Print character to stdout
   }

   printf("\n"); 

   return 0;
}
