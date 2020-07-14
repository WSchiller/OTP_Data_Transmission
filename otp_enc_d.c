/*******************************************************************************
** Program 4: otp_enc_d
** Description: The otp_enc_d program acts as a server on local host accepting
**              a plaintext message and a key. Otp_enc_d set up a listener on a 
**		specified port waiting for connections, up to 5. A 
**		communication socket is created between server and client.
**              Otp_enc_d will receive an authentication token from client that 
**	        must be verified prior to any other data transmission can take
**              place.  Once the client is verified, otp_enc_d will receive the
**              for encryption  The ciphertext is returned to the client.
**                                                                                                                                                               
** Date Last Modified: March 17, 2019
** Author: Wesley Schiller
*********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define MAXSIZE 72000


//------------------------------------------------------------------------------
// Function:    error(const char *msg)
// Parameter:
//     In:      msg - char pointer to a message with error description
//     Out:     none
//
// Returns:     none
//
// Desc:        Displays description of an error message before successfully
//              exiting the program.
//------------------------------------------------------------------------------
void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues


//------------------------------------------------------------------------------
// Function:    sendMessage(int socketFD, char* buffer, int msgLength)
// Parameter:
//     In:      socketFD - file descriptor of socket where transmission
//              will be received.
//              buffer - char pointer to buffer that contains message
//              msgLength - number of chars in message
//
//     Out:     none
//
// Returns:     none
//
// Desc:        Sends the encrypted ciphertext back to client.
//-------------------------------------------------------------------------------
void sendMessage(int socketFD, char* buffer, int msgLength) {
   int curMsgLength, charsRead;
   int charsWritten = 0;
   // printf("Message length: %d\n", msgLength);
   int charsRemaining = msgLength;
   bool firstPass = true;


   char ackBuffer[100];
   memset(ackBuffer, '\0', 100);

   while(charsWritten < msgLength) {
        char tempBuffer[1001];
        memset(tempBuffer, '\0', sizeof(tempBuffer));
        if ((firstPass) && (charsRemaining > 1000)) {
                strncpy(tempBuffer, buffer, 1000);
                firstPass = false;
        }
        else if (charsRemaining > 1000) {
                strncpy(tempBuffer, buffer + charsWritten, 1000);
        }
        else {
                strncpy(tempBuffer, buffer + charsWritten, charsRemaining);//strcat(tempBuffer,
                tempBuffer[charsRemaining - 1] = '*';  // Delimiter to specify end of message
         //       printf("* appended to end of message\n");
        }
        curMsgLength = strlen(tempBuffer);
       // printf("%s\n", tempBuffer);
       // printf("Chars Written: %d\n", charsWritten);

        charsWritten += send(socketFD, tempBuffer, curMsgLength, 0);
        charsRead = recv(socketFD, ackBuffer, sizeof(ackBuffer), 0);

        //printf("Chars Read: %d\n", charsRead);
        //printf("ACK Buffer: %s\n", ackBuffer);
        charsRemaining = msgLength - charsWritten;
        //printf("Charms Remaining %d\n", charsRemaining);
   }
}


//------------------------------------------------------------------------------
// Function:    receiveMessage(int communicationFD, char* buffer)
// Parameter:
//     In:      communicationFD - file descriptor of socket where transmission
//              will be received.
//              buffer - char pointer to buffer for storage
//
//	Out:     none
//
// Returns:     none
//
// Desc:        Receives the plaintext and key from client storing into buffer.  
// 		Breaks from receiving transmission when a * is found.  Sends
//              acknowledgment of reception to client.
//-------------------------------------------------------------------------------
void receiveMessage(int communicationFD, char* buffer) {
    bool newlineFound = false;
    char tempBuffer[1001];
    int totalBytesRead = 0;
    bool firstPass = true;
    
    while(!newlineFound) {
    // printf("Before received total bytes %d\n", totalBytesRead);
    	int numBytesRead = recv(communicationFD, tempBuffer, sizeof(tempBuffer), 0);
    // printf("Num bytes read %d\n", numBytesRead);
    // printf("Temp Buffer: %s\n", tempBuffer);
	totalBytesRead += numBytesRead;
    	if (numBytesRead > 0) {	
	   for (int i=0; i<numBytesRead; i++) {
		char c = tempBuffer[i];
		if (c == '*') {
			// printf("* End of message!\n");
			tempBuffer[i] = '\0';
			newlineFound = true;
			break;
		}
   	   }	   
	   strcat(buffer, tempBuffer);   
	}	

	send(communicationFD, "Server has received message\n", 28, 0);
    }
}

//------------------------------------------------------------------------------
// Function:    generateCipherText(int communicationFD)
// Parameter:
//     In:      communicationFD - file descriptor of socket where transmission
//              will be received.
//     
//     Out:     ciphertext buffer 
//
// Returns:     none
//
// Desc:        Encrypts the plaintext message with key using cipher algorithm.
// 		Sends the ciphertext to the client.
//-------------------------------------------------------------------------------
//
void generateCipherText(int communicationFD) {
   char plaintextBuffer[MAXSIZE], keyBuffer[MAXSIZE];
   int plaintextLength;
   // Clear buffers
   memset(plaintextBuffer, '\0', MAXSIZE);
   memset(keyBuffer, '\0', MAXSIZE);

   // Receive plaintext message and key
   receiveMessage(communicationFD, plaintextBuffer);
   receiveMessage(communicationFD, keyBuffer);
   plaintextLength = strlen(plaintextBuffer);

   int temp1, temp2;
   int ciphertextInt;
   char ciphertext[plaintextLength];
   memset(ciphertext, '\0', sizeof(ciphertext));

   // Generate Ciphertext
   for (int i = 0; i < plaintextLength; i++ ) {
	// If space is found, revert to ASCII DEC 91 character
	if (plaintextBuffer[i] == ' ') {
		plaintextBuffer[i] = (char) 91;
	}
	if (keyBuffer[i] == ' ') {
		keyBuffer[i] = (char) 91;
	}
	// Convert ASCII to 0 - 26 values.  0 = A, ' ' = 26	
	temp1  = (int)plaintextBuffer[i] - 65;
	temp2 = (int)keyBuffer[i] - 65;

	// Cipher formula.  Add message and key, then modulus by size of character bank
        ciphertextInt = (temp1 + temp2) % 27;
	ciphertext[i] = (char)(ciphertextInt + 65);
   }

   sendMessage(communicationFD, ciphertext, strlen(ciphertext));
}

//------------------------------------------------------------------------------
// Function:    int createListener(int portNumber)
// Parameter:
//     In:      portNumber - port server will be listening on for connections.
//
//     Out:     
//
// Returns:     file descriptor number of the listening socket
//
// Desc:        Creates a listener on a specified port that can accept up to
// 		5 incoming connections.
//-------------------------------------------------------------------------------
int createListener(int portNumber) {
   struct sockaddr_in serverAddress;

   // Set up the address struct for the server
   memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
   serverAddress.sin_family = AF_INET; // Create a network-capable socket
   serverAddress.sin_port = htons(portNumber); // Store the port number
   serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

   // Set up the socket
   int listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket.  IPv4 family and reliable 2-way byte streaming	
   if (listenSocketFD < 0) {
	error("ERROR opening socket");
   }

   // Enable the socket to begin listening.  Bind server address file to socket stored in file descriptor
   if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) { 
   	error("ERROR on binding");
   }
	
   listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections at a time
   
   return listenSocketFD;
}

int main(int argc, char *argv[])
{
   struct sockaddr_in clientAddress;
   int listenSocketFD, establishedConnectionFD, portNumber, charsRead, charsWritten;
   socklen_t sizeOfClientInfo;
   char clientToken[100];
   int pid;
   char verifyClientToken[] = "redWolf7";

   // Check usage & args
   if (argc < 2) { 
	fprintf(stderr,"USAGE: %s port\n", argv[0]);
	 exit(1); 
   } 

   // Set up listening port on client server to take in client requests
   portNumber = atoi(argv[1]); // Get the port number from arguments, convert to an integer from a string
   listenSocketFD = createListener(portNumber);

   // Loop for incoming connection request.  Up to 5 active connections at a time
   while(1) {
	// Accept a connection, blocking if one is not available until one connects
	sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		
	// Connection made to listening port.  Generate socket for communication between server/client
	establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); 
       		
	// Failed to establish connection
	if (establishedConnectionFD < 0) {
		error("ERROR on accept");
	}

	// Connection established, create child process
	pid = fork();
	switch(pid) {
		// (-1) error creating child process
		case -1:
			perror("Hull Breach!");
			exit(1);

		// Child created successfully 
		case 0:	
   			memset(clientToken, '\0', sizeof(clientToken));  // clear buffer
   			charsRead = recv(establishedConnectionFD, clientToken, sizeof(clientToken), 0);  // receive authentication token from client
	
			if (charsRead < 0) error("ERROR reading from socket");

   			// Verify authentication token
   			if (strcmp(clientToken, verifyClientToken) != 0) {
				charsWritten = send(establishedConnectionFD, "failed", 6, 0); // Send failed token message to client 
			}
			else {
				charsWritten = send(establishedConnectionFD, "success", 7, 0);  // Send success token message to client		
			}
			if (charsWritten < 0) error("ERROR writing to socket");

			generateCipherText(establishedConnectionFD);
			exit(0);
			break;
	}
   	close(establishedConnectionFD); // Close the ecommunication socket
   }
 
   close(listenSocketFD); // Session finished.  Close the listener
	
   return 0; 
}
