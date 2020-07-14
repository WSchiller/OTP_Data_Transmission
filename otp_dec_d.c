/*******************************************************************************
** Description: The otp_dec_d program acts as a server on local host accepting
**              a ciphertext message and a key. Otp_dec_d set up a listener on a
**              specified port waiting for connections, up to 5. A
**              communication socket is created between server and client.
**              Otp_dec_d will receive an authentication token from client that
**              must be verified prior to any other data transmission can take
**              place.  Once the client is verified, otp_dec_d will receive the
**              msg for decryption. The ciphertext is returned to the client.
**
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define MAXSIZE 72000
#define MAXSENDSIZE 1000


// Display error message
void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

// Send plaintext to client
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
        if ((firstPass) && (charsRemaining > MAXSENDSIZE)) {
                strncpy(tempBuffer, buffer, MAXSENDSIZE);
                firstPass = false;
        }
        else if (charsRemaining > MAXSENDSIZE) {
                strncpy(tempBuffer, buffer + charsWritten, MAXSENDSIZE);
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

// Receive key and ciphertext from client
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

// Decrypt ciphertext
void generatePlaintext(int communicationFD) {
   
   char ciphertextBuffer[MAXSIZE], keyBuffer[MAXSIZE];
   int ciphertextLength;
   // Clear buffers
   memset(ciphertextBuffer, '\0', MAXSIZE);
   memset(keyBuffer, '\0', MAXSIZE);

   // Receive plaintext message and key
   receiveMessage(communicationFD, ciphertextBuffer);
   receiveMessage(communicationFD, keyBuffer);
   ciphertextLength = strlen(ciphertextBuffer);

   int temp1, temp2;
   int plaintextInt;
   char plaintext[ciphertextLength];
   memset(plaintext, '\0', sizeof(plaintext));

    // Generate Plaintext
    for (int i = 0; i < ciphertextLength; i++ ) {
    // Convert ASCII to 0 - 26 values.  0 = A, ' ' = 26
    //	printf("Before %d  ",(int)ciphertextBuffer[i]);
    	if (ciphertextBuffer[i] == ' ') {
        	temp1 = 91;
     	}
        else {
  		temp1  = (int)ciphertextBuffer[i];
 	}

        if (keyBuffer[i] == ' ') {
   		temp2 = 91;                                                                                     
   	}
	else {
   		temp2 = (int)keyBuffer[i];
 	}
   
	// Decryption formula.   Subtract message and key, then modulus by size of character bank
        // printf("cipher: %d key: %d ", temp1, temp2);
   	plaintextInt = (((temp1 - temp2) % 27) + 27) % 27;
        // printf(" Plaintext: %d ", plaintextInt);
   	plaintext[i] = plaintextInt + 65; // Store value
        // printf("After %d  ", (int)plaintext[i]);
    }
   																									
   	sendMessage(communicationFD, plaintext, strlen(plaintext));   
}

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
   char verifyClientToken[] = "jambalaya";

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

			generatePlaintext(establishedConnectionFD);
			exit(0);
			break;
	}
   	close(establishedConnectionFD); // Close the ecommunication socket
   }
 
   close(listenSocketFD); // Session finished.  Close the listener
	
   return 0; 
}
