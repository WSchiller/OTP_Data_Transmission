/*******************************************************************************
** Description: The otp_enc program acts on behalf of the client, accepting
*               a message and a key. Otp_enc will connect to the listening port
*               on the otp_enc_d daemon which acts as the server.  A
*               communication socket is created between server and client.
*               Otp_enc will send an authentication token to server that must
*               to be verified prior to any other data transmission can take
*               place.  Once the client is verified, otp_enc will send the
*               message and key to the otp_enc_d daemon (server) for
*               encryption. The message and key must only contain uppercase
*               letters, spaces, and a trailing newline or the program will
*               exit. The ciphertext is returned to the client.
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>

#define MAXSENDSIZE 1000
#define MAXSIZE 72000
#define h_addr h_addr_list[0]


// Print error message
void error(const char *msg) { 
   perror(msg); 
   exit(0); 
} 

// Receive ciphertext from server, reply with ACK
void receiveMessage(int communicationFD, char* buffer) {
    bool newlineFound = false;
    char tempBuffer[1001];
    int totalBytesRead = 0;
    bool firstPass = true;

    while(!newlineFound) {
        int numBytesRead = recv(communicationFD, tempBuffer, sizeof(tempBuffer), 0);
        totalBytesRead += numBytesRead;  
	// Read until no bytes left in transmission
        if (numBytesRead > 0) {
           for (int i = 0; i < numBytesRead; i++) {
                char c = tempBuffer[i];
                if (c == '*') {
                        tempBuffer[i] = '\0';
                        newlineFound = true;
                        break;
                }
           }
           strcat(buffer, tempBuffer);  
        }
        send(communicationFD, "Client has received message\n", 28 , 0);  // ack
    }
}

// Send plaintext to server
void sendMessage(int socketFD, char* buffer, int msgLength) {
   int curMsgLength, charsRead;
   int charsWritten = 0;
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
		strncpy(tempBuffer, buffer + charsWritten, charsRemaining);
		tempBuffer[charsRemaining] = '*'; 
	}
   	curMsgLength = strlen(tempBuffer);	
	charsWritten += send(socketFD, tempBuffer, curMsgLength, 0); 
	charsRead = recv(socketFD, ackBuffer, sizeof(ackBuffer), 0);
	charsRemaining = msgLength - charsWritten;
   }
}

void authenticationHandshake(int socketFD, int portNumber) {
   char clientToken[] = "redWolf7";
   int charsWritten, charsRead;
   char buffer[100];

   memset(buffer, '\0', sizeof(buffer));  
   
   // Send client token to server.  Ensure we can send on socket.
   charsWritten = send(socketFD, clientToken, sizeof(clientToken), 0);
   if (charsWritten < 0) error("CLIENT: ERROR writing to socket");

   // Receive authentication result from server.  Ensure we can receive on socket.
   charsRead = recv(socketFD, buffer, sizeof(buffer), 0);	
   if (charsRead < 0) error("CLIENT: ERROR reading from socket");

   if (strcmp (buffer, "success") != 0) {
	fprintf(stderr, "401 Unauthorized! Unable to connect on port %d\n", portNumber); // Invalid token
	exit(2);
   }
}

int createSocket(int portNumber) {
   struct sockaddr_in serverAddress;  // IPv4 address family, server address/info
   struct hostent* serverHostInfo;  // Entry to host, host info 
	
   // Set up the server address struct
   memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
   serverAddress.sin_family = AF_INET; // Create a network-capable socket
   serverAddress.sin_port = htons(portNumber); // Store the clinets port number

   // Set up host
   serverHostInfo = gethostbyname("localhost"); // loopback to another process on the local system
   if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }  // Error connecting to localhost
   memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the host address to server

   // Create Socket. 1. AF_INET: IP address family. 2. SOCK_STREAM: reliable 2-way connection based byte streams  
   int socketFD = socket(AF_INET, SOCK_STREAM, 0);
   if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
   // Connect to server
   if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

   return socketFD;
}

int main(int argc, char *argv[])
{
	int i, socketFD, portNumber, charsWritten, charsRead;
	int plaintext_fd, plaintextLength;
	char plaintextBuffer[MAXSIZE];
	ssize_t ret_plaintext;  // Number of bytes returned by read() plaintext file
	int key_fd, keyLength;
	char keyBuffer[MAXSIZE];
	ssize_t ret_key;  // Number of bytes returned by read() key file
    
	// Check correct number of arguments were passed in
	// Argument # - 1.Program Name, 2. Plaintext, 3. Key, 4. Encryped port #
	if (argc != 4) { fprintf(stderr,"USAGE: %s otp_enc plaintext key port\n", argv[0]); exit(0); } // Check usage & args

	// Attempt to establish connection with server
	portNumber = atoi(argv[3]); // Get the clients port number
	socketFD = createSocket(portNumber);
	
	// Client/Server authentication handshake.
	authenticationHandshake(socketFD, portNumber);

	// Get and Open plaintext file
	plaintext_fd = open(argv[1], O_RDONLY);
	
	// Failed to open file
	if (plaintext_fd < 0) {
		perror("Failed to open file!");
		exit(1);
	}
	memset(plaintextBuffer, '\0', MAXSIZE);  	
	ret_plaintext = read(plaintext_fd, plaintextBuffer, sizeof(plaintextBuffer)); 
	plaintextLength = strlen(plaintextBuffer);  

	// Check plaintext buffer to ensure all characters are valid
	for (i =0; i < plaintextLength; i++) { 
		if ((!isupper(plaintextBuffer[i])) && (!isspace(plaintextBuffer[i])) && (plaintextBuffer[i] != '\n')) {
			fprintf(stderr, "Invalid character(s) found in %s file!\n", argv[1]);
			exit(1);
		}
	}
	
	// Open generated key file
	key_fd = open(argv[2], O_RDONLY);
	
	// Failed to open file
	if (key_fd < 0) {
		perror("Failed to open file!");
		exit(1);
	}
	memset(keyBuffer, '\0', MAXSIZE);  	
	ret_key = read(key_fd, keyBuffer, sizeof(keyBuffer));  
	keyLength = strlen(keyBuffer);  

	// Check key buffer to ensure all characters are valid
	for (i =0; i < keyLength; i++) { 	
		if ((!isupper(keyBuffer[i])) && (!isspace(keyBuffer[i])) && (keyBuffer[i] != '\n')) {
			fprintf(stderr, "Invalid character found in key!");
			exit(1);
		}
	}

	// Compare length of plaintext and key
	if (plaintextLength > keyLength) {
		fprintf(stderr, "Error! Key length less than plaintext length!");
		exit(1);
	}

	sendMessage(socketFD, plaintextBuffer, plaintextLength);
   	sendMessage(socketFD, keyBuffer, keyLength);
    
	// Receive Cipher Text
	char ciphertext[plaintextLength + 1];
	
	memset(ciphertext, '\0', sizeof(ciphertext));
	receiveMessage(socketFD, ciphertext); 	
	int ciphertextLength = strlen(ciphertext);

	// Print ciphertext to stdout
	for(i = 0; i < ciphertextLength; i++) {
		if (ciphertext[i] == '[') {
			ciphertext[i] = ' '; // Change bracket back to space
		}
		printf("%c", ciphertext[i]);
	}
       printf("\n");
 
   close(socketFD);
	
   return 0;
}
