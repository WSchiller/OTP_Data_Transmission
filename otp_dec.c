/*******************************************************************************
** Description: The otp_dec program acts on behalf of the client, accepting
*               ciphertext and a key. Otp_enc will connect to the listening port
*               on the otp_dec_d daemon which acts as the server.  A
*               communication socket is created between server and client.
*               Otp_dec will send an authentication token to server that must
*               to be verified prior to any other data transmission can take
*               place.  Once the client is verified, otp_dec will send the
*               ciphertext and key to the otp_enc_d daemon (server) for
*               decryption. The message and key must only contain uppercase
*               letters, spaces, and a trailing newline or the program will
*               exit. The plaintext message is returned to the client.                                                                                                                                                           
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

// Receive plaintext and send ACK to server
void receiveMessage(int communicationFD, char* buffer) {
   bool newlineFound = false;
   char tempBuffer[1001];
   int totalBytesRead = 0;
   bool firstPass = true;

   while(!newlineFound) {
   	memset(tempBuffer, '\0', sizeof(tempBuffer));	       
        int numBytesRead = recv(communicationFD, tempBuffer, sizeof(tempBuffer), 0);
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

        send(communicationFD, "Client has received message\n", 28 , 0);
    }
}


// Sends key and ciphertext to server
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
		strncpy(tempBuffer, buffer + charsWritten, charsRemaining);  // Copy current transmission cycle into the temp buffer 
		tempBuffer[charsRemaining] = '*';  // Delimiter to specify end of message
	}
   	curMsgLength = strlen(tempBuffer);
	charsWritten += send(socketFD, tempBuffer, curMsgLength, 0); 
	charsRead = recv(socketFD, ackBuffer, sizeof(ackBuffer), 0);
	charsRemaining = msgLength - charsWritten;
   }
}

// Send authentication token to server
void authenticationHandshake(int socketFD, int portNumber) {
   char clientToken[] = "jambalaya";
   int charsWritten, charsRead;
   char buffer[100];

   memset(buffer, '\0', sizeof(buffer));  // clear buffer
   
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

// Attempt to connect to listening port on server
int createSocket(int portNumber) {
   struct sockaddr_in serverAddress;  // IPv4 address family
   struct hostent* serverHostInfo;  // Entry to host 
	
   // Set up the server address struct
   memset((char*)&serverAddress, '\0', sizeof(serverAddress)); 
   serverAddress.sin_family = AF_INET; // Create a network-capable socket
   serverAddress.sin_port = htons(portNumber); // Store the clients port number

   // Set up host
   serverHostInfo = gethostbyname("localhost"); // loopback to another process on the local system
   if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }  
   memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the host address to server

   // Create Socket. 1. AF_INET: IP address family. 2. SOCK_STREAM: reliable 2-way connection based byte streams  
   int socketFD = socket(AF_INET, SOCK_STREAM, 0);
   if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
   // Connect to server
   if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
		error("CLIENT: ERROR connecting");

   return socketFD;
}

int main(int argc, char *argv[])
{
   int i, socketFD, portNumber, charsWritten, charsRead;
   int ciphertext_fd, ciphertextLength;
   char ciphertextBuffer[MAXSIZE];
   ssize_t ret_ciphertext;  // Number of bytes returned by read() ciphertext file
   int key_fd, keyLength;
   char keyBuffer[MAXSIZE];
   ssize_t ret_key;  // Number of bytes returned by read() key file
    
   // Check correct number of arguments were passed in
   // Argument # - 1.Program Name, 2. Ciphertext, 3. Key, 4. Listening Port #
   if (argc != 4) { fprintf(stderr,"USAGE: %s otp_enc plaintext key port\n", argv[0]); exit(0); } // Check usage & args

   // Attempt to establish connection with server
   portNumber = atoi(argv[3]); // Get port number
   socketFD = createSocket(portNumber);
	
   // Client/Server authentication handshake.
   authenticationHandshake(socketFD, portNumber);

   // Get and Open ciphertext file
   ciphertext_fd = open(argv[1], O_RDONLY);
	
   if (ciphertext_fd < 0) {
	perror("Failed to open file!");
	exit(1);
   }
   memset(ciphertextBuffer, '\0', MAXSIZE); 	
   ret_ciphertext = read(ciphertext_fd, ciphertextBuffer, sizeof(ciphertextBuffer));  
   ciphertextLength = strlen(ciphertextBuffer); 
	
   // Open generated key file
   key_fd = open(argv[2], O_RDONLY);
	
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

   // Compare length of ciphertext and key
   if (ciphertextLength > keyLength) {
	fprintf(stderr, "Error! Key length less than plaintext length!");
	exit(1);
   }

   // Send ciphertext and key to daemon for decyrption
   sendMessage(socketFD, ciphertextBuffer, ciphertextLength);
   sendMessage(socketFD, keyBuffer, keyLength);
    
   // Receive plaintext
   char plaintext[ciphertextLength + 1];
   memset(plaintext, '\0', sizeof(plaintext));
   receiveMessage(socketFD, plaintext); 	
   int plaintextLength = strlen(plaintext);

   // Print plaintext to stdout
   for(i = 0; i < plaintextLength; i++) {
	if (plaintext[i] == '[') {
		plaintext[i] = ' '; 
	}
	printf("%c", plaintext[i]);
   }
   printf("\n");
 
   close(socketFD);
	
   return 0;
}
