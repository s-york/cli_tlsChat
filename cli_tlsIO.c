#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "encrypt.c" //TLS stuff

#define BUFF 4096

typedef struct mbuffer{
	char owner[INET_ADDRSTRLEN];
	char buffer[BUFF];
	FILE *dl;
	struct mbuffer *next;
}mbuffer;

typedef struct connectargs{
		char addr[32];
		char port[6];
		struct connectargs *next;
}connectargs;

int * startServer(void){
	static int passivesock=0, *livesockref=&passivesock;
	int sockfd=0, opt=1, status=0;
	struct tls *CTXR=NULL;
	//init address:port details for our server
	struct addrinfo hints, *result;
	char myhost[INET_ADDRSTRLEN];
	gethostname(myhost, strlen(myhost));
	memset(&hints,0,sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE; //use local host address
		if((status = getaddrinfo(NULL, "1776", &hints, &result)) != 0){
			fprintf(stderr,"getaddrinfo error: %s\n",gai_strerror(status));
		}
	//make socket to use with our server
	sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if(sockfd < 0){
		fprintf(stderr, "Couldn't make server socket:%d:%s\n",errno,strerror(errno));
	}
	if((status = setsockopt(sockfd,SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)){
		fprintf(stderr, "Couldn't set socket options: %d:%s\n",errno,strerror(errno));
	}
	//associate ^^this address and port details with this\/ socket
	bind(sockfd, result->ai_addr, result->ai_addrlen);
	if(sockfd < 0){
		fprintf(stderr, "Couldnt bind server socket:%d:%s\n",errno,strerror(errno));
		perror("ERROR");
	}
	//set the socket to listening with a Q of 5
	if((listen(sockfd,5)) == -1){
		fprintf(stderr, "Setting server Socket to listening failed%d:%s\n",errno,strerror(errno));
	}else{fprintf(stdout,"Started server on %s.\n\n",myhost);

	if((status = TLS_Config_Server(CTXR))==-1){
			exit(-1);
	}
		//wait for connection
		for(;;){
			//accept incoming connections (blocking until connection is made).
			if((passivesock = accept(sockfd, result->ai_addr, &result->ai_addrlen))<0){
				fprintf(stderr,"failed to accept connection %d:%s\n",errno,strerror(errno));
			}
			//shutdown(passivesock,2);
			//close(passivesock);
		}
	}
	freeaddrinfo(result);
return(livesockref);
}
//set name of message

//Connect to remote server
int * connectToServer(const connectargs *args){
	static int sockfd, *livesockref=&sockfd;
	struct addrinfo hints, *postPacked;
	struct sockaddr_storage hostList;
	int state=0;
		memset(&hostList, 0, sizeof(hostList));
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
			getaddrinfo(args->addr, args->port, &hints, &postPacked);
	if((sockfd = socket(postPacked->ai_family,postPacked->ai_socktype,postPacked->ai_protocol))<0){
		fprintf(stderr,"init connect socket failed %d:%s\n",errno,strerror(errno));
		exit(-1);
	} else if((state = connect(sockfd, postPacked->ai_addr, postPacked->ai_addrlen))<0){
		fprintf(stderr,"Failed to connect to server %d:%s\n",errno,strerror(errno));
		} else {fprintf(stdout,"Connected.\n");
	}
	freeaddrinfo(postPacked);
return(livesockref);
}
//recieve over live socket: serv <= client
mbuffer  recieveMessagesFrom(int *sock){
	mbuffer *recievedMessage=(mbuffer*)malloc(sizeof(mbuffer));
	uint64_t objCount=0;
	FILE *fdp = fdopen(*sock,"r+b");
	memset(&recievedMessage, 0, sizeof(recievedMessage));
//setup recv fd
		if(fdp==NULL){
			perror("ERROR:");
			fprintf(stderr,"file descriptor (fdopen()) ERROR: %d:%s.\n",
			errno,strerror(errno));
		}
//work with open fd:
		while((fdp > 0)){
			objCount = fread(&recievedMessage, sizeof(mbuffer), 1, fdp);
			fdp--;
		}	
//return struct with stuff when done, then clear.
	return(*recievedMessage);
	memset(&recievedMessage, 0, sizeof(mbuffer));
	free(recievedMessage);
}
//send over connected socket: serv => client
void sendMessage(int *sock, const char *out, mbuffer *msg){
	FILE *fdp = fdopen(*sock,"w+b");
	char ourName[INET_ADDRSTRLEN];
	int count=0, er=0;
	if((er = gethostname(ourName, sizeof(ourName)))<0){
		fprintf(stderr, "sendMessage() set message owner failed\n %d:%s",
			errno,strerror(errno));
			perror("ERROR");
	}
		memset(&msg, 0, sizeof(msg));
		strncpy(msg->owner, ourName, strlen(ourName));
		strncpy(msg->buffer, out, strlen(out));
		//just incase
		strcat(msg->buffer, NULL);	
		count = fwrite(&msg, sizeof(msg), 1, fdp);

		memset(&msg,0,sizeof(msg));
		fclose(fdp);
	
}
//chat message log
void displayMessageIfExists(int *sfd, mbuffer *incoming){
	socklen_t size=0;
	struct sockaddr_in forname;
	memset(&forname,0,sizeof forname);
	char echobuffer[BUFF]={0};
	char ipstr[INET_ADDRSTRLEN]={0};

		getpeername(*sfd, (struct sockaddr *)&forname, &size);
		inet_ntop(AF_UNSPEC, &(forname.sin_addr), ipstr, INET_ADDRSTRLEN);

	snprintf(incoming->owner,sizeof ipstr,"%s",ipstr);
	snprintf(echobuffer, sizeof incoming->buffer,"[%s]:%s",
		incoming->owner,incoming->buffer);

	puts(echobuffer);
}
//will we connect or listen
int8_t connectOrListen(const char string[10]){
	regex_t yes, no;
	regmatch_t match[1];
	uint8_t b=0;
	int32_t rv=0, rz=0;
	int8_t ans=0;
//these regexz are shit
	if((rv = regcomp(&yes,"(y|Y)|(yes|Yes)|YES",REG_EXTENDED))!=0){
		fprintf(stderr,"regcomp failed with : %d:%d:",rv,errno);

	}if((rz = regcomp(&no,"(n|N)|(no|No)|NO",REG_EXTENDED))!=0){
		fprintf(stderr,"regcomp failed with : %d:%d:",rv,errno);
	}
	while(b != 4){
	if(regexec(&yes, string, 1, match, 0)==0){
		ans=1;
		b=4;
		}else if(regexec(&no, string, 1, match, 0)==0){
		ans=0;
		b=4;
		}else{fprintf(stdout,"what?\n");}
	}
	regfree(&yes);
	regfree(&no);
return ans;
}
//ya mush
int initCli_tls(void){
	mbuffer *messageLog=(mbuffer*)malloc(sizeof(mbuffer));
	mbuffer *ourMsgPtr=(mbuffer*)malloc(sizeof(mbuffer));
	connectargs args;
	char outbuff[BUFF];
	char answer[10];
	uint16_t sw=0;

	fprintf(stdout,"\n\nMake connection?(yes or no(listen only)):");
	fscanf(stdin,"%4s",answer);
		if((connectOrListen(answer))){
			fprintf(stdout,"Usage: connect>address port\n");
			fprintf(stdout,"connect>");
			fscanf(stdin,"%32s %6s", args.addr, args.port);
			int *connected = connectToServer(&args);
			//client
		while(connected){

			*messageLog = recieveMessagesFrom(connected);

			while((fgets(outbuff, BUFF, stdin))){
				sendMessage(connected, outbuff, ourMsgPtr);
				memset(&ourMsgPtr,0,sizeof(ourMsgPtr));
				free(&ourMsgPtr);

				if(messageLog > 0){
				displayMessageIfExists(connected, messageLog);
				memset(&messageLog, 0, sizeof messageLog);
				free(&messageLog);
				}
			}
		}
		close(*connected);
		} else {
			int *connected = startServer();
			fprintf(stdout,"Server listening.\v\n");
			//server
			while(connected && (sw!=2)){

				*messageLog = recieveMessagesFrom(connected);

				while((fgets(outbuff,BUFF,stdin))){
					sendMessage(connected, outbuff, ourMsgPtr);

					if(messageLog > 0){
					displayMessageIfExists(connected, messageLog);
					memset(&messageLog, 0, sizeof messageLog);
					free(&messageLog);
					}
				}
			}
		close(*connected);
		}
	return(0);
}