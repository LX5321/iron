#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<error.h>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>

#define BUFFER 1024

int main(int argc,char **argv){
	struct sockaddr_in r_server;
	int sock;
	char input[BUFFER],output[BUFFER];
	int len,recieve;
	
	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("Socket: ");
		exit(-1);	
	}
	
	r_server.sin_family=AF_INET;
	r_server.sin_port=htons(atoi(argv[2]));
	r_server.sin_addr.s_addr=inet_addr(argv[1]);
	bzero(&r_server.sin_zero,8);
	
	len=sizeof(struct sockaddr_in);
	if((connect(sock,(struct sockaddr *)&r_server,len))==-1){
		perror("Connect");
		exit(-1);
	}
	
	while(1){
		fgets(input,BUFFER,stdin);
		send(sock,input,strlen(input),0);
		
		recieve=recv(sock,output,BUFFER,0);
		output[recieve]='\0';
		printf("%s\n",output);
	}
	close(sock);
}

