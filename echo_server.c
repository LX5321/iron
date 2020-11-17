#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<strings.h>

#define BUFFER 1024

int main(int argc,char **argv) {
	int sock,cli;
	struct sockaddr_in server,client;
	int len,data_len;
	char data[BUFFER];

	if((sock=socket(AF_INET, SOCK_STREAM, 0)) ==-1){
		perror("Socket: ");
		exit(-1);
	}
	server.sin_family=AF_INET;
	server.sin_port=htons(atoi(argv[1]));
	server.sin_addr.s_addr=INADDR_ANY;
	bzero(&server.sin_zero,8);
	
	len=sizeof(struct sockaddr_in);
	if(bind(sock,(struct sockaddr *)&server,len)==-1){
		perror("Bind: ");
		exit(-1);
	}

	if((listen(sock,2))==-1){
		perror("Listen: ");
		exit(-1);
	}
	
	
	while(1){
		if((cli=accept(sock,(struct sockaddr *)&client,&len))==-1){
			perror("Accept");
			exit(-1);
		}
		
		printf("Client Connected to IP Address %s and from Port No. %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
		
		data_len=1;
		
		while(data_len){
			data_len=recv(cli,data,BUFFER,0);
			if(data_len){
				send(cli,data,data_len,0);
				data[data_len]='\0';
				printf("Sent Message: %s",data);
			}
		}
		printf("Client Disconnected\n");
		
		close(cli);
	}
}
