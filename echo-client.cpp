#include<bits/stdc++.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<error.h>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>

int main(int argc,char **argv)
{
    int sockfd,n;
    char sendline[100];
    char recvline[100];
    struct sockaddr_in servaddr;

    sockfd=socket(AF_INET,SOCK_STREAM,0);
    bzero(&servaddr,sizeof servaddr);

    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(1234);

    inet_pton(AF_INET,"127.0.0.1",&(servaddr.sin_addr));

    connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

    // while(true)
    for(int i=10;i>0;--i)
    {
        if (sendline[0]== 'e' && sendline[1] == 'x' && sendline[2] == 'i' &&  sendline[3] == 't')
        {
            break;
        }
        else{
            bzero(sendline, 100);
            bzero(recvline, 100);
            fgets(sendline,100,stdin); /*stdin = 0 , for standard input */
            std::cin.clear();
            write(sockfd,sendline,strlen(sendline)+1);
            read(sockfd,recvline,100);
        }
        std::cout<<"-> "<<recvline;
    }

}
