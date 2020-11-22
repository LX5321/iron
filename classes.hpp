#include<bits/stdc++.h>
#include<thread>
#include<chrono>
#include<fstream>
#include<unistd.h> // read, write, close
#include<arpa/inet.h> // sockaddr_in, AF_INET, SOCK_STREAM, INADDR_ANY, socket etc...
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<netinet/ip_icmp.h> //Provides declarations for icmp header
#include<netinet/udp.h> //Provides declarations for udp header
#include<netinet/tcp.h> //Provides declarations for tcp header
#include<netinet/ip.h>  //Provides declarations for ip header
#include<netinet/if_ether.h>    //For ETH_P_ALL
#include<net/ethernet.h>    //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

# define port 1234
# define updateInterval 10 // seconds to log to console

class packetAnalyser
{
private:
	FILE *logfile;
	struct sockaddr_in source,dest;
	int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
	int saddr_size , data_size;
	struct sockaddr saddr;
	// buffer for size of ethernet packet
	unsigned char *buffer = (unsigned char *) malloc(65536);

public:
	void ProcessPacket(unsigned char *, int);
	void printIPHeader(unsigned char* , int);
	void printTCPPacket(unsigned char *, int);
	void printUDPPacket(unsigned char *, int);
	void printICMPPacket(unsigned char*, int);
	void printEthernetHeader(unsigned char*, int);
	void PrintData(unsigned char* , int);
	void runPacket();
};

void packetAnalyser::runPacket(){
	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		std::cout<<"[Packet Analyser] Unable to create logfile.\n";
	}
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

	if(sock_raw < 0)
	{
        //Print the error with proper message
		std::cout<<"[Packet Analyser] Socket Error. Try with Admin Privilleges.\n";
		exit(0);
	}
	while(1)
	{
		saddr_size = sizeof saddr;
        //Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			std::cout<<"Recv from error , failed to get packets\n";
			exit(0);
		}
        	//Now process the packet
		ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
}

void packetAnalyser:: ProcessPacket(unsigned char* buffer, int size)
{
    // Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;

	// parse protocols carried by the packet header
	switch (iph->protocol)
	{
        case 1:  //ICMP Protocol
        ++icmp;
        printICMPPacket(buffer , size);
        break;
        
        case 2:  //IGMP Protocol
        ++igmp;
        break;
        
        case 6:  //TCP Protocol
        ++tcp;
        printTCPPacket(buffer , size);
        break;
        
        case 17: //UDP Protocol
        ++udp;
        printUDPPacket(buffer , size);
        break;
        
        default: //Some Other Protocol like ARP etc.
        ++others;
        break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
    // std::cout << tcp <<";" << udp<<";" << icmp<<";" << igmp<<";" << others<<";" << total << std::endl;


}

void packetAnalyser::printEthernetHeader(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void packetAnalyser::  printIPHeader(unsigned char* Buffer, int Size)
{
	printEthernetHeader(Buffer , Size);
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void packetAnalyser::  printTCPPacket(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
	
	printIPHeader(Buffer,Size);
	
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
	
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
	
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
	
	fprintf(logfile , "Data Payload\n");    
	PrintData(Buffer + header_size , Size - header_size );
	
	fprintf(logfile , "\n###########################################################");
}

void packetAnalyser::printUDPPacket(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	
	printIPHeader(Buffer,Size);           
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
	
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
	
	fprintf(logfile , "Data Payload\n");    
	
    //Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}

void packetAnalyser::printICMPPacket(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
	
	printIPHeader(Buffer , Size);
	
	fprintf(logfile , "\n");
	
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
	
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
	
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
	
	fprintf(logfile , "Data Payload\n");    
	
    //Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n###########################################################");
}

void packetAnalyser::PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		// print one line of output and another on the other line
		if( i!=0 && i%16==0)
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128){
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                }
                
                else{
                	fprintf(logfile , "."); //otherwise print a dot
                }
            }
            fprintf(logfile , "\n");
        } 
        
        if(i%16==0) fprintf(logfile , "   ");
        fprintf(logfile , " %02X",(unsigned int)data[i]);
        
        if( i==Size-1)  //print the last spaces
        {
        	for(j=0;j<15-i%16;j++) 
        	{
              fprintf(logfile , "   "); //extra spaces
          }
          
          fprintf(logfile , "         ");
          
          for(j=i-i%16 ; j<=i ; j++)
          {
          	if(data[j]>=32 && data[j]<=128) 
          	{
          		fprintf(logfile , "%c",(unsigned char)data[j]);
          	}
          	else 
          	{
          		fprintf(logfile , ".");
          	}
          }
          
          fprintf(logfile ,  "\n" );
      }
  } 
}

class echoServer
{
private:
	char str[100];
	int listen_fd, comm_fd;
	struct sockaddr_in servaddr;
public:
	void runServer(){
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		bzero( &servaddr, sizeof(servaddr) );
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htons(INADDR_ANY);
		servaddr.sin_port = htons(port);
		bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
		listen(listen_fd, 10);
		comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
		while(1)
		{
			bzero(str, 100);
			read(comm_fd,str,100);
			std::cout<<"\nSending: " << str;
			write(comm_fd, str, strlen(str)+1);

		}
	}

};


class UIinterface : public echoServer, public packetAnalyser
{
private:
	// vector to handle all threads
	std::vector<std::thread> threadSpool;
public:
	void printLogo();	
	void consolePrompt();
	void startServer();
};

void UIinterface::printLogo(){
	// logo
	std::cout<< std::endl;
	std::cout<<"\t'####:'########:::'#######::'##::: ##:"<<std::endl;
	std::cout<<"\t. ##:: ##.... ##:'##.... ##: ###:: ##:"<<std::endl;
	std::cout<<"\t: ##:: ##:::: ##: ##:::: ##: ####: ##:"<<std::endl;
	std::cout<<"\t: ##:: ########:: ##:::: ##: ## ## ##:"<<std::endl;
	std::cout<<"\t: ##:: ##.. ##::: ##:::: ##: ##. ####:"<<std::endl;
	std::cout<<"\t: ##:: ##::. ##:: ##:::: ##: ##:. ###:"<<std::endl;
	std::cout<<"\t'####: ##:::. ##:. #######:: ##::. ##:"<<std::endl;
	std::cout<<"\t....::..:::::..:::.......:::..::::..::"<<std::endl;
	std::cout<<"\t...... Alexander Roque Rodrigues ....."<<std::endl;
	std::cout<<"\t.......... Omkar Shripad Modak ......."<<std::endl;
	std::cout<<"\t......................................\n"<<std::endl;
}

void UIinterface::startServer(){
	// calculate time
	auto currentTime = std::chrono::system_clock::now();
	std::time_t humanReadableCurrentTime = std::chrono::system_clock::to_time_t(currentTime);
		std::cout<<std::ctime(&humanReadableCurrentTime);

	threadSpool.push_back(std::thread(&echoServer::runServer, echoServer()));
	std::cout << "Server @ thread ID: " << threadSpool[0].get_id() << std::endl;
	threadSpool.push_back(std::thread(&packetAnalyser::runPacket, packetAnalyser()));
	std::cout << "Packet Analyser @ thread ID: " << threadSpool[1].get_id() << std::endl;	
}

void UIinterface::consolePrompt(){
	std::string userInput;
	while(1){
		startServer();
		for(auto& thread : threadSpool){
			thread.join();
		}
	}
}
