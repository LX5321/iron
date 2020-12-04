#include <bits/stdc++.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <string>
#include <netinet/ip_icmp.h> 
#include <netinet/udp.h> 
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>   
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

// port number for echo server
# define port 1234

class packetAnalyser
{
private:
	// file pointer for logging packet tracer output
	FILE *logfile;
	// initialise
	struct sockaddr_in source,dest;
	int saddr_size , data_size;
	struct sockaddr saddr;
	// buffer for size of ethernet packet
	unsigned char *buffer = (unsigned char *) malloc(65536);
	// tcp count
	float tcp=0;
	// udp packet count
	float udp=0;
	// icmp packet count
	float icmp=0;
	// other packets (ARP included)
	float others=0;
	// igmp count
	float igmp=0;
	// total count. Required for summary
	float total=0;
	// counter for loops
	int i;
	int j;
	// 

public:
	void ProcessPacket(unsigned char *, int);
	void printIPHeader(unsigned char* , int);
	void printTCPPacket(unsigned char *, int);
	void printUDPPacket(unsigned char *, int);
	void printICMPPacket(unsigned char*, int);
	void printEthernetHeader(unsigned char*, int);
	void PrintData(unsigned char* , int);
	void runPacket();
	void printPacketSummary();
};

void packetAnalyser::runPacket(){
	logfile = fopen("packetlogger.txt","w");
	if(logfile==NULL){
		// failed to create log file
		std::cout<<"[Packet Analyser] Unable to create logfile.\n";
	}
	
	// create the socket object
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	
	// enhanced options for extensibility
	// configure with network card interface details
	setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "enp1s0" , strlen("eth0")+ 1 );

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
		if(data_size < 0)
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
    printf("TCP: %.0f [%.1f] UDP: %.0f [%.1f] ICMP: %.0f [%.1f] IGMP: %.0f [%.1f] Others: %.0f [%.1f] Total: %.0f\r", tcp, tcp/total , udp, udp/total , icmp, icmp/total, igmp, igmp/total , others, others/total, total);

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
	fprintf(logfile , "   |-TTL               : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol          : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum          : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP         : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
}

void packetAnalyser::printTCPPacket(unsigned char* Buffer, int Size)
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
	fprintf(logfile , "   |-Source Port        : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port   : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window               : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum             : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer       : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                       -DATA CARRIED-                        ");
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
	
	fprintf(logfile , "   |-Code     : %d\n",(unsigned int)(icmph->code));
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

void packetAnalyser::printPacketSummary(){
	while(1)
	{
		std::this_thread::sleep_for (std::chrono::seconds(10));
		std::cout<<"\n\nSummary. TCP 10%\n";
	}

}

class echoServer
{
private:
	std::ofstream outfile;
	char str[100];
	int listen_fd, comm_fd;
	struct sockaddr_in servaddr;
public:
	void runServer(){
     	outfile.open("echoserverlog.dat");
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
			// uncommenting this will print the sending string to the terminal
			// std::cout<<"\nSending: " << str;
			outfile << str;
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
	
	threadSpool.push_back(std::thread(&echoServer::runServer, echoServer()));
	std::cout << "Server @ thread ID: " << threadSpool[0].get_id() << std::endl;
	threadSpool.push_back(std::thread(&packetAnalyser::runPacket, packetAnalyser()));
	std::cout << "Packet Analyser @ thread ID: " << threadSpool[1].get_id() << std::endl;	
	threadSpool.push_back(std::thread(&packetAnalyser::printPacketSummary, packetAnalyser()));

}

void UIinterface::consolePrompt(){
	while(1){
		startServer();
		for(auto& thread : threadSpool){
			thread.join();
		}
	}
}


int main()
{
	UIinterface i;
	i.printLogo();
	i.consolePrompt();
	return 0;
}
