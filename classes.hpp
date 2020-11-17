#include <bits/stdc++.h>
#include <chrono>
// #include <ctime>
#include <stdlib.h> // exit, atoi
#include <unistd.h> // read, write, close
#include <arpa/inet.h> // sockaddr_in, AF_INET, SOCK_STREAM, INADDR_ANY, socket etc...
#include <string.h> // memset

# define port 1234

class echoServer
{
private:
	char str[100];
	int listen_fd, comm_fd;
	struct sockaddr_in servaddr;
public:
	void runServer(){

		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		bzero( &servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htons(INADDR_ANY);
		servaddr.sin_port = htons(port);
		bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
		listen(listen_fd, 10);

		comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);

		while(1)
		{
			bzero( str, 100);
			read(comm_fd,str,100);
			// std::cout<<"\nSending"<<str;
			write(comm_fd, str, strlen(str)+1);

		}
	}

};


class UIinterface : public echoServer
{
private:
	// check if the user typed exit
	bool exitFlag = false;
	// check if server has been started
	bool isServerUp = false;
	// check if analyser is active
	bool isAnalyserUp = false;
public:
	void printLogo();	
	void consolePrompt();
	bool getExitFlag();
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
	std::cout<<"\t......................................"<<std::endl;
}
bool UIinterface::getExitFlag(){return exitFlag;}

void UIinterface::consolePrompt(){

	std::string userInput;
	while(!getExitFlag()){
		// calculate time
		auto currentTime = std::chrono::system_clock::now();
		std::time_t humanReadableCurrentTime = std::chrono::system_clock::to_time_t(currentTime);
		std::cout << std::endl << std::ctime(&humanReadableCurrentTime) <<"[+] ";
		// get command
		std::getline(std::cin, userInput);
		if(!userInput.compare("exit")){
			std::cout << "Goodbye." << std::endl;
			exitFlag = !exitFlag;
		}
		else if(!userInput.compare("start server")){
			std::cout << "server is starting." << std::endl;
			runServer();
		}
		else if(!userInput.compare("start analyser")){
			std::cout << "analyser is recording." << std::endl;
		}
		else if(!userInput.compare("summary ethernet")){
			std::cout << "ethernet summary" << std::endl;
		}
		else if(!userInput.compare("summary ip")){
			std::cout << "ip summary." << std::endl;
		}
		else if(!userInput.compare("summary tcp")){
			std::cout << "tcp summary." << std::endl;
		}
		else{
			std::cout<<"Couldn't understand that.\n";
		}
	}
}