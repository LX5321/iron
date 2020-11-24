#compile server
set -e
echo "compiling server"
g++ -std=c++11 -pthread main.cpp -o server
echo "compiling client"
g++ echo-client.cpp -o echo-client
