#include <iostream> 
#include <client.h>
 
int main() { 
    try {
        Client* client = Client::getInstance();
        client->initialize("127.0.0.1", "8080", "hello");
        client->run();
    }
    catch(const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
 
    return 0; 
}