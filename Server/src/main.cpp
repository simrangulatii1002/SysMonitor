#include <iostream> 
#include <server.h>
#include <boost/asio.hpp>
#include "DatabaseInitializer.h"

using namespace boost::asio;
 
int main() { 
    try {
        boost::asio::io_context ioc_;
        Server server(ioc_, "hello");

        DatabaseInitializer dbInitializer("localhost", "root", "1234");
        if (!dbInitializer.initializeDatabase()) {
            return 1;
        }


        //server.start();
        ioc_.run();
    }
    catch(const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
 
    return 0; 
}