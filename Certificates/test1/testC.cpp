/*

g++ testC.cpp -o client -lboost_system -lboost_thread -lboost_date_time -lboost_regex -lboost_serialization -lssl -lcrypto -pthread


*/


#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using namespace boost::asio;

int main() {
    try {
        io_context io_context;
        ssl::context context(ssl::context::tlsv12); // Ensuring TLSv1.2 protocol version
        
        std::cout<<"test 1"<<std::endl;
        context.load_verify_file("/home/vboxuser/MonitoringSys/Certificates/server.crt"); // Set your CA certificate path here
        context.set_verify_mode(ssl::verify_peer);
		std::cout<<"test 1"<<std::endl;
        
        // Debugging output
        context.set_verify_callback(
            [](bool preverified, ssl::verify_context& ctx) {
                if (!preverified) {
                    X509_STORE_CTX* cts = ctx.native_handle();
                    int err = X509_STORE_CTX_get_error(cts);
                    std::cout << "Certificate verification failed with error: " << err << std::endl;
                }
                return preverified;
            });

        ssl::stream<ip::tcp::socket> socket(io_context, context);
        ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("127.0.0.1", "8080");
        connect(socket.next_layer(), endpoints);

        socket.handshake(ssl::stream_base::client);
        std::cout << "SSL handshake succeeded." << std::endl;
        
        std::string message = "Hello, server!";

        async_write(socket, boost::asio::buffer(message),
            [](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
                if (ec) {
                    std::cerr << "Error sending message: " << ec.message() << std::endl;
                } else {
                    std::cerr << " message send: " << std::endl;
                }
            });

        // Communication with the server
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}

