#include <iostream>
#include <boost/asio.hpp>
// #include <boost/asio/ssl.hpp>
#include <thread>
#include <vector>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

///////////////////////////////////////////
#include <boost/asio.hpp>
// #include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <thread>
 
using namespace boost::asio;
using namespace boost::beast;

///////////////////////////////


void client(int i) {
    try {
        io_context io_context;
        ssl::context context(ssl::context::tlsv12);

        context.load_verify_file("/home/vboxuser/MonitoringSys/Certificates/server.crt");
        context.set_verify_mode(ssl::verify_peer);

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

         /////////////////////////////////////////////////////////////////////////////////////////////
        websocket::stream<ssl::stream<ip::tcp::socket>> stream_(std::move(socket));
        stream_.next_layer().async_handshake(ssl::stream_base::client,
            [&stream_](const boost::system::error_code& ec) {
                std::cout<<"test 3"<<std::endl;
                if (!ec) {
                    // Handshake with WebSocket
                    stream_.async_handshake("127.0.0.1", "/",
                        [](const boost::system::error_code& ec) {
                            std::cout<<"test 4"<<std::endl;
                            if (!ec) {
                                std::cout << "Connection established successfully." << std::endl;
                                // Connection is established, you can start reading/writing
                            } else {
                                std::cerr << "WebSocket handshake failed: " << ec.message() << std::endl;
                            }
                        }
                    );
                } else {
                    std::cerr << "SSL handshake failed: " << ec.message() << std::endl;
                }
            }
        );
        ///////////////////////////////////////////////////////////////////////////////////////////////

//         socket.async_handshake(ssl::stream_base::client,
//             [&socket, &i](boost::system::error_code ec) {
//                 if (!ec) {
//                     std::cout << "SSL handshake succeeded." << std::endl;
//                     // Send a message to the server
//                     std::string message = "Hello, server!" + std::to_string(i);

//                     async_write(socket, boost::asio::buffer(message),
//                         [](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
//                             if (ec) {
//                                 std::cerr << "Error sending message: " << ec.message() << std::endl;
//                             } else {
//                                 std::cerr << " message send1: " << ec.message() << std::endl;
//                             }
//                     });

//  /* test  */        std::this_thread::sleep_for(std::chrono::seconds(5));

//                     message = "Hello, server! again" + std::to_string(i);
//                     async_write(socket, boost::asio::buffer(message),
//                         [&socket, &i](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
//                             if (ec) {
//                                 std::cerr << "Error sending message: " << ec.message() << std::endl;
//                             } else {
//                                 std::cerr << " message send2: " << ec.message() << std::endl;
//                             }
//                             socket.async_shutdown([&socket](boost::system::error_code ec) {
//                                 if (ec) {
//                                     std::cerr << "Error closing connection: " << ec.message() << std::endl;
//                                 }
//                             });
//                     });
//                     std::this_thread::sleep_for(std::chrono::seconds(2));

//                 } else {
//                     std::cerr << "Error in SSL handshake: " << ec.message() << std::endl;
//                 }
//             });

        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

int main() {
    std::vector<std::thread> clients;
    for (int i = 1; i <= 1; ++i) {
        clients.emplace_back(client, i);
        
    }

    // Wait for all clients to finish
    for (auto& client : clients) {
        client.join();
    }
    return 0;
}
