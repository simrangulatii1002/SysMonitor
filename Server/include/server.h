#pragma once

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <thread>
#include <nlohmann/json.hpp>
#include <DatabaseConnector.h>
 
using namespace boost::asio;
namespace beast = boost::beast;
// namespace http = beast::http;
namespace websocket = beast::websocket;
// namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using json = nlohmann::json;

class Server {
    private:
        std::string ConnectionKey_;
    
        ssl::context context_;
        //std::unique_ptr<tcp::acceptor> acceptor_;
        tcp::acceptor acceptor_;

        sql::Connection *dbConnection;

    public:
        Server(io_context& io_context_, std::string conKey);
        void accept_();
};


class ClientSession : public std::enable_shared_from_this<ClientSession> {
    public:
        ClientSession(io_context& io_context, ssl::context& context, std::string ConnectionKey_);
        void start();
        websocket::stream<ssl::stream<ip::tcp::socket>>& wsStream() {
            return *wsStream_;
        }
        ~ClientSession() {
            std::cout << "Session object destroyed." << std::endl;
        }

    private:
        sql::Connection *dbConnection;
        std::string ConnectionKey_;
        beast::flat_buffer buffer_;
        std::unique_ptr<websocket::stream<ssl::stream<ip::tcp::socket>>> wsStream_;
        void handleClient();
        void verifyClient();
        void receiveData();
        void handleError(const boost::system::error_code& ec, const std::string& errorMessage);
};


//  void handleError(const boost::system::error_code& ec, const std::string& errorMessage) {
//         std::cerr << errorMessage << ": " << ec.message() << std::endl;
//         // Optionally, close the connection or take other appropriate actions
// }

// void closeConnection(websocket::stream<ssl::stream<ip::tcp::socket>> &stream) {
//         stream.async_close(websocket::close_code::normal,
//             [this](boost::system::error_code ec) {
//                 if (ec) {
//                     std::cerr << "Error closing connection: " << ec.message() << std::endl;
//                 } else {
//                     std::cout << "Connection closed successfully." << std::endl;
//                 }
//             });
// }

