#pragma once

#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
// #include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <thread>
#include <csignal>
#include <nlohmann/json.hpp>

#include<sys_info.h>
 
using namespace boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using json = nlohmann::json;

class Client {
    private:
        static Client* instance;
        std::string serverIP_;
        std::string port_;
        std::string ConnectionKey_;

        boost::asio::io_context ioc_;
        ssl::context ctx_;
        websocket::stream<beast::ssl_stream<tcp::socket>> stream_;
        boost::system::error_code errorCode;
        // beast::flat_buffer buffer_;
        bool shouldRun_;
        int reconnectAttempts_;

        Client(): ctx_(ssl::context::tlsv12_client), stream_(ioc_, ctx_){};
        void handleError(const boost::system::error_code& ec, const std::string& errorMessage);
        ~Client();
    public:
        Client(const Client&) = delete;
        void operator=(const Client&) = delete;

        static Client* getInstance();
        void initialize(const std::string &ip, const std::string &port, const std::string &conKey);
        void connect();
        void keyVerification();
        void sysInfo();
        void receiveResponse();
        void disconnect();
        void run();
};