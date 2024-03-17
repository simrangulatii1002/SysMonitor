#include <server.h>
#include <DatabaseInitializer.h>

Server::Server(io_context& io_context_, std::string conKey): ConnectionKey_(conKey), 
    context_(ssl::context::tlsv12), acceptor_(io_context_, tcp::endpoint(tcp::v4(), 8080)) {

    try {
        context_.set_options(ssl::context::default_workarounds |
                                ssl::context::no_sslv2 |
                                ssl::context::no_sslv3 |
                                ssl::context::single_dh_use |
                                ssl::context::no_tlsv1 |
                                ssl::context::no_tlsv1_1
        );
        context_.set_password_callback([](std::size_t max_length, ssl::context::password_purpose purpose) {
            return "password"; // Set your certificate password here
        });
        context_.use_certificate_chain_file("/home/vboxuser/sysmonitor/Certificates/server.crt");
        context_.use_private_key_file("/home/vboxuser/sysmonitor/Certificates/server.key", ssl::context::pem);

        // Verify the certificate
        context_.set_verify_mode(ssl::verify_peer); // | ssl::verify_fail_if_no_peer_cert);
        context_.load_verify_file("/home/vboxuser/sysmonitor/Certificates/server.crt"); // Set your CA certificate path here

        // Debugging output
        context_.set_verify_callback(
            [](bool preverified, ssl::verify_context& ctx) {
                if (!preverified) {
                    X509_STORE_CTX* cts = ctx.native_handle();
                    int err = X509_STORE_CTX_get_error(cts);
                    std::cout << "Certificate verification failed with error: " << err << std::endl;
                }
                return preverified;
            }
        );
        
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));

        accept_();

        } catch (const std::exception& e) {
            std::cerr << "SSL context setup error: " << e.what() << std::endl;
            throw;
        }

}

void Server::accept_() {
    try {

        auto new_clientSession = std::make_shared<ClientSession>(static_cast<io_context&>(acceptor_.get_executor().context()), context_, ConnectionKey_);

        acceptor_.async_accept(new_clientSession->wsStream().next_layer().lowest_layer(),
            [this, new_clientSession](const boost::system::error_code& error) {
                if (!error) {
                    new_clientSession->start();
                } else {
                    std::cerr << "Accept error: " << error.message() << std::endl;
                }
                accept_();
            }
        );
    }
    catch(const std::exception& e) {
        std::cerr << "Exception in accepting client: " << e.what() << std::endl;
        // Continue accepting even after exception
        //accept_();
    }
    
}

ClientSession::ClientSession(io_context& io_context, ssl::context& context, std::string conKey)
        : ConnectionKey_(conKey), wsStream_(std::make_unique<websocket::stream<ssl::stream<ip::tcp::socket>>>(io_context, context)) {}

void ClientSession::start() {
    wsStream_->next_layer().async_handshake(ssl::stream_base::server,
        [this, self = shared_from_this()](const boost::system::error_code& error) {
            if (!error) {
                std::cout << "SSL handshake succeeded." << std::endl;

                wsStream_->async_accept(
                    [this, self = shared_from_this()](const boost::system::error_code& ec) {
                        if (!ec) {
                            std::cout << "WebSocket handshake succeeded." << std::endl;
                            verifyClient();

                        } else {
                            handleError(ec, "WebSocket handshake failed: ");
                            // std::cerr << "Socket state: " << (wsStream_->next_layer().next_layer().is_open() ? "Open" : "Closed") << std::endl;
                            // std::cerr << "Session object: " << (self.use_count() > 1 ? "Alive" : "Destroyed") << std::endl;  
                        }
                    });
            } else {
                handleError(error, "SSL handshake failed: ");
            }
        }
    );
}

void ClientSession::verifyClient() {
    wsStream_->async_read(buffer_,
        [this, self = shared_from_this()](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                
                std::string receivedKey(beast::buffers_to_string(buffer_.data()));
                std::cout<<receivedKey<<receivedKey.size()<<std::endl;
                if (receivedKey == ConnectionKey_) {
                    std::cout << " \n \nConnection key is valid. Client is authorized.\n" << std::endl;

                    receiveData();
                } else {
                    char errorResponse[256] = "Invalid connection key.....retry!!!";
                    std::cout<<"Invalid connection key"<<std::endl;
                    return ;
                }
            } else {
                handleError(ec, "Error reading connection key: ");
            }
        }
    );
}

void ClientSession::receiveData() {
    while(true) {
        char received_data[1024]; 
        
        wsStream_->async_read_some(buffer(received_data),
            [this, self = shared_from_this(), &received_data](boost::system::error_code ec, std::size_t bytes_transferred) {
                if(!ec) {
                    std::string received_message(received_data, bytes_transferred);

                    // Parse JSON
                    json received_json = json::parse(received_message);

                    boost::system::error_code error_code;
                    //Checking connection status
                    if(received_json["status"] == "0") {
                        wsStream_->close(websocket::close_code::normal, error_code);
                        if (error_code){
                            std::cerr << "Error while closing websocket Connection: " << error_code.message() << std::endl;
                        }        
                        std::cout << "client disconnected." << std::endl;
                        return ;
                    }
                    std::string hostName = received_json["hostname"];
                    std::string ipaddr = received_json["ipAddress"];
                    std::string cpu = received_json["cpu"];
                    std::string ram = received_json["ram"];
                    std::string netstats = received_json["netstate"];
                    std::string hddUtilization = received_json["hddUtilization"];
                    std::string idleTime = received_json["idleTime"];

                    std::cout << "host name: "<< hostName << std::endl; 
                    std::cout << "ip address: "<< ipaddr << std::endl; 
                    std::cout << "CPU: "<< cpu << std::endl; 
                    std::cout << "RAM: "<< ram << std::endl; 
                    std::cout << "Network Stats: "<< netstats << std::endl; 
                    std::cout << "HDD Utilization: "<< hddUtilization << std::endl; 
                    std::cout << "Idle Time: "<< idleTime << std::endl; 
                    std::cout << "data received" << std::endl;

                    DatabaseInitializer dbInitializer("localhost", "root", "1234");
                    dbInitializer.insertSystemInformation(ipaddr, ram, cpu, idleTime, hddUtilization, netstats);

                    // Create JSON to send back
                    json reply_json;
                    reply_json["status"] = "OK";
                    reply_json["message"] = "Received message successfully";
                    std::string reply_message = reply_json.dump();

                    wsStream_->async_write(boost::asio::buffer(reply_message),
                        [this, self = shared_from_this()](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
                            if (ec) {
                                handleError(ec, "Error sending reply message: ");
                            } else {
                                std::cerr << " reply message sent: " << ec.message() << std::endl;
                                receiveData();
                            }
                    });
                    //wsStream_->write(buffer(reply_message), error_code);
                
                } else {
                    handleError(ec, "Error reading sysinfo: " );
                }
        });
        return;
    }
}

void ClientSession::handleError(const boost::system::error_code& ec, const std::string& errorMessage) {
    if (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated) {
        std::cout << "Client disconnected." << std::endl;
    } else {
        std::cerr << errorMessage<< ec.message() << std::endl;
    }
}