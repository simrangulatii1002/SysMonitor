#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <memory>
#include <string>

// namespace boost::asio;
using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using websocket = boost::beast::websocket::stream<boost::asio::ssl::stream<tcp::socket>>;
using json = nlohmann::json;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::io_context& io_context, ssl::context& context, tcp::socket socket): context_(context), socket_(std::move(socket), context) {
        // Initialize the socket with the accepted socket
        //socket_.lowest_layer().swap(socket);
        // Perform the SSL handshake
        socket_.async_handshake(ssl::stream_base::server,
            [this](boost::system::error_code ec) {
                if (!ec) {
                    // Handshake succeeded, start handling the client
                    std::cout<<"session handshake"<<std::endl;
                    handle_client();
                } else {
                    std::cout<<"else handshake"<<std::endl;
                    std::cerr << "Error in SSL handshake: " << ec.message() << std::endl;
                }
            });
            std::cout<<"end"<<std::endl;
    }

    void handle_client() {
        std::array<char, 1024> buf;
        socket_.async_read_some(boost::asio::buffer(buf),
            [this, buf](boost::system::error_code ec, std::size_t bytes_transferred) {
                if (!ec) {
                    // Process the message
                    std::string message(buf.data(), bytes_transferred);
                    std::cout << "Received message: " << message << std::endl;

                    // // Echo the message back to the client
                    // boost::asio::async_write(socket_, boost::asio::buffer(message),
                    //     [this](boost::system::error_code ec, std::size_t /*bytes_transferred*/) {
                    //         if (ec) {
                    //             std::cerr << "Error sending message: " << ec.message() << std::endl;
                    //         } else {
                    //             // Continue listening for more data
                    //             handle_client();
                    //         }
                    //     });
                } else {
                    std::cerr << "Error reading message: " << ec.message() << std::endl;
                }
            });
    }

private:

    ssl::stream<tcp::socket> socket_;
    ssl::context& context_;
};

class Server {
public:
    Server(boost::asio::io_context& io_context)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), 8080)), context_(ssl::context::tlsv12) {
            try {
            context_.set_options(ssl::context::default_workarounds |
                                 ssl::context::no_sslv2 |
                                 ssl::context::no_sslv3 |
                                 ssl::context::single_dh_use |
                                 ssl::context::no_tlsv1 |
                                 ssl::context::no_tlsv1_1);
            context_.set_password_callback([](std::size_t max_length, ssl::context::password_purpose purpose) {
                return "password"; // Set your certificate password here
            });
            context_.use_certificate_chain_file("/home/vboxuser/MonitoringSys/Certificates/server.crt");
            context_.use_private_key_file("/home/vboxuser/MonitoringSys/Certificates/server.key", ssl::context::pem);
            //context_.use_tmp_dh_file("dhparams.pem");

            // Verify the certificate
            context_.set_verify_mode(ssl::verify_peer); // | ssl::verify_fail_if_no_peer_cert);
            context_.load_verify_file("/home/vboxuser/MonitoringSys/Certificates/server.crt"); // Set your CA certificate path here

            // Debugging output
            context_.set_verify_callback(
                [](bool preverified, ssl::verify_context& ctx) {
                    if (!preverified) {
                        X509_STORE_CTX* cts = ctx.native_handle();
                        int err = X509_STORE_CTX_get_error(cts);
                        std::cout << "Certificate verification failed with error: " << err << std::endl;
                    }
                    return preverified;
                });
                std::cout<<"server object"<<std::endl;
            start_accept();

        } catch (const std::exception& e) {
            std::cerr << "SSL context setup error: " << e.what() << std::endl;
            throw;
        }
        
    }

private:
    void start_accept() {
        // auto new_session = std::make_shared<Session>(, context_);
        // new_session->start();
        // std::cout<<"start_accept"<<std::endl;
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout<<"server accept()"<<std::endl;
                    auto new_session = std::make_shared<Session>(static_cast<boost::asio::io_context&>(acceptor_.get_executor().context()), context_, std::move(socket));
                } else {
                    std::cerr << "Error in async_accept(): " << ec.message() << std::endl;
                }
                // Continue accepting connections
                start_accept();
            });
    }

    tcp::acceptor acceptor_;
    ssl::context context_;
};

int main() {
    try {
        boost::asio::io_context io_context;

        
        Server server(io_context);
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}

