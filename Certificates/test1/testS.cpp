/*

g++ testS.cpp -o server -lboost_system -lboost_thread -lboost_date_time -lboost_regex -lboost_serialization -lssl -lcrypto -pthread

*/


#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket/stream.hpp>

using namespace boost::asio;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(io_context& io_context, ssl::context& context)
        : socket_(io_context, context) {}

    ssl::stream<ip::tcp::socket>& socket() {
        return socket_;
    }

    void start() {
        socket_.async_handshake(ssl::stream_base::server,
            [this, self = shared_from_this()](const boost::system::error_code& error) {
                if (!error) {
                    std::cout << "SSL handshake succeeded." << std::endl;
                    // Now you can communicate with the client securely.
                    handle_client();
                } else {
                    std::cerr << "SSL handshake failed: " << error.message() << std::endl;
                }
            });
    }

private:
	void handle_client() {
    std::array<char, 1024> buf;
    // boost::system::error_code ec;
    // std::size_t bytes_transferred = socket_.read_some(boost::asio::buffer(buf), ec);
    // if(!ec) {
        
    //     std::string message(buf.data(), bytes_transferred);
    //     std::cout << "Received message1: " << message << std::endl;

    //     bytes_transferred = socket_.read_some(boost::asio::buffer(buf), ec);
    //     message = std::string(buf.data(), bytes_transferred);
    //     std::cout << "Received message2: " << message << std::endl;
    //     //std::cerr << "Error reading message: " << ec.message() << std::endl;
    //     // Additional debugging output
    //     std::cerr << "Socket state: " << (socket_.lowest_layer().is_open() ? "Open" : "Closed") << std::endl;
    //     std::cerr << "Session object: " << (shared_from_this().use_count() > 1 ? "Alive" : "Destroyed") << std::endl;
    // }
    socket_.async_read_some(boost::asio::buffer(buf),
        [this, &buf](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                // Process the message
                std::string message(buf.data(), bytes_transferred);
                std::cout << "Received message: " << message << std::endl;

                std::cerr << "Socket state: " << (socket_.lowest_layer().is_open() ? "Open" : "Closed") << std::endl;
                std::cerr << "Session object: " << (shared_from_this().use_count() > 1 ? "Alive" : "Destroyed") << std::endl;

                // Echo the message back to the client
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
                // Additional debugging output
                std::cerr << "Socket state: " << (socket_.lowest_layer().is_open() ? "Open" : "Closed") << std::endl;
                std::cerr << "Session object: " << (shared_from_this().use_count() > 1 ? "Alive" : "Destroyed") << std::endl;
            }
        });
	}


    ssl::stream<ip::tcp::socket> socket_;
};

class Server {
public:
    Server(io_context &io_context, unsigned short port)
        : acceptor_(io_context, ip::tcp::endpoint(ip::tcp::v4(), port)),
          context_(ssl::context::tlsv12) { // Ensuring TLSv1.2 protocol version
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

        } catch (const std::exception& e) {
            std::cerr << "SSL context setup error: " << e.what() << std::endl;
            throw;
        }
    }

    void start_accept() {
        auto new_session = std::make_shared<Session>(static_cast<io_context&>(acceptor_.get_executor().context()), context_);
        acceptor_.async_accept(new_session->socket().lowest_layer(),
                               [this, new_session](const boost::system::error_code& error) {
                                   if (!error) {
                                       new_session->start();
                                   } else {
                                       std::cerr << "Accept error: " << error.message() << std::endl;
                                   }
                                   start_accept();
                               });
    }

private:
    ip::tcp::acceptor acceptor_;
    ssl::context context_;
    io_context ioc_;
};

int main() {
    try {
        io_context io_context;
        Server server(io_context, 8080);
        server.start_accept();
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}

