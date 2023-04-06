// Base on https://github.com/boostorg/beast/blob/master/example/http/client/sync-ssl/http_client_sync_ssl.cpp

#include <boost/asio.hpp>
#include <boost/asio/basic_socket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/string_body.hpp>
#include <cstdlib>
#include <iostream>

// From https://github.com/boostorg/beast/blob/master/example/common/root_certificates.hpp
#include "root_certificates.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

int main() {
    int constexpr http_version = 11;
    std::string const target_host = "ident.me:443";
    auto const target_uri = "/";
    auto const proxy_endpoint = tcp::endpoint(
            net::ip::address_v4::from_string("127.0.0.1"),
            10800
    );

    net::io_context io_ctx;
    tcp::socket sock(io_ctx);

    try {
        sock.connect(proxy_endpoint);

        ssl::context ssl_ctx(ssl::context::tlsv12_client);

        // This holds the root certificate used for verification
        load_root_certificates(ssl_ctx);

        // This SSL-encrypted tunnel
        ssl::stream<tcp::socket &> stream(sock, ssl_ctx);
        stream.set_verify_mode(ssl::verify_peer);
        /** The CONNECT method converts the request connection to a transparent TCP/IP tunnel.

            This is usually to facilitate SSL-encrypted communication (HTTPS)
            through an unencrypted HTTP proxy.
        */
        http::request<http::string_body> conn_req(http::verb::connect, target_host, http_version);
        conn_req.set(http::field::host, target_host);
        http::write(sock, conn_req);
        http::response<http::empty_body> res;
        http::parser<false, http::empty_body> http_parser(res);

        /** Set the skip parse option.

            This option controls whether or not the parser expects to see an HTTP
            body, regardless of the presence or absence of certain fields such as
            Content-Length or a chunked Transfer-Encoding. Depending on the request,
            some responses do not carry a body. For example, a 200 response to a
            CONNECT request from a tunneling proxy, or a response to a HEAD request.
            In these cases, callers may use this function inform the parser that
            no body is expected. The parser will consider the message complete
            after the header has been received.
        */
        http_parser.skip(true);

        // Read proxy response
        beast::flat_buffer buffer;
        http::read(sock, buffer, http_parser);
        std::cout << "Connection proxy response: " << res << std::endl;
        if (res.result() == http::status::ok) {
            // Start ssl session
            stream.handshake(ssl::stream_base::client);

            // Make target host request
            http::request<http::string_body> req(http::verb::get, target_uri, http_version);
            req.set(http::field::host, target_host);
            http::write(stream, req);
            http::response<http::dynamic_body> stream_res;
            http::read(stream, buffer, stream_res);
            std::cout << "Target host response: " << stream_res << std::endl;
            if (error_code ec; stream.shutdown(ec) != net::error::eof) {
                throw beast::system_error(ec);
            }
        }
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}