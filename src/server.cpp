#include "server.hpp"

// Std C includes
#include <unistd.h>
#include <errno.h>
#include <string.h>

// Std C++ includes
#include <chrono>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <type_traits>
#include <cstdint>
#include <random>
#if __has_include(<format>)
#define USE_FORMAT
#include <format>
#include <stdio.h>
#include <inttypes.h>
#else
#include <stdio.h>
#include <inttypes.h>
#endif
#include <cmath>
#include <numbers>
#include <cassert>

// C libraires that we use
#include <uv.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

// Internal includes
#include "App.h"


class Server::Internal {
public:
    Internal(const Server::Settings& settings);
    ~Internal();
    Internal(const Internal&) = delete;
    Internal& operator=(const Internal&) = delete;

    void restart(const Server::Settings& settings);
    void start();
    void stop();

private:
    class Session;
    struct WsConData {
        Session* session;
    };

    struct Session {
        std::string                                        id{};
        std::chrono::time_point<std::chrono::steady_clock> last_activity{};
        std::chrono::time_point<std::chrono::steady_clock> ws_ping_sent{};
        uWS::WebSocket<false, true, WsConData>*            ws{nullptr};
        double                                             rtt{0.0};
        std::string                                        rtt_str{"0"};
    };

    Server::Settings               settings_;
    bool                           running_;
    std::mutex                     m_;
    std::thread                    t_;
    int                            ctrl_pipe[2];
    std::unique_ptr<uWS::App>      std_app;
    std::unique_ptr<uWS::SSLApp>   tls_app;
    short                          sample_buffer_[513]; // Last word is a counter
    int                            sample_idx_{0};
    std::map<std::string, Session> sessions;

    std::random_device             random_device_;
    std::mt19937                   random_generator_;
    std::uniform_int_distribution<uint64_t> random_distribution_;

    std::string read_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }
        std::ostringstream content;
        content << file.rdbuf();
        return content.str();
    }

    std::string get_session_id() {
        uint64_t rn = random_distribution_(random_generator_);
#ifdef USE_FORMAT
        std::string rs = std::format("{:08x}", rn);
#else
        char tmp_str[24];
        sprintf(tmp_str, "%.08" PRIx64, rn);
        std::string rs{tmp_str};
#endif
        return rs;
    };

    void worker_(void);
};


Server::Internal::Internal(const Server::Settings& settings)
: settings_(settings), running_(false), random_generator_(random_device_()),
  random_distribution_(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max()) {
    start();
}

Server::Internal::~Internal() {
    stop();
}

void Server::Internal::start() {
    std::unique_lock<std::mutex> lock{m_};
    if (!running_) {
        pipe(ctrl_pipe);
        running_ = true;
        //lock.unlock();
        t_ = std::thread(&Internal::worker_, this);
    }
}

void Server::Internal::stop() {
    std::unique_lock<std::mutex> lock{m_};
    if (running_) {
        running_ = false;
        write(ctrl_pipe[1], "Q", 1);
        //lock.unlock();
        t_.join();
        close(ctrl_pipe[0]);
        close(ctrl_pipe[1]);
    }
}

void Server::Internal::restart(const Server::Settings& new_settings) {
    stop();

    // Update settings if new_settings is non-empty
    if (new_settings) settings_ = new_settings;

    start();
}

void Server::Internal::worker_() {
    int        ret;
    uv_loop_t  loop;
    uv_timer_t timer;
    uv_timer_t worker_timer;
    uv_poll_t  ctrl_poll;

    std::cout << "Worker started for server " << this << std::endl;
    std::cout << "Settings:\n";
    std::cout << "    std_sockets="; for (auto& s : settings_.std_sockets) { std::cout << s.first << ":" << s.second << " "; }; std::cout << std::endl;
    std::cout << "    tls_sockets="; for (auto& s : settings_.tls_sockets) { std::cout << s.first << ":" << s.second << " "; }; std::cout << std::endl;
    std::cout << "    crt_file=" << settings_.crt_file << std::endl;
    std::cout << "    key_file=" << settings_.key_file << std::endl;
    std::cout << "    client_ca_file=" << settings_.client_ca_file << std::endl;
    std::cout << "    auth_hostname=" << settings_.auth_hostname << std::endl;
    std::cout << "    webroot=" << settings_.webroot << std::endl;

    ret = uv_loop_init(&loop);
    if (ret < 0) std::cerr << "Error: Unable to create uv_loop, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    // Attach our instance to the loop. Can be used in callbacks later on to get "this"
    uv_loop_set_data(&loop, reinterpret_cast<void*>(this));

    ret = uv_poll_init(&loop, &ctrl_poll, ctrl_pipe[0]);
    if (ret < 0) std::cerr << "Error: Unable to initialize uv_poll, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    ret = uv_poll_start(&ctrl_poll, UV_READABLE, [](uv_poll_t* p, int, int) {
        auto  handle{reinterpret_cast<uv_handle_t*>(p)};
        char  cmd{'X'};
        int   ret;
        int   fd;

        uv_fileno(handle, &fd);
        ret = read(fd, &cmd, 1);
        if (ret < 0) {
            std::cerr << "Error: Unable to read command from command pipe, ret = " << ret << "(" << strerror(errno) << ")" << std::endl;
            return;
        }

        switch (cmd) {
            case 'Q':
                //std::cout << "Quit command received" << std::endl;
                uv_stop(uv_handle_get_loop(handle));
                break;
            default:
                std::cerr << "Error: Unknown command received (" << cmd << ")\n";
                break;
        }
    });
    if (ret < 0) std::cerr << "Error: Unable to start uv_poll, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    ret = uv_timer_init(&loop, &timer);
    if (ret < 0) std::cerr << "Error: Unable to initialize idle timer, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    // This is the idle timer for the server. Runs the function below every 5 seconds
    ret = uv_timer_start(&timer, [](uv_timer_t* t) {
        auto  loop{uv_handle_get_loop(reinterpret_cast<uv_handle_t*>(t))};
        auto& self{*reinterpret_cast<Internal*>(uv_loop_get_data(loop))};

        // Use erase_if to easily loop trough all sessions (and remove if stale)
        std::erase_if(self.sessions, [] (auto& session_pair) {
            using namespace std::chrono_literals;
            auto& session{session_pair.second};

            auto now = std::chrono::steady_clock::now();
            std::chrono::duration<double> session_age{now - session.last_activity};
            if (!session.ws && session_age > 30s) {
                std::cout << "Removing inactive session " << session.id << std::endl;
                return true;
            }

            if (session.ws) {
                session.ws_ping_sent = std::chrono::steady_clock::now();
                auto status = session.ws->send("ping", uWS::OpCode::PING);
                if (status != std::remove_pointer<decltype(session.ws)>::type::SUCCESS) {
                    std::cerr << "Error: Unable to send websocket ping to client\n";
                }
            }

            return false;
        });
    }, 0, 5000);
    if (ret < 0) std::cerr << "Error: Unable to start idle timer, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    ret = uv_timer_init(&loop, &worker_timer);
    if (ret < 0) std::cerr << "Error: Unable to initialize worker timer, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    // Init our frame counter
    sample_buffer_[512] = 0;

    // This is the worker timer for the server. Runs the function below every 32ms
    ret = uv_timer_start(&worker_timer, [](uv_timer_t* t) {
        auto  loop{uv_handle_get_loop(reinterpret_cast<uv_handle_t*>(t))};
        auto& self{*reinterpret_cast<Internal*>(uv_loop_get_data(loop))};

        int fs = 16000; // Hz
        float tone_fq = 800.0; // Hz

        // Fill buffer from sine wave generated with sin(2 * PI * f) @ 16kHz
        for (int i = 0; i < 512; i++) {
            self.sample_buffer_[i] = (short)(std::sin(2.0 * std::numbers::pi * tone_fq * (float)self.sample_idx_ / (float)fs) * (float)SHRT_MAX / 10.0);
            self.sample_idx_++;
            if (self.sample_idx_ == fs) self.sample_idx_ = 0;
        }

        // Update frame counter
        self.sample_buffer_[512]++;

        // Loop over active sessions and send data if active websockets connection exist
        for (auto& [id, session] : self.sessions) {
            if (session.ws) {
                std::string_view data{(char*)self.sample_buffer_, 1026};
                auto status = session.ws->send(data, uWS::OpCode::BINARY);
                if (status != std::remove_pointer<decltype(session.ws)>::type::SUCCESS) {
                    std::cerr << "Error: Unable to send ws message\n";
                }
            }
        }

        uv_update_time(loop);
    }, 0, 32);
    if (ret < 0) std::cerr << "Error: Unable to start worker timer, ret = " << ret << "(" << uv_strerror(ret) << ")\n";
    uv_timer_set_repeat(&worker_timer, 32);

    // Attach the uWS Loop to our uv_loop in this thread
    uWS::Loop::get(&loop);

    // Don't really know what this is for, but trying it for the time being
    uWS::Loop::get()->integrate();

    // Do not send server name on HTTP Response
    uWS::Loop::get()->setSilent(true);

    std_app = std::move(std::make_unique<uWS::App>());
    std_app->filter([&](auto* res, int con) {
        if (con == 1) {
            std::string remote_addr{res->getRemoteAddressAsText()};
            int         remote_port{us_socket_remote_port(0, reinterpret_cast<us_socket_t*>(res))};
            std::cout << "Incoming http connection from " + remote_addr + ":" << remote_port << " to server " << this << std::endl;
            // If we like to have ban on IP-addresses, we could just do res->close() here
            // to reset the incoming connection
        } else if (con == -1) {
            std::cout << "Client disconnected from server " << this << "\n\n";
        }
    }).any("/*", [&](auto* res, auto* req) {
        // Catch all with 404
        std::string method{req->getCaseSensitiveMethod()};
        std::string url{req->getUrl()};
        std::string query{req->getQuery()};

        std::cout << "Denying " << method << " " << url << (query.empty() ? "":query) << std::endl;

        res->writeStatus("404 Not Found");
        res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
    //}).get("/*", [&](uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    }).get("/*", [&](auto* res, auto* req) {
        std::string url{req->getUrl()};
        if (url == "/") url = "/index.html";
        std::string file_path = settings_.webroot + url;

        // TODO: Add prevention for breaking out of the webroot
        std::cout << "Incoming GET " << file_path << " to server " << this << std::endl;

        // Check if the file exists
        if (std::filesystem::is_regular_file(file_path) && !std::filesystem::is_symlink(file_path)) {
            std::string content = read_file(file_path);

            auto now = std::chrono::steady_clock::now();

            std::string cookie{req->getHeader("cookie")};
            std::cout << "Incoming cookie: " << cookie << ". Looking for session...\n";
            auto session_map = sessions.find(cookie);
            if (session_map != sessions.end()) {
                // Session found
                std::cout << "Session " << cookie << " found\n";
                session_map->second.last_activity = now;
            } else {
                // Create new session
                std::cout << "No active session, creating new\n";
                std::string id{get_session_id()};
                std::cout << "New session: " << id << "\n";
                sessions[id] = Session({ .id = id, .last_activity = now });

                res->writeHeader("Set-Cookie", id + "; SameSite=Strict");
            }

            // Determine content type based on file extension
            std::string contentType = "text/plain";
            if (file_path.ends_with(".html")) {
                contentType = "text/html";
            } else if (file_path.ends_with(".css")) {
                contentType = "text/css";
            } else if (file_path.ends_with(".js")) {
                contentType = "application/javascript";
            } else if (file_path.ends_with(".jpg") || file_path.ends_with(".jpeg")) {
                contentType = "image/jpeg";
            } else if (file_path.ends_with(".png")) {
                contentType = "image/png";
            }

            // Send the file content
            res->writeHeader("Content-Type", contentType)->end(content);
        } else {
            // File not found
            res->writeStatus("404 Not Found");
            res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
        }
    //}).post("/auth/login", [&](uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    }).post("/auth/login", [&](auto* res, auto* req) {
        std::string url{req->getUrl()};

        std::cout << "Logging in\n";
        res->writeHeader("Content-Type", "application/json")->end("{ \"success\": true }\n");
    //}).post("/auth/logout", [&](uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    }).post("/auth/logout", [&](auto* res, auto* req) {
        std::string url{req->getUrl()};

        std::cout << "Logging out\n";
        res->writeHeader("Content-Type", "application/json")->end("{ \"success\": true }\n");
    });

    std_app->ws<WsConData>("/ws", {
        // Settings
        .compression = uWS::SHARED_COMPRESSOR,
        .maxPayloadLength = 16 * 1024,
        .idleTimeout = 10,
        .maxBackpressure = 1 * 1024 * 1024,
        .sendPingsAutomatically = false,
        // Handlers
        .upgrade = [&](auto* res, auto* req, auto* context) {
            std::string cookie{req->getHeader("cookie")};
            std::cout << "Incoming WS UPGRADE. Cookie: " << cookie << ". Looking for session...\n";
            auto session_pair = sessions.find(cookie);
            if (session_pair != sessions.end()) {
                // Session found
                std::cout << "Session " << cookie << " found. Accepting WS UPGRADE\n";
                res->template upgrade<WsConData>(
                    { .session = &session_pair->second },
                    req->getHeader("sec-websocket-key"),
                    req->getHeader("sec-websocket-protocol"),
                    req->getHeader("sec-websocket-extensions"),
                    context
                );
            } else {
                std::cout << "No session found for cookie " << cookie << ". Denying upgrade.\n";
                res->writeStatus("404 Not Found");
                res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
            }
        },
        .open = [&](auto* ws) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);
            session.ws = ws;
            std::cout << "WebSocket connection for session " << session.id << " opend\n";
        },
        .message = [&](auto* ws, std::string_view message, uWS::OpCode op_code) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            if (op_code == uWS::OpCode::TEXT) {
                std::cout << "ws.message(), message = " << message << " from session " << session.id << std::endl;
            } else if (op_code == uWS::OpCode::BINARY) {
                std::cout << "ws.message(), message = 0x";
                auto it = message.begin();
                while (it != message.end()) {
#ifdef USE_FORMAT
                    std::cout << std::format("{:#04x}", *it);
#endif
                    ++it;
                }
                std::cout << "\n";
            } else {
                std::cerr << "Error: Unknown opcoded received from client\n";
            }
        },
        .drain = [](auto* /*ws*/) {
            // Check ws->getBufferedAmount() here
        },
        .ping = [&](auto* /*ws*/, std::string_view message) {
            // You don't need to handle this one, we automatically respond to pings as per standard
            std::cout << ": ws.ping(), message = " << message << std::endl;
        },
        .pong = [&](uWS::WebSocket<false, true, WsConData>* ws, std::string_view message) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);
            const auto now = std::chrono::steady_clock::now();

            const std::chrono::duration<double> rtt = now - session.ws_ping_sent;

            session.rtt = rtt.count() * 1000.0;
#ifdef USE_FORMAT
            session.rtt_str = std::format("{:.1f}", session.rtt);
#else
            session.rtt_str = "dummy";
#endif
            std::cout << "Received pong from client associated with session " << session.id << ". RTT = " <<
                         session.rtt_str << "ms, message = " << message << std::endl;
        },
        .close = [&](auto* ws, int code, std::string_view message) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            std::cout << "ws closed for session " << session.id << ". code = " << code << ", message = " << message << std::endl;

            session.ws = nullptr;
        }
    });

    for (auto &socket : settings_.std_sockets) {
        std::string addr{socket.first};
        int         port{socket.second};
        std_app->listen(addr, port, LIBUS_LISTEN_EXCLUSIVE_PORT, [this, addr, port](auto* listen_socket) {
            std::string tmp{addr};
            if (tmp.find(':') != std::string::npos) tmp = "[" + addr + "]";

            if (listen_socket) {
                std::cout << "Listening on http://" << tmp << ":" << port << " for server " << this << std::endl;
            } else {
                std::cerr << "Error: Unable to listen on http://" << tmp << ":" << port << " for server " << this << ". Invalid or busy host/port\n";
            }
        });
    }

    if (!settings_.crt_file.empty() && !settings_.key_file.empty() && !settings_.tls_sockets.empty()) {
        uWS::SocketContextOptions tls_options{
            .key_file_name  = settings_.key_file.c_str(),
            .cert_file_name = settings_.crt_file.c_str()
        };

        tls_app = std::move(std::make_unique<uWS::SSLApp>(tls_options));
        tls_app->filter([&](auto* res, int con) {
            if (con == 1) {
                std::string remote_addr{res->getRemoteAddressAsText()};
                int         remote_port{us_socket_remote_port(1, reinterpret_cast<us_socket_t*>(res))};
                std::cout << "Incoming https connection from " + remote_addr + ":" << remote_port << " to server " << this << std::endl;
            } else if (con == -1) {
                std::cout << "Client disconnected\n\n";
            }
        }).any("/*", [&](auto* res, auto* req) {
            // Catch all with 404
            std::cout << "Path " << req->getUrl() << " does not exist.\n";
            res->writeStatus("404 Not Found");
            res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
        //}).get("/*", [&](uWS::HttpResponse<true>* res, uWS::HttpRequest *req) {
        }).get("/*", [&](auto* res, auto *req) {
            std::string url{req->getUrl()};
            if (url == "/") url = "/index.html";
            std::string file_path = settings_.webroot + url;

            // TODO: Add prevention for breaking out of the webroot
            std::cout << "Incoming GET " << file_path << " to server " << this << std::endl;

            // Check if the file exists
            if (std::filesystem::is_regular_file(file_path) && !std::filesystem::is_symlink(file_path)) {
                std::string content = read_file(file_path);

                // Determine content type based on file extension
                std::string contentType = "text/plain";
                if (file_path.ends_with(".html")) {
                    contentType = "text/html";
                } else if (file_path.ends_with(".css")) {
                    contentType = "text/css";
                } else if (file_path.ends_with(".js")) {
                    contentType = "application/javascript";
                } else if (file_path.ends_with(".jpg") || file_path.ends_with(".jpeg")) {
                    contentType = "image/jpeg";
                } else if (file_path.ends_with(".png")) {
                    contentType = "image/png";
                }

                // Send the file content
                res->writeHeader("Content-Type", contentType)->end(content);
            } else {
                // File not found
                res->writeStatus("404 Not Found");
                res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
            }
        });

        // This should be a POST only endpoint used just for authentication
        // with mTLS
        if (!settings_.auth_hostname.empty() && !settings_.client_ca_file.empty()) {
            // If the constructor failed above, all calls below will become "no-ops"
            tls_app->addServerName(settings_.auth_hostname, {
                .key_file_name  = settings_.key_file.c_str(),
                .cert_file_name = settings_.crt_file.c_str(),
                .ca_file_name   = settings_.client_ca_file.c_str()
            //}).domain(settings_.auth_hostname).get("/*", [&](uWS::HttpResponse<true>* res, uWS::HttpRequest*) {
            }).domain(settings_.auth_hostname).get("/*", [&](auto* res, auto*) {
                std::string remote_addr{res->getRemoteAddressAsText()};
                int         remote_port{us_socket_remote_port(1, reinterpret_cast<us_socket_t*>(res))};
                std::cout << "Incoming https GET to auth from " + remote_addr + ":" << remote_port << " to server " << this << std::endl;

                SSL* ssl = reinterpret_cast<SSL*>(res->getNativeHandle());
                assert(ssl != nullptr);

                // See x509_vfy.h for possible return values
                long ssl_verify_result = SSL_get_verify_result(ssl);
                std::cout << "ssl_verify_result() == " << ssl_verify_result << std::endl;

                std::string c;
                std::string o;
                std::string ou;
                std::string cn;

                auto peer_cert = SSL_get0_peer_certificate(ssl);
                if (peer_cert) {
                    std::cout << "Client provided a valid certificate!\n";

                    auto sn_obj = X509_get_subject_name(peer_cert);
                    if (sn_obj != nullptr) {
                        int len;
                        char tmp_str[128];

                        len = X509_NAME_get_text_by_NID(sn_obj, NID_countryName, tmp_str, sizeof(tmp_str));
                        if (len > 0) c.assign(tmp_str, len);

                        len = X509_NAME_get_text_by_NID(sn_obj, NID_organizationName, tmp_str, sizeof(tmp_str));
                        if (len > 0) o.assign(tmp_str, len);

                        len = X509_NAME_get_text_by_NID(sn_obj, NID_organizationalUnitName, tmp_str, sizeof(tmp_str));
                        if (len > 0) ou.assign(tmp_str, len);

                        len = X509_NAME_get_text_by_NID(sn_obj, NID_commonName, tmp_str, sizeof(tmp_str));
                        if (len > 0) cn.assign(tmp_str, len);
                    }

                    std::cout << "Client certificate subject: C=" << c << ", O=" << o << ", OU=" << ou << ", CN=" << cn << std::endl;
                } else {
                    std::cout << "No cert provided by the client.\n";
                }

                res->writeHeader("Content-Type", "text/plain");
                res->end("Greetings from " + settings_.auth_hostname + "\n" + "Your CN='" + cn + "'\n");
            });
        }

        for (auto &socket : settings_.tls_sockets) {
            std::string addr{socket.first};
            int         port{socket.second};
            tls_app->listen(addr, port, LIBUS_LISTEN_EXCLUSIVE_PORT, [this, addr, port](auto* listen_socket) {
                std::string tmp{addr};
                if (tmp.find(':') != std::string::npos) tmp = "[" + addr + "]";

                if (listen_socket) {
                    std::cout << "Listening on https://" << tmp << ":" << port << " for server " << this << std::endl;
                } else {
                    std::cerr << "Error: Unable to listen on https://" << tmp << ":" << port << " for server " << this << ". ";
                    if (tls_app->constructorFailed()) {
                        std::cerr << "Invalid TLS configuration (cert/key/ca)\n";
                    } else {
                        std::cerr << "Invalid or busy host/port\n";
                    }
                }
            });
        }
    }

    // Start the loop. Blocks until call to uv_stop()
    ret = uv_run(&loop, UV_RUN_DEFAULT);
    //if (ret != 0) std::cerr << "Status: Loop still has stuff to handle, main invocation of uv_run() returned " << ret << "\n";

    {
        // uWs apps need to be closed here and a call to uv_run() needed as
        // well to clean up libuv stuff
        if (std_app) std_app->close();
        if (tls_app) {
            tls_app->close();
            tls_app->removeServerName(settings_.auth_hostname);
        }
        ret = uv_run(&loop, UV_RUN_NOWAIT);
        //if (ret != 0) std::cerr << "Status: Loop still has stuff to handle, second invocation of uv_run() returned " << ret << "\n";

        // Ugly hack to make the two apps go out of scope before we free() the loop
        auto tmp_std_app = std::move(std_app);
        auto tmp_tls_app = std::move(tls_app);
    }

    // Detach the uWS Loop from our uv_loop
    uWS::Loop::get()->free();

    // Stop worker_timer
    uv_timer_stop(&worker_timer);
    uv_close(reinterpret_cast<uv_handle_t*>(&worker_timer), nullptr);

    // Stop timer
    uv_timer_stop(&timer);
    uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);

    // Stop quit poll
    uv_poll_stop(&ctrl_poll);
    uv_close(reinterpret_cast<uv_handle_t*>(&ctrl_poll), nullptr);

    // Final uv cleanup (yes, libuv is strange...)
    ret = uv_run(&loop, UV_RUN_NOWAIT);
    //if (ret != 0) std::cerr << "Status: Loop still has stuff to handle, third invocation of uv_run() returned " << ret << "\n";

    ret = uv_loop_close(&loop);
    if (ret < 0) std::cerr << "Error: Failed to close uv_loop, ret = " << ret << "(" << uv_strerror(ret) << ")\n";

    std::cout << "Worker stopped for server " << this << std::endl;
}


//
// External interface
//
Server::Server() {
}

Server::Server(const Settings& settings)
: internal_(std::make_unique<Internal>(settings)) {
}

Server::Server(Server&& other)
: internal_(std::move(other.internal_)) {
}

Server& Server::operator=(Server&& other) {
    stop();
    internal_ = std::move(other.internal_);
    return *this;
}

void Server::restart(const Settings& settings) {
    if (internal_) internal_->restart(settings);
}

void Server::start() {
    if (internal_) internal_->start();
}

void Server::stop() {
    if (internal_) internal_->stop();
}

Server::~Server() {
}
