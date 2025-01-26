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
#include <format>
#else
#include <fmt/core.h>
namespace std { using fmt::format; } // std::format polyfill using fmt
#endif
#include <cmath>
#include <limits>
#include <numbers>
#include <cassert>

// C libraires that we use
#include <uv.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

// Internal includes
#include "logging.hpp"
#include "App.h"


// Sleeping:
// - https://blat-blatnik.github.io/computerBear/making-accurate-sleep-function
// - https://bulldozer00.blog/2013/12/27/periodic-processing-with-standard-c11-facilities

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
    constexpr static bool STD = false;
    constexpr static bool TLS = true;
    constexpr static bool SERVER = true;

    class Session;
    struct WsConData {
        Session* session;
    };

    struct Session {
        std::string                                        id{};
        std::chrono::steady_clock::time_point              last_activity{};
        std::chrono::steady_clock::time_point              ws_ping_sent{};
        uWS::WebSocket<STD, SERVER, WsConData>*            std_ws{nullptr};
        uWS::WebSocket<TLS, SERVER, WsConData>*            tls_ws{nullptr};
        double                                             rtt{0.0};
        int                                                client_buffer_depth{0};
        bool                                               buff_depth_updated{false};
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
        std::string rs = std::format("{:016x}", rn);
        return rs;
    };

    void worker_(void);
    void send_audio_(void);
};


Server::Internal::Internal(const Server::Settings& settings)
: settings_(settings), running_(false), random_generator_(random_device_()),
  random_distribution_(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max()) {
    // Init our frame counter
    sample_buffer_[512] = 0;

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
        t_ = std::thread(&Internal::worker_, this);
    }
}

void Server::Internal::stop() {
    std::unique_lock<std::mutex> lock{m_};
    if (running_) {
        running_ = false;
        write(ctrl_pipe[1], "Q", 1);
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
    int       ret;
    uv_loop_t loop;

    spdlog::info("Server worker started");
    spdlog::info("Settings:");
    std::cout << "    std_sockets="; for (auto& s : settings_.std_sockets) { std::cout << s.first << ":" << s.second << " "; }; std::cout << std::endl;
    std::cout << "    tls_sockets="; for (auto& s : settings_.tls_sockets) { std::cout << s.first << ":" << s.second << " "; }; std::cout << std::endl;
    std::cout << "    crt_file=" << settings_.crt_file << std::endl;
    std::cout << "    key_file=" << settings_.key_file << std::endl;
    std::cout << "    client_ca_file=" << settings_.client_ca_file << std::endl;
    std::cout << "    auth_hostname=" << settings_.auth_hostname << std::endl;
    std::cout << "    webroot=" << settings_.webroot << std::endl;

    ret = uv_loop_init(&loop);
    if (ret < 0) spdlog::error("Unable to create uv_loop, ret = {} ({})", ret, uv_strerror(ret));

    // Attach our instance to the loop. Can be used in callbacks later on to get "this"
    uv_loop_set_data(&loop, reinterpret_cast<void*>(this));

    // Create a uv_poll to watch on the quit pipe
    uv_poll_t ctrl_poll;
    ret = uv_poll_init(&loop, &ctrl_poll, ctrl_pipe[0]);
    if (ret < 0) spdlog::error("Unable to initialize ctrl_poll, ret = {} ({})", ret, uv_strerror(ret));

    ret = uv_poll_start(&ctrl_poll, UV_READABLE, [](uv_poll_t* p, int, int) {
        auto handle = reinterpret_cast<uv_handle_t*>(p);
        char cmd{'X'};
        int  ret;
        int  fd;

        uv_fileno(handle, &fd);
        ret = read(fd, &cmd, 1);
        if (ret < 0) {
            spdlog::error("Unable to read command from command pipe, ret = {} ({})", ret, strerror(errno));
            return;
        }

        switch (cmd) {
            case 'Q':
                uv_stop(uv_handle_get_loop(handle));
                break;
            default:
                spdlog::error("Unknown command received ({})", cmd);
                break;
        }
    });
    if (ret < 0) spdlog::error("Unable to start ctrl_poll, ret = {} ({})", ret, uv_strerror(ret));

    // Create a uv_timer for periodic maintenance work. It is called every 5000ms
    uv_timer_t maintenance_timer;
    ret = uv_timer_init(&loop, &maintenance_timer);
    if (ret < 0) spdlog::error("Unable to initialize maintenance timer, ret = {} ({})", ret, uv_strerror(ret));

    ret = uv_timer_start(&maintenance_timer, [](uv_timer_t* t) {
        auto  loop = uv_handle_get_loop(reinterpret_cast<uv_handle_t*>(t));
        auto& self = *reinterpret_cast<Internal*>(uv_loop_get_data(loop));

        // Loop through all sessions and remove inactive ones. Send WebSockes ping to active ones
        auto session_pair = self.sessions.begin();
        while (session_pair != self.sessions.end()) {
            using namespace std::chrono_literals;
            auto& session = session_pair->second;

            auto session_age = std::chrono::steady_clock::now() - session.last_activity;
            if (!session.std_ws && !session.tls_ws && session_age > 30s) {
                spdlog::info("[----------------] [{}] Removing inactive session", session.id);
                session_pair = self.sessions.erase(session_pair);
                continue;
            }

            if (session.std_ws) {
                session.ws_ping_sent = std::chrono::steady_clock::now();
                auto status = session.std_ws->send("ping", uWS::OpCode::PING);
                if (status != std::remove_pointer<decltype(session.std_ws)>::type::SUCCESS) {
                    spdlog::error("[{:016x}] [{}] Unable to send websocket ping to client", reinterpret_cast<uint64_t>(session.std_ws), session.id);
                }
                spdlog::info("[{:016x}] [{}] rtt = {:.1f}ms, client_buffer_depth = {}", reinterpret_cast<uint64_t>(session.std_ws), session.id, session.rtt, session.client_buffer_depth);
            }

            if (session.tls_ws) {
                session.ws_ping_sent = std::chrono::steady_clock::now();
                auto status = session.tls_ws->send("ping", uWS::OpCode::PING);
                if (status != std::remove_pointer<decltype(session.tls_ws)>::type::SUCCESS) {
                    spdlog::error("[{:016x}] [{}] Unable to send websocket ping to client", reinterpret_cast<uint64_t>(session.tls_ws), session.id);
                }
                spdlog::info("[{:016x}] [{}] rtt = {:.1f}ms, client_buffer_depth = {}", reinterpret_cast<uint64_t>(session.tls_ws), session.id, session.rtt, session.client_buffer_depth);
            }

            ++session_pair;
        }
    }, 0, 5000);
    if (ret < 0) spdlog::error("Unable to start maintenance timer, ret = {} ({})", ret, uv_strerror(ret));

    // Create a poll and timer to create a function that is calles every 32ms
    int        audio_pipe[2];
    uv_poll_t  audio_poll;

    pipe(audio_pipe);

    uv_poll_init(&loop, &audio_poll, audio_pipe[0]);
    uv_poll_start(&audio_poll, UV_READABLE, [](uv_poll_t* p, int, int) {
        auto  handle = reinterpret_cast<uv_handle_t*>(p);
        auto  loop = uv_handle_get_loop(handle);
        auto& self = *reinterpret_cast<Internal*>(uv_loop_get_data(loop));
        char  cmd{};
        int   fd;

        uv_fileno(handle, &fd);
        read(fd, &cmd, 1);

        self.send_audio_();
    });

    // Pacer in it's own thread to get accurate 32ms wakeups
    auto t = std::thread([&]() {
        using namespace std::chrono_literals;

        auto wakeup = std::chrono::steady_clock::now();
        while (running_) {
            wakeup = wakeup + 32ms;
            std::this_thread::sleep_until(wakeup);
            write(audio_pipe[1], "W", 1);
        }
    });

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
            spdlog::info("[{:016x}] [----------------] Incoming http connection from {}:{}", reinterpret_cast<uint64_t>(res), remote_addr, remote_port);
            // If we like to have ban on IP-addresses, we could just do res->close() here
            // to reset the incoming connection
        } else if (con == -1) {
            spdlog::info("[{:016x}] [????????????????] Client disconnected from server", reinterpret_cast<uint64_t>(res));
        }
    }).any("/*", [&](auto* res, auto* req) {
        // Catch all with 404
        std::string method{req->getCaseSensitiveMethod()};
        std::string url{req->getUrl()};
        std::string query{req->getQuery()};

        spdlog::warn("[{:016x}] [????????????????] Denying Request {} {}{}", reinterpret_cast<uint64_t>(res), method, url, (query.empty() ? "":query));

        res->writeStatus("404 Not Found");
        res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
    //}).get("/*", [&](uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    }).get("/*", [&](auto* res, auto* req) {
        std::string url{req->getUrl()};
        std::string cookie{req->getHeader("cookie")};

        if (url == "/") url = "/index.html";
        std::string requested_file = settings_.webroot + url;

        auto now = std::chrono::steady_clock::now();

        std::string id{"----------------"};
        auto session_map = sessions.find(cookie);
        if (session_map == sessions.end()) {
            if (sessions.size() < 10) {
                id = get_session_id();
                sessions[id] = Session({ .id = id, .last_activity = now });
                res->writeHeader("Set-Cookie", id + "; SameSite=Strict");
                spdlog::info("[{:016x}] [{}] Incoming Request. New session created", reinterpret_cast<uint64_t>(res), id);
            } else {
                spdlog::warn("[{:016x}] [{}] Incoming Request. Max number of sessions reached. Not creating a new one", reinterpret_cast<uint64_t>(res), id);
            }
        } else {
            session_map->second.last_activity = now;
            id = session_map->first;
        }

        spdlog::info("[{:016x}] [{}] GET {}", reinterpret_cast<uint64_t>(res), id, url);

        // Check if the file exists
        if (std::filesystem::is_regular_file(requested_file) && !std::filesystem::is_symlink(requested_file)) {
            std::string content = read_file(requested_file);

            // Determine content type based on file extension
            std::string contentType = "text/plain";
            if (requested_file.ends_with(".html")) {
                contentType = "text/html";
            } else if (requested_file.ends_with(".css")) {
                contentType = "text/css";
            } else if (requested_file.ends_with(".js")) {
                contentType = "application/javascript";
            } else if (requested_file.ends_with(".jpg") || requested_file.ends_with(".jpeg")) {
                contentType = "image/jpeg";
            } else if (requested_file.ends_with(".png")) {
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

            auto session_pair = sessions.find(cookie);
            if (session_pair != sessions.end()) {
                spdlog::info("[{:016x}] [{}] Accepting WebSocket upgrade", reinterpret_cast<uint64_t>(res), session_pair->first);
                res->template upgrade<WsConData>(
                    { .session = &session_pair->second },
                    req->getHeader("sec-websocket-key"),
                    req->getHeader("sec-websocket-protocol"),
                    req->getHeader("sec-websocket-extensions"),
                    context
                );
            } else {
                spdlog::warn("[{:016x}] [----------------] Denying WebSocket upgrade. No session found for cookie {}", reinterpret_cast<uint64_t>(res), cookie);
                res->writeStatus("404 Not Found");
                res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
            }
        },
        .open = [&](auto* ws) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);
            session.std_ws = ws;
            spdlog::info("[{:016x}] [{}] WebSocket connection opened", reinterpret_cast<uint64_t>(ws), session.id);
        },
        .message = [&](auto* ws, std::string_view message, uWS::OpCode op_code) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            if (op_code == uWS::OpCode::TEXT) {
                spdlog::info("[{:016x}] [{}] Message from client: {}", reinterpret_cast<uint64_t>(ws), session.id, message);
            } else if (op_code == uWS::OpCode::BINARY) {
                if (message.size() > 0) {
                    auto msg = message[0];
                    switch (msg) {
                        case 0x01:
                            if (message.size() == 2) {
                                session.client_buffer_depth = message[1];
                                session.buff_depth_updated = true;
                            } else {
                                spdlog::error("[{:016x}] [{}] Invalid length for message type 0x01", reinterpret_cast<uint64_t>(ws), session.id);
                            }
                            break;
                        default:
                            spdlog::error("[{:016x}] [{}] Unknown message type ({}) received from WebSocket client", reinterpret_cast<uint64_t>(ws), session.id, msg);
                            std::cerr << "message = 0x";
                            auto it = message.begin();
                            while (it != message.end()) {
                                std::cout << std::format("{:02x}", *it);
                                ++it;
                            }
                            std::cerr << std::endl;
                    }
                } else {
                    spdlog::error("[{:016x}] [{}] Empty PDU received from WebSocket client", reinterpret_cast<uint64_t>(ws), session.id);
                }
            } else {
                std::cerr << "Error: Unknown opcoded received from client\n";
            }
        },
        .drain = [&](auto*) {
            // Check ws->getBufferedAmount() here
        },
        .ping = [&](auto* /*ws*/, std::string_view /*message*/) {
            // You don't need to handle this one, we automatically respond to pings as per standard
        },
        //.pong = [&](uWS::WebSocket<STD, SERVER, WsConData>* ws, std::string_view message) {
        .pong = [&](auto* ws, std::string_view) {
            const auto now = std::chrono::steady_clock::now();
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            const std::chrono::duration<double> rtt = now - session.ws_ping_sent;
            session.rtt = rtt.count() * 1000.0;

            //spdlog::info("[{:016x}] [{}] WebSocket ping response from client. RTT = {:.1f}ms", reinterpret_cast<uint64_t>(ws), session.id, session.rtt);
        },
        .close = [&](auto* ws, int code, std::string_view message) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            spdlog::info("[{:016x}] [{}] WebSocket connection closed. Code = {}, Message = '{}'", reinterpret_cast<uint64_t>(ws), session.id, code, message);

            session.std_ws = nullptr;
        }
    });

    for (auto &socket : settings_.std_sockets) {
        std::string addr{socket.first};
        int         port{socket.second};
        std_app->listen(addr, port, LIBUS_LISTEN_EXCLUSIVE_PORT, [this, addr, port](auto* listen_socket) {
            std::string tmp{addr};
            if (tmp.find(':') != std::string::npos) tmp = "[" + addr + "]";

            if (listen_socket) {
                spdlog::info("Listening on http://{}:{}", tmp, port);
            } else {
                spdlog::error("Unable to listen on http://{}:{}. Invalid/busy host/port", tmp, port);
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
                spdlog::info("[{:016x}] [----------------] Incoming https connection from {}:{}", reinterpret_cast<uint64_t>(res), remote_addr, remote_port);
            } else if (con == -1) {
                spdlog::info("[{:016x}] [????????????????] Client disconnected from server", reinterpret_cast<uint64_t>(res));
            }
        }).any("/*", [&](auto* res, auto* req) {
            // Catch all with 404
            std::string method{req->getCaseSensitiveMethod()};
            std::string url{req->getUrl()};
            std::string query{req->getQuery()};

            spdlog::warn("[{:016x}] [????????????????] Denying Request {} {}{}", reinterpret_cast<uint64_t>(res), method, url, (query.empty() ? "":query));

            res->writeStatus("404 Not Found");
            res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
        //}).get("/*", [&](uWS::HttpResponse<true>* res, uWS::HttpRequest *req) {
        }).get("/*", [&](auto* res, auto* req) {
            std::string url{req->getUrl()};
            std::string cookie{req->getHeader("cookie")};

            if (url == "/") url = "/index.html";
            std::string requested_file = settings_.webroot + url;

            auto now = std::chrono::steady_clock::now();

            std::string id{"----------------"};
            auto session_map = sessions.find(cookie);
            if (session_map == sessions.end()) {
                if (sessions.size() < 10) {
                    id = get_session_id();
                    sessions[id] = Session({ .id = id, .last_activity = now });
                    res->writeHeader("Set-Cookie", id + "; SameSite=Strict");
                    spdlog::info("[{:016x}] [{}] Incoming Request. New session created", reinterpret_cast<uint64_t>(res), id);
                } else {
                    spdlog::warn("[{:016x}] [{}] Incoming Request. Max number of sessions reached. Not creating a new one", reinterpret_cast<uint64_t>(res), id);
                }
            } else {
                session_map->second.last_activity = now;
                id = session_map->first;
            }

            spdlog::info("[{:016x}] [{}] GET {}", reinterpret_cast<uint64_t>(res), id, url);

            // Check if the file exists
            if (std::filesystem::is_regular_file(requested_file) && !std::filesystem::is_symlink(requested_file)) {
                std::string content = read_file(requested_file);

                // Determine content type based on file extension
                std::string contentType = "text/plain";
                if (requested_file.ends_with(".html")) {
                    contentType = "text/html";
                } else if (requested_file.ends_with(".css")) {
                    contentType = "text/css";
                } else if (requested_file.ends_with(".js")) {
                    contentType = "application/javascript";
                } else if (requested_file.ends_with(".jpg") || requested_file.ends_with(".jpeg")) {
                    contentType = "image/jpeg";
                } else if (requested_file.ends_with(".png")) {
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

        tls_app->ws<WsConData>("/ws", {
            // Settings
            .compression = uWS::SHARED_COMPRESSOR,
            .maxPayloadLength = 16 * 1024,
            .idleTimeout = 10,
            .maxBackpressure = 1 * 1024 * 1024,
            .sendPingsAutomatically = false,
            // Handlers
            .upgrade = [&](auto* res, auto* req, auto* context) {
                std::string cookie{req->getHeader("cookie")};

                auto session_pair = sessions.find(cookie);
                if (session_pair != sessions.end()) {
                    spdlog::info("[{:016x}] [{}] Accepting WebSocket upgrade", reinterpret_cast<uint64_t>(res), session_pair->first);
                    res->template upgrade<WsConData>(
                        { .session = &session_pair->second },
                        req->getHeader("sec-websocket-key"),
                        req->getHeader("sec-websocket-protocol"),
                        req->getHeader("sec-websocket-extensions"),
                        context
                    );
                } else {
                    spdlog::warn("[{:016x}] [----------------] Denying WebSocket upgrade. No session found for cookie {}", reinterpret_cast<uint64_t>(res), cookie);
                    res->writeStatus("404 Not Found");
                    res->writeHeader("Content-Type", "text/plain")->end("404 Not Found\n");
                }
            },
            .open = [&](auto* ws) {
                Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);
                session.tls_ws = ws;
                spdlog::info("[{:016x}] [{}] WebSocket connection opened", reinterpret_cast<uint64_t>(ws), session.id);
            },
            .message = [&](auto* ws, std::string_view message, uWS::OpCode op_code) {
            Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

            if (op_code == uWS::OpCode::TEXT) {
                spdlog::info("[{:016x}] [{}] Message from client: {}", reinterpret_cast<uint64_t>(ws), session.id, message);
            } else if (op_code == uWS::OpCode::BINARY) {
                if (message.size() > 0) {
                    auto msg = message[0];
                    switch (msg) {
                        case 0x01:
                            if (message.size() == 2) {
                                session.client_buffer_depth = message[1];
                                session.buff_depth_updated = true;
                            } else {
                                spdlog::error("[{:016x}] [{}] Invalid length for message type 0x01", reinterpret_cast<uint64_t>(ws), session.id);
                            }
                            break;
                        default:
                            spdlog::error("[{:016x}] [{}] Unknown message type ({}) received from WebSocket client", reinterpret_cast<uint64_t>(ws), session.id, msg);
                            std::cerr << "message = 0x";
                            auto it = message.begin();
                            while (it != message.end()) {
                                std::cout << std::format("{:02x}", *it);
                                ++it;
                            }
                            std::cerr << std::endl;
                    }
                } else {
                    spdlog::error("[{:016x}] [{}] Empty PDU received from WebSocket client", reinterpret_cast<uint64_t>(ws), session.id);
                }
            } else {
                std::cerr << "Error: Unknown opcoded received from client\n";
            }
            },
            .drain = [&](auto*) {
                // Check ws->getBufferedAmount() here
            },
            .ping = [&](auto* /*ws*/, std::string_view /*message*/) {
                // You don't need to handle this one, we automatically respond to pings as per standard
            },
            //.pong = [&](uWS::WebSocket<TLS, SERVER, WsConData>* ws, std::string_view message) {
            .pong = [&](auto* ws, std::string_view) {
                const auto now = std::chrono::steady_clock::now();
                Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

                const std::chrono::duration<double> rtt = now - session.ws_ping_sent;
                session.rtt = rtt.count() * 1000.0;

                //spdlog::info("[{:016x}] [{}] WebSocket ping response from client. RTT = {:.1f}ms", reinterpret_cast<uint64_t>(ws), session.id, session.rtt);
            },
            .close = [&](auto* ws, int code, std::string_view message) {
                Session& session = *((reinterpret_cast<WsConData*>(ws->getUserData()))->session);

                spdlog::info("[{:016x}] [{}] WebSocket connection closed. Code = {}, Message = '{}'", reinterpret_cast<uint64_t>(ws), session.id, code, message);

                session.tls_ws = nullptr;
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

        for (auto& socket : settings_.tls_sockets) {
            std::string addr{socket.first};
            int         port{socket.second};
            tls_app->listen(addr, port, LIBUS_LISTEN_EXCLUSIVE_PORT, [this, addr, port](auto* listen_socket) {
                std::string tmp{addr};
                if (tmp.find(':') != std::string::npos) tmp = "[" + addr + "]";

                if (listen_socket) {
                    spdlog::info("Listening on https://{}:{}", tmp, port);
                } else {
                    if (tls_app->constructorFailed()) {
                        spdlog::error("Unable to listen on https://{}:{}. Invalid TLS configuration (cert/key/ca)", tmp, port);
                    } else {
                        spdlog::error("Unable to listen on https://{}:{}. Invalid/busy host/port", tmp, port);
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

    // Stop and cleanup the audio sequencer
    t.join();
    uv_poll_stop(&audio_poll);
    uv_close(reinterpret_cast<uv_handle_t*>(&audio_poll), nullptr);
    close(audio_pipe[0]);
    close(audio_pipe[1]);

    // Stop and cleanup the maintenance timer
    uv_timer_stop(&maintenance_timer);
    uv_close(reinterpret_cast<uv_handle_t*>(&maintenance_timer), nullptr);

    // Stop and cleanup the quit poll
    uv_poll_stop(&ctrl_poll);
    uv_close(reinterpret_cast<uv_handle_t*>(&ctrl_poll), nullptr);

    // Final uv cleanup (yes, libuv is strange...)
    ret = uv_run(&loop, UV_RUN_NOWAIT);
    //if (ret != 0) std::cerr << "Status: Loop still has stuff to handle, third invocation of uv_run() returned " << ret << "\n";

    ret = uv_loop_close(&loop);
    if (ret < 0) spdlog::error("Failed to close uv_loop, ret = {} ({})", ret, uv_strerror(ret));

    spdlog::info("Server worker stopped");
}

void Server::Internal::send_audio_(void) {
    int fs = 16000; // Hz
    float tone_fq = 800.0; // Hz

    // Fill buffer from sine wave generated with sin(2 * PI * f) @ 16kHz
    for (int i = 0; i < 512; i++) {
        float sample = std::sin(2.0f * std::numbers::pi * tone_fq * static_cast<float>(sample_idx_)/static_cast<float>(fs)) * std::numeric_limits<short>::max();
        sample_buffer_[i] = static_cast<short>(sample / 10.0f);
        if (++sample_idx_ == fs) sample_idx_ = 0;
    }

    // Update frame counter
    sample_buffer_[512]++;

    // Loop over active sessions and send data if active websockets connection exist
    for (auto& [id, session] : sessions) {
        // TODO: Investigate if uWS copies the data to be sent or not and move
        //       the buffer outside of the loop
        // TODO: Inspect client_buffer_depth and skip a frame here and there
        //       when the client buffer is "to full". Need to do it slowly through
        //       so that we can receive changes from the client
        std::string_view data{reinterpret_cast<char*>(sample_buffer_), 1026};
        if (session.std_ws) {
            if (session.buff_depth_updated && session.client_buffer_depth > 12) {
                spdlog::warn("[{:016x}] [{}] Skipping audio frame to client", reinterpret_cast<uint64_t>(session.std_ws), session.id);
            } else {
                auto status = session.std_ws->send(data, uWS::OpCode::BINARY);
                if (status != std::remove_pointer<decltype(session.std_ws)>::type::SUCCESS) {
                    spdlog::error("[{:016x}] [{}] Failed to send audio data to WebSocket client", reinterpret_cast<uint64_t>(session.std_ws), session.id);
                }
            }
            session.buff_depth_updated = false;
        }
        if (session.tls_ws) {
            if (session.buff_depth_updated && session.client_buffer_depth > 12) {
                spdlog::warn("[{:016x}] [{}] Skipping audio frame to client", reinterpret_cast<uint64_t>(session.std_ws), session.id);
            } else {
                auto status = session.tls_ws->send(data, uWS::OpCode::BINARY);
                if (status != std::remove_pointer<decltype(session.tls_ws)>::type::SUCCESS) {
                    spdlog::error("[{:016x}] [{}] Failed to send audio data to WebSocket client", reinterpret_cast<uint64_t>(session.std_ws), session.id);
                }
            }
            session.buff_depth_updated = false;
        }
    }
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
