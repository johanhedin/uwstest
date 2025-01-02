#include <unistd.h>

#include <iostream>
#include <csignal>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <cassert>

#include <uv.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "App.h"

static std::function<void(int)> signal_callback = nullptr;
static void signal_handler(int signal) { signal_callback(signal); }

static std::function<void(uv_poll_t*)> ctrl_callback = nullptr;
static void ctrl_handler(uv_poll_t *poll, int, int) { ctrl_callback(poll); }

class StdSocket {
public:
    std::string addr{"0.0.0.0"};
    int port{8080};
};

class TlsHost {
public:
    std::string name{};
    std::string server_crt{};
    std::string server_key{};
    std::string client_ca{};
};

class TlsSocket : public StdSocket {
public:
    std::vector<TlsHost> hosts;
};


void webserver_thread(int ctrl_fd) {
    int ret;
    std::vector<uWS::App>    std_apps;
    std::vector<uWS::SSLApp> ssl_apps;
    uv_loop_t uv_loop;
    uv_loop_init(&uv_loop);

    uv_poll_t ctrl_poll;
    uv_poll_init(&uv_loop, &ctrl_poll, ctrl_fd);

    ctrl_callback = [&](uv_poll_t *poll) -> void {
        char cmd{'X'};
        int ret;
        int fd;

        uv_fileno(reinterpret_cast<uv_handle_t*>(poll), &fd);
        ret = read(fd, &cmd, 1);
        if (ret < 0) {
            std::cerr << "Error: Unable to read command from command pipe, ret = " << ret << std::endl;
            return;
        }

        switch (cmd) {
            case 'Q':
                std::cout << "Quit command received" << std::endl;
                uv_poll_stop(poll);
                for (auto &app: std_apps) { app.close(); }
                for (auto &app: ssl_apps) { app.close(); }
                break;
            default:
                std::cerr << "Error: Unknown command received (" << cmd << ")\n";
                break;
        }
    };
    uv_poll_start(&ctrl_poll, UV_READABLE, ctrl_handler);

    // Attach uWS to our uv_loop
    uWS::Loop::get(&uv_loop)->setSilent(true);

    // ***
    std::string name;
    std::string addr;
    int         port;

    name = "std_app"; addr = "0.0.0.0"; port = 8080;
    std_apps.emplace_back(uWS::App(
    )).filter([name](auto *res, int con) {
        if (con == 1) {
            std::string remote_addr(res->getRemoteAddressAsText());
            int         remote_port = us_socket_remote_port(0, reinterpret_cast<us_socket_t*>(res));
            std::cout << name << ": Incoming connection from " + remote_addr + ":" << remote_port << std::endl;
        } else if (con == -1) {
            std::cout << name << ": Client disconnected\n\n";
        } else {
            std::cerr << name << ": Error: Invalid filter con value (" << con << ")\n";
        }
    }).any("/*", [name](auto *res, auto *req) {
        // Catch all with 404
        std::cout << name << ": Path " << req->getUrl() << " does not exist.\n";
        res->writeStatus("404 Not Found");
        res->writeHeader("Content-Type", "text/plain");
        res->end("Not Found\n");
    }).get("/api", [name](auto *res, auto *req) {
        std::string remote_addr(res->getRemoteAddressAsText());
        int         remote_port = us_socket_remote_port(0, reinterpret_cast<us_socket_t*>(res));
        std::string host{"none"};
        for (auto hdr : *req) {
            if (hdr.first == "host") {
                host = hdr.second;
                break;
            }
        }

        std::cout << name << ": Incoming GET to " << host << " from " << remote_addr << ":" << remote_port << std::endl;
        res->writeHeader("Content-Type", "text/plain");
        res->end("Greetings from µWebSockets@" + name + "\n");
    }).listen(addr, port, [name, addr, port](auto *listen_socket) {
        if (listen_socket) {
            std::cout << name << ": Listening on " << addr << ":" << port << std::endl;
        } else {
            std::cerr << name << ": Error: Unable to listen to " << addr << ":" << port << std::endl;
        }
    });

    name = "tls_app"; addr = "0.0.0.0"; port = 8443;
    ssl_apps.emplace_back(uWS::SSLApp({
        .key_file_name = "../srv.key",
        .cert_file_name = "../srv.crt"
    })).addServerName("auth.xps.local", {
        .key_file_name = "../srv.key",
        .cert_file_name = "../srv.crt",
        .ca_file_name = "../ttt-root-ca-01.crt"
    }).filter([name](auto *res, int con) {
        if (con == 1) {
            std::string remote_addr(res->getRemoteAddressAsText());
            int         remote_port = us_socket_remote_port(1, reinterpret_cast<us_socket_t*>(res));
            std::cout << name << ": Incoming connection from " + remote_addr + ":" << remote_port << std::endl;
        } else if (con == -1) {
            std::cout << name << ": Client disconnected\n\n";
        } else {
            std::cerr << name << ": Error: Invalid filter con value (" << con << ")\n";
        }
    }).get("/*", [name](auto *res, auto *) {
        std::string remote_addr(res->getRemoteAddressAsText());
        int         remote_port = us_socket_remote_port(1, reinterpret_cast<us_socket_t*>(res));
        std::cout << name << ": (catch-all context): Incoming GET from " << remote_addr << ":" << remote_port<< std::endl;
        res->writeHeader("Content-Type", "text/plain");
        res->end("Greetings from catch-all context!\n");
    }).domain("auth.xps.local").get("/*", [name](auto *res, auto *req) {
        std::string remote_addr(res->getRemoteAddressAsText());
        int         remote_port = us_socket_remote_port(1, reinterpret_cast<us_socket_t*>(res));
        std::cout << name << ": (auth.xps.local context): Incoming GET from " << remote_addr << ":" << remote_port<< std::endl;

        std::cout << name << ": Request headers:" << std::endl;
        for (auto hdr : *req) {
            std::cout << name << ":    " << hdr.first << ": " << hdr.second << std::endl;
            if (hdr.first == "x-uwstest-ext" && hdr.second == "forbidden") {
                res->writeStatus("403 Forbidden");
                res->writeHeader("Content-Type", "text/plain");
                res->end("Forbidden\n");
                return;
            }
        }

        SSL *ssl = reinterpret_cast<SSL*>(res->getNativeHandle());
        assert(ssl != nullptr);

        long ssl_verify_result = SSL_get_verify_result(ssl);
        std::cout << name << ": ssl_verify_result() == " << ssl_verify_result << std::endl;

        std::string c;
        std::string o;
        std::string ou;
        std::string cn;

        auto peer_cert = SSL_get_peer_certificate(ssl);
        if (peer_cert) {
            std::cout << name << ": Client provided a valid certificate!\n";

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

            std::cout << name << ": Client certificate subject: C=" << c << ", O=" << o << ", OU=" << ou << ", CN=" << cn << std::endl;

            X509_free(peer_cert);
        } else {
            std::cout << name << ": No peer cert provided by the client.\n";
        }

        res->writeHeader("Content-Type", "text/plain");
        res->end("Greetings from " + name + " auth.xps.local context!\n" + "Your CN='" + cn + "'\n");
    }).listen(addr, port, [name, addr, port](auto *listen_socket) {
        if (listen_socket) {
            std::cout << name << ": Listening on " << addr << ":" << port << std::endl;
        } else {
            std::cerr << name << ": Error: Unable to listen to " << addr << ":" << port << std::endl;
        }
    });
    // ***

    // Run the event loop. Will block until all polls are stopped
    ret = uv_run(&uv_loop, UV_RUN_DEFAULT);

    // Need to cleanup "virtual servers" for TLS
    for (auto &app: ssl_apps) { app.removeServerName("auth.xps.local"); }

    // Run destructors for all uWS apps
    std_apps.clear();
    ssl_apps.clear();

    // Detach uWS from our uv_loop
    uWS::Loop::get()->free();

    // Loop through all remaining handles and close them
    uv_walk(&uv_loop, [](uv_handle_t* handle, void*) -> void {
        uv_close(handle, nullptr);
        uv_run(uv_handle_get_loop(handle), UV_RUN_ONCE);
    }, nullptr);

    ret = uv_loop_close(&uv_loop);
    std::cout << "uv_loop_close() returned, ret = " << ret << "\n";
}


int main(int, char**) {
    std::cout << "Hello µWebSockets!\n";

    // Signal handling. We use a mutex protected deque to "send" caught signals
    // to the main thread (see further down). SIGINT/SIGTERM have priority.
    std::deque<int> sq;
    std::mutex sq_mutex;
    std::condition_variable sq_cv;
    signal_callback = [&sq, &sq_mutex, &sq_cv](int signal) -> void {
        std::unique_lock<std::mutex> sq_lock{sq_mutex};
        if (signal == SIGTERM || signal == SIGINT) {
            sq.push_front(signal);
        } else {
            sq.push_back(signal);
        }
        sq_lock.unlock();
        sq_cv.notify_one();
    };
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGHUP,  signal_handler);

    // Control pipe to the webserver thread
    int ctrl_pipe[2];
    pipe(ctrl_pipe);

    auto t = std::thread(webserver_thread, ctrl_pipe[0]);

    // Main loop
    bool run{true};
    while (run) {
        using namespace std::chrono_literals;
        std::unique_lock<std::mutex> sq_lock{sq_mutex};
        if (sq.empty()) {
            sq_cv.wait_for(sq_lock, 10s, [&sq](){ return !sq.empty(); });
            if (sq.empty()) {
                sq_lock.unlock();
                // Do maintanace tasks every 10s
            }
        } else {
            auto signal = sq.front();
            sq.pop_front();
            sq_lock.unlock();
            switch (signal) {
                case SIGTERM:
                case SIGINT:
                    run = false;
                    write(ctrl_pipe[1], "Q", 1);
                    break;
                case SIGHUP:
                    // Do nothing
                    std::cout << "SIGHUP received\n";
                    break;
                default:
                    // Ignore "unknown" signals
                    break;
            }
        }
    }

    t.join();

    close(ctrl_pipe[0]);
    close(ctrl_pipe[1]);

    return 0;
}
