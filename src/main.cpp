// Std C++ includes
#include <iostream>
#include <csignal>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <functional>
#include <chrono>
#include <filesystem>

// Internal includes
#include "logging.hpp"
#include "server.hpp"

// Some code for playing audio received via a websocket:
// https://github.com/nexmo-community/audiosocket-demo
// Explanation: https://developer.vonage.com/en/blog/streaming-calls-to-a-browser-with-voice-websockets-dr
// This also: https://medium.com/@sandeeplakhiwal/real-time-audio-streaming-in-react-js-handling-and-playing-live-audio-buffers-c72ec38c91fa
// https://developer.mozilla.org/en-US/docs/Web/API/AudioBufferSourceNode

// Trick to be able to use signal_callback as lambda
static std::function<void(int)> signal_callback = nullptr;
static void signal_handler(int signal) { signal_callback(signal); }


int main(int argc, char** argv) {
    spdlog::info("Hello µWSTest!");

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
        sq_cv.notify_one();
    };
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGHUP,  signal_handler);

    Server::Settings settings{
        .std_sockets = { {"127.0.0.1", 8080} },
        .webroot = "../webroot"
    };

    // If a key and certificate file exist in the directory above cwd, activate
    // TLS on 8443 as well
    if (std::filesystem::is_regular_file("../srv.key") && std::filesystem::is_regular_file("../srv.crt")) {
        settings.key_file = "../srv.key";
        settings.crt_file = "../srv.crt";
        settings.tls_sockets = { {"0.0.0.0", 8443} };

        // If a CA exist and an argument is given, activate client auth with TLS
        // as well. The argument is suppose to be the hostname for the auth
        // server
        if (std::filesystem::is_regular_file("../ca.crt") && argc > 1) {
            settings.client_ca_file = "../ca.crt";
            settings.auth_hostname = argv[1];
        }
    }

    Server s1{settings};

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
                    break;
                case SIGHUP:
                    // Do nothing
                    spdlog::info("SIGHUP received");
                    break;
                default:
                    // Ignore "unknown" signals
                    break;
            }
        }
    }

    s1.stop();

    return 0;
}
