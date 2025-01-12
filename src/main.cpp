// Std C++ includes
#include <iostream>
#include <csignal>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <functional>
#include <chrono>

// Internal includes
#include "server.hpp"

// Some code for playing audio received via a websocket:
// https://github.com/nexmo-community/audiosocket-demo
// Explanation: https://developer.vonage.com/en/blog/streaming-calls-to-a-browser-with-voice-websockets-dr
// This also: https://medium.com/@sandeeplakhiwal/real-time-audio-streaming-in-react-js-handling-and-playing-live-audio-buffers-c72ec38c91fa
// https://developer.mozilla.org/en-US/docs/Web/API/AudioBufferSourceNode

// Trick to be able to use signal_callback as lambda
static std::function<void(int)> signal_callback = nullptr;
static void signal_handler(int signal) { signal_callback(signal); }


int main(int, char**) {
    std::cout << "Hello µWSTest!\n";

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

    Server s1{{
        .std_sockets = { {"127.0.0.1", 8080} },
        .tls_sockets = { {"127.0.0.1", 8443} },
        .crt_file = "../srv.crt",
        .key_file = "../srv.key",
        .webroot = "../webroot"
    }};

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
                    std::cout << "SIGHUP received\n";
                    break;
                default:
                    // Ignore "unknown" signals
                    break;
            }
        }
    }

    return 0;
}
