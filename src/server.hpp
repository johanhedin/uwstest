#ifndef SERVER_HPP
#define SERVER_HPP

#include <string>
#include <vector>
#include <memory>

class Server final {
public:
    // TODO: Sane default for webroot so that we do not expose
    //       the whole world if not set
    struct Settings {
        std::vector<std::pair<std::string,int>> std_sockets{};
        std::vector<std::pair<std::string,int>> tls_sockets{};
        std::string                             crt_file{};
        std::string                             key_file{};
        std::string                             client_ca_file{};
        std::string                             auth_hostname{};
        std::string                             webroot{};

        // Used to check if an instance is "empty"
        operator bool() const {
            if (std_sockets.empty() &&
                tls_sockets.empty() &&
                crt_file.empty() &&
                key_file.empty() &&
                client_ca_file.empty() &&
                auth_hostname.empty() &&
                webroot.empty()
            ) return false;

            return true;
        };
    };

    Server();
    Server(const Settings& settings);
    ~Server();

    Server(Server&& other);
    Server& operator=(Server&& other);

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void restart(const Settings& new_settings = { {}, {}, {}, {}, {}, {}, {} });
    void start();
    void stop();

private:
    class Internal;
    std::unique_ptr<Internal> internal_;
};

#endif // SERVER_HPP
