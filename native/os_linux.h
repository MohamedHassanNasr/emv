#ifndef OS_LINUX
#define OS_LINUX

#include <strings.h>

#include <arpa/inet.h>
#include <map>
#include <memory>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace emv;
class udp_message_router : public message_router {
public:
    udp_message_router(mqueue* queue) : queue(queue){};
    void set_address(uint16_t my_port, const char* remote_ip, uint16_t remote_port) {
        struct sockaddr_in server;
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == -1) {
            perror("Could not create socket");
        }

        server.sin_addr.s_addr = inet_addr("0.0.0.0");
        server.sin_family = AF_INET;
        server.sin_port = htons(my_port);
        if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            perror("Connection error");
        }

        bzero(&remote, sizeof(remote));
        remote.sin_addr.s_addr = inet_addr(remote_ip);
        remote.sin_family = AF_INET;
        remote.sin_port = htons(remote_port);
    };

    virtual void post(const message& msg) override {
        if (queue->have_consumer(msg)) {
            // Adding a message to the queue.
            queue->post(msg);
        } else {
            // Sending a message via external interface.
            send(msg);
        }
    };

    ~udp_message_router() { close(sock); };

    virtual void start() override {
        if (sock < 0)
            return;
        message msg{emv::MESSAGE_ID::ROUTER_INIT, emv::EMV_MODULE::ROUTER, emv::EMV_MODULE::ROUTER};
        logger.debug("start router\n");
        if (!send(msg)) {
            logger.error("can not reach other end");
        }
        while (true) {
            recv();
        }
    };

private:
    bool send(const message& msg) {
        const std::vector<uint8_t>& buffer = msg.get_raw_data();
        if (sendto(sock, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0,
                   (struct sockaddr*)&remote, sizeof(remote)) <= 0) {
            perror("send failed");
            return false;
        }

        return true;
    }

    bool recv() {
        std::vector<uint8_t> buffer(message::MAX_MESSAGE_LENGTH);
        struct sockaddr_in sender;
        socklen_t sendsize = sizeof(sender);
        ssize_t msgLen = recvfrom(sock, reinterpret_cast<char*>(buffer.data()), buffer.capacity(), 0,
                                  (struct sockaddr*)&sender, &sendsize);
        if (msgLen == 0)
            return false;
        if (msgLen > 0) {
            logger.verbose("Received packet from ", std::string(inet_ntoa(sender.sin_addr)), " : ", std::to_string(ntohs(sender.sin_port)), "\n");
            buffer.resize(msgLen);
            message msg(buffer);

            if (queue->have_consumer(msg)) {
                queue->post(std::move(msg));
            } else {
                logger.error("receive an msg not knowing how to route");
            }

            return true;
        }

        return false;
    }

    int sock = -1;
    struct sockaddr_in remote;
    mqueue* queue;
};

class unix_timer : public timer {
public:
    unix_timer(long msecs, std::function<void()> timer_callback) : timer{msecs, timer_callback} {};
    virtual void start() override{};
    virtual void stop() override{};
    virtual ~unix_timer(){};
};

class unix_timer_factory : public timer_factory {
public:
    virtual std::unique_ptr<timer> create(long msecs, std::function<void()> timer_callback) override {
        return std::unique_ptr<timer>(new unix_timer{msecs, timer_callback});
    }
};

#endif

