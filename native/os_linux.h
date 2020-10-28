#ifndef OS_LINUX
#define OS_LINUX

#include "emv.h"

// some utility class and routines for a linux environment
// which can fill the platform dependency by emv kernel
#include <strings.h>
#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <random>
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

    virtual void post(message&& msg) override
    {
        if (queue->have_consumer(msg)) {
            // Adding a message to the queue.
            queue->post(std::move(msg));
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

struct default_rng {
    void operator()(uint8_t* ptr, size_t size) const
    {
        static std::random_device rd;
        static std::default_random_engine dre(rd());
        std::uniform_int_distribution<int> di(0, 255);
        while (size--) {
            *ptr++ = static_cast<uint8_t>(di(dre));
        }
    }

    std::vector<uint8_t> operator()(size_t size) const
    {
        std::vector<uint8_t> v(size);
        (*this)(v.data(), v.size());
        return v;
    }
};

struct wall_clock {
    std::vector<uint8_t> yymmdd() const
    {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        tm local_tm = *localtime(&t);
        int year = (local_tm.tm_year + 1900) % 100;
        int month = local_tm.tm_mon + 1;
        int day = local_tm.tm_mday;
        char buf[7];
        sprintf(buf, "%2d%2d%2d", year, month, day);
        return emv::TRANSACTION_DATE_9A.from_string(std::string(buf));
    };

    std::vector<uint8_t> hhmmss() const
    {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        tm local_tm = *localtime(&t);
        int hour = local_tm.tm_hour;
        int minute = local_tm.tm_min;
        int second = local_tm.tm_sec;
        char buf[7];
        sprintf(buf, "%2d%2d%2d", hour, minute, second);
        return emv::TRANSACTION_TIME_9F21.from_string(std::string(buf));
    };
};

class global_locker : public emv::mqueue::qlocker
{
public:
    virtual void lock() override
    {
        m.lock();
    };

    virtual void unlock() override
    {
        m.unlock();
    };

    virtual void wait(std::function<bool()> cond) override
    {
        std::unique_lock<std::mutex> ul(m);
        cv.wait(ul, cond);
    };

    virtual void notify() override
    {
        cv.notify_one();
    };

private:
    std::mutex m;
    std::condition_variable cv;
};

#endif

