#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <thread>

constexpr auto TICK_FREQUENCY = std::chrono::seconds(10);
using Callback = std::function<void()>;
class Timer {

  public:
    Timer(Callback action)
        : timer_(service_, TICK_FREQUENCY), action_(action) {}

    ~Timer() {
        service_.stop();
        if (timer_thread_.joinable()) {
            timer_thread_.join();
        }
    }

    void start() {
        timer_.async_wait(
            std::bind(&Timer::mem_tick, this, std::placeholders::_1));
        timer_thread_ = std::thread([&]() { service_.run(); });
    }

  private:
    std::thread timer_thread_;
    boost::asio::io_service service_;
    boost::asio::steady_timer timer_;
    Callback action_;
    void mem_tick(const boost::system::error_code& ec) {
        if (ec.value() != 0) {
            return;
        }
        /// todo: check if I need to catch any exceptions
        action_();
        timer_.expires_at(timer_.expiry() + TICK_FREQUENCY);
        timer_.async_wait(
            std::bind(&Timer::mem_tick, this, std::placeholders::_1));
    }
};
