#include "Database.hpp"
#include "utils.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include <boost/test/unit_test.hpp>

using oxen::storage::Item;

using namespace oxen;

using namespace std::literals;

struct StorageRAIIFixture {
    StorageRAIIFixture() {
        if (std::filesystem::remove("storage.db")) {
            std::cout << "Pre-test db removal" << std::endl;
        }
    }
    ~StorageRAIIFixture() {
        if (std::filesystem::remove("storage.db")) {
            std::cout << "Post-test db removal" << std::endl;
        }
    }
};

BOOST_AUTO_TEST_SUITE(storage)

BOOST_AUTO_TEST_CASE(it_creates_the_database_file) {
    StorageRAIIFixture fixture;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");
    BOOST_CHECK(std::filesystem::exists("storage.db"));
}

BOOST_AUTO_TEST_CASE(it_stores_data_persistently) {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();
    {
        boost::asio::io_context ioc;
        Database storage(ioc, ".");
        BOOST_CHECK(storage.store(hash, pubkey, bytes, ttl, timestamp, nonce));
        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        boost::asio::io_context ioc;
        Database storage(ioc, ".");

        std::vector<Item> items;
        const auto lastHash = "";

        BOOST_CHECK(storage.retrieve(pubkey, items, lastHash));

        BOOST_CHECK_EQUAL(items.size(), 1);
        BOOST_CHECK_EQUAL(items[0].pub_key, pubkey);
        BOOST_CHECK_EQUAL(items[0].hash, hash);
        BOOST_CHECK_EQUAL((items[0].expiration_timestamp - items[0].timestamp),
                          ttl);
        BOOST_CHECK_EQUAL(items[0].data, bytes);
    }
}

BOOST_AUTO_TEST_CASE(it_returns_false_when_storing_existing_hash) {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    BOOST_CHECK(storage.store(hash, pubkey, bytes, ttl, timestamp, nonce));
    // store using the same hash, FAIL is default behaviour
    BOOST_CHECK(storage.store(hash, pubkey, bytes, ttl, timestamp, nonce,
                              Database::DuplicateHandling::FAIL) == false);
}

BOOST_AUTO_TEST_CASE(
    it_returns_true_when_storing_existing_with_ignore_constraint) {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    BOOST_CHECK(storage.store(hash, pubkey, bytes, ttl, timestamp, nonce));
    // store using the same hash
    BOOST_CHECK(storage.store(hash, pubkey, bytes, ttl, timestamp, nonce,
                              Database::DuplicateHandling::IGNORE) == true);
}

BOOST_AUTO_TEST_CASE(it_only_returns_entries_for_specified_pubkey) {
    StorageRAIIFixture fixture;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    BOOST_CHECK(storage.store("hash0", "mypubkey", "bytesasstring0", 100000,
                              util::get_time_ms(), "nonce"));
    BOOST_CHECK(storage.store("hash1", "otherpubkey", "bytesasstring1", 100000,
                              util::get_time_ms(), "nonce"));

    {
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), 1);
        BOOST_CHECK_EQUAL(items[0].hash, "hash0");
    }

    {
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("otherpubkey", items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), 1);
        BOOST_CHECK_EQUAL(items[0].hash, "hash1");
    }
}

BOOST_AUTO_TEST_CASE(it_returns_entries_older_than_lasthash) {
    StorageRAIIFixture fixture;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    const size_t num_entries = 1000;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = std::string("hash") + std::to_string(i);
        storage.store(hash, "mypubkey", "bytesasstring", 100000,
                      util::get_time_ms(), "nonce");
    }

    {
        std::vector<Item> items;
        const auto lastHash = "hash0";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), num_entries - 1);
        BOOST_CHECK_EQUAL(items[0].hash, "hash1");
    }

    {
        std::vector<Item> items;
        const auto lastHash =
            std::string("hash") + std::to_string(num_entries / 2 - 1);
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), num_entries / 2);
        BOOST_CHECK_EQUAL(items[0].hash, std::string("hash") +
                                             std::to_string(num_entries / 2));
    }
}

BOOST_AUTO_TEST_CASE(it_removes_expired_entries) {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";

    boost::asio::io_context ioc;

    Database storage(ioc, ".");

    /// Note: `Database` is not thread safe
    /// and not meant to be used in this way;
    /// However, it should be fine for tests
    std::thread t([&]() { ioc.run(); });

    BOOST_CHECK(storage.store("hash0", pubkey, "bytesasstring0", 100000,
                              util::get_time_ms(), "nonce"));
    BOOST_CHECK(storage.store("hash1", pubkey, "bytesasstring0", 0,
                              util::get_time_ms(), "nonce"));
    {
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve(pubkey, items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), 2);
    }
    // the timer kicks in every 10 seconds
    // give 100ms to perform the cleanup
    std::cout << "waiting for cleanup timer..." << std::endl;
    std::this_thread::sleep_for(10s + 100ms);

    {
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve(pubkey, items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), 1);
        BOOST_CHECK_EQUAL(items[0].hash, "hash0");
    }

    ioc.stop();
    t.join();
}

BOOST_AUTO_TEST_CASE(it_stores_data_in_bulk) {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();

    const size_t num_items = 10000;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    // bulk store
    {
        std::vector<Item> items;
        for (int i = 0; i < num_items; ++i) {
            items.push_back({std::to_string(i), pubkey, timestamp, ttl,
                             timestamp + ttl, nonce, bytes});
        }

        BOOST_CHECK(storage.bulk_store(items));
    }

    // retrieve
    {
        std::vector<Item> items;

        BOOST_CHECK(storage.retrieve(pubkey, items, ""));
        BOOST_CHECK_EQUAL(items.size(), num_items);
    }
}

BOOST_AUTO_TEST_CASE(it_stores_data_in_bulk_even_when_overlaps) {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();

    const size_t num_items = 10000;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    // insert existing
    BOOST_CHECK(storage.store("0", pubkey, bytes, ttl, timestamp, nonce));

    // bulk store
    {
        std::vector<Item> items;
        for (int i = 0; i < num_items; ++i) {
            items.push_back({std::to_string(i), pubkey, timestamp, ttl,
                             timestamp + ttl, nonce, bytes});
        }

        BOOST_CHECK(storage.bulk_store(items));
    }

    // retrieve
    {
        std::vector<Item> items;

        BOOST_CHECK(storage.retrieve(pubkey, items, ""));
        BOOST_CHECK_EQUAL(items.size(), num_items);
    }
}

BOOST_AUTO_TEST_CASE(bulk_performance_check) {
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto nonce = "nonce";
    const uint64_t ttl = 123456;
    const uint64_t timestamp = util::get_time_ms();

    const size_t num_items = 10000;

    std::vector<Item> items;
    for (int i = 0; i < num_items; ++i) {
        items.push_back({std::to_string(i), pubkey, timestamp, ttl,
                         timestamp + ttl, nonce, bytes});
    }

    // bulk store
    {
        StorageRAIIFixture fixture;
        boost::asio::io_context ioc;
        Database storage(ioc, ".");
        const auto start = std::chrono::steady_clock::now();
        storage.bulk_store(items);
        const auto end = std::chrono::steady_clock::now();
        const auto diff = end - start;
        std::cout << "bulk: "
                  << std::chrono::duration<double, std::milli>(diff).count()
                  << " ms" << std::endl;
    }

    // single stores
    {
        StorageRAIIFixture fixture;
        boost::asio::io_context ioc;
        Database storage(ioc, ".");
        const auto start = std::chrono::steady_clock::now();
        for (const auto& item : items) {
            storage.store(item.hash, item.pub_key, item.data, item.ttl,
                          item.timestamp, item.nonce);
        }
        const auto end = std::chrono::steady_clock::now();
        const auto diff = end - start;
        std::cout << "singles:"
                  << std::chrono::duration<double, std::milli>(diff).count()
                  << " ms" << std::endl;
    }
}

BOOST_AUTO_TEST_CASE(it_checks_the_retrieve_limit_works) {
    StorageRAIIFixture fixture;

    boost::asio::io_context ioc;
    Database storage(ioc, ".");

    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = std::string("hash") + std::to_string(i);
        storage.store(hash, "mypubkey", "bytesasstring", 100000,
                      util::get_time_ms(), "nonce");
    }

    // should return all items
    {
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash));
        BOOST_CHECK_EQUAL(items.size(), num_entries);
    }

    // should return 10 items
    {
        const int num_results = 10;
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        BOOST_CHECK_EQUAL(items.size(), num_results);
    }

    // should return 88 items
    {
        const int num_results = 88;
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        BOOST_CHECK_EQUAL(items.size(), num_results);
    }

    // should return num_entries items
    {
        const int num_results = 2 * num_entries;
        std::vector<Item> items;
        const auto lastHash = "";
        BOOST_CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        BOOST_CHECK_EQUAL(items.size(), num_entries);
    }
}

BOOST_AUTO_TEST_SUITE_END()
