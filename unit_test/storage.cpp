#include "Database.hpp"
#include "utils.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include <catch2/catch.hpp>

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

TEST_CASE("storage - database file creation", "[storage]") {
    StorageRAIIFixture fixture;

    Database storage{"."};
    CHECK(std::filesystem::exists("storage.db"));
}

TEST_CASE("storage - data persistence", "[storage]") {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto now = std::chrono::system_clock::now();
    {
        Database storage{"."};
        CHECK(storage.store(hash, pubkey, bytes, now, now + ttl));
        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        Database storage{"."};

        std::vector<Item> items;
        const auto lastHash = "";

        CHECK(storage.retrieve(pubkey, items, lastHash));

        REQUIRE(items.size() == 1);
        CHECK(items[0].pub_key == pubkey);
        CHECK(items[0].hash == hash);
        CHECK(items[0].expiration - items[0].timestamp == ttl);
        CHECK(items[0].data == bytes);
    }
}

TEST_CASE("storage - returns false when storing existing hash", "[storage]") {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    Database storage{"."};

    CHECK(storage.store(hash, pubkey, bytes, timestamp, timestamp + ttl));
    // store using the same hash, FAIL is default behaviour
    CHECK_FALSE(storage.store(hash, pubkey, bytes, timestamp, timestamp + ttl,
                              Database::DuplicateHandling::FAIL));
}

TEST_CASE("storage - returns true when storing existing with ignore constraint", "[storage]") {
    StorageRAIIFixture fixture;

    const auto hash = "myhash";
    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    Database storage{"."};

    CHECK(storage.store(hash, pubkey, bytes, timestamp, timestamp + ttl));
    // store using the same hash
    CHECK(storage.store(hash, pubkey, bytes, timestamp, timestamp + ttl,
                              Database::DuplicateHandling::IGNORE));
}

TEST_CASE("storage - only return entries for specified pubkey", "[storage]") {
    StorageRAIIFixture fixture;

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store("hash0", "mypubkey", "bytesasstring0", now, now + 100s));
    CHECK(storage.store("hash1", "otherpubkey", "bytesasstring1", now, now + 100s));

    {
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("mypubkey", items, lastHash));
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }

    {
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("otherpubkey", items, lastHash));
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash1");
    }
}

TEST_CASE("storage - return entries older than lasthash", "[storage]") {
    StorageRAIIFixture fixture;

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = std::string("hash") + std::to_string(i);
        storage.store(hash, "mypubkey", "bytesasstring", now, now + 100s);
    }

    {
        std::vector<Item> items;
        const auto lastHash = "hash0";
        CHECK(storage.retrieve("mypubkey", items, lastHash));
        REQUIRE(items.size() == num_entries - 1);
        CHECK(items[0].hash == "hash1");
    }

    {
        std::vector<Item> items;
        const auto lastHash =
            std::string("hash") + std::to_string(num_entries / 2 - 1);
        CHECK(storage.retrieve("mypubkey", items, lastHash));
        REQUIRE(items.size() == num_entries / 2);
        CHECK(items[0].hash == "hash" + std::to_string(num_entries / 2));
    }
}

TEST_CASE("storage - remove expired entries", "[storage]") {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store("hash0", pubkey, "bytesasstring0", now, now + 1s));
    CHECK(storage.store("hash1", pubkey, "bytesasstring0", now, now));
    {
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve(pubkey, items, lastHash));
        REQUIRE(items.size() == 2);
    }
    std::this_thread::sleep_for(5ms);
    storage.clean_expired();
    {
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve(pubkey, items, lastHash));
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }
}

TEST_CASE("storage - bulk data storage", "[storage]") {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // bulk store
    {
        std::vector<Item> items;
        for (int i = 0; i < num_items; ++i) {
            items.emplace_back(std::to_string(i), pubkey, timestamp,
                             timestamp + ttl, bytes);
        }

        CHECK(storage.bulk_store(items));
    }

    // retrieve
    {
        std::vector<Item> items;

        CHECK(storage.retrieve(pubkey, items, ""));
        CHECK(items.size() == num_items);
    }
}

TEST_CASE("storage - bulk storage with overlap", "[storage]") {
    StorageRAIIFixture fixture;

    const auto pubkey = "mypubkey";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // insert existing
    CHECK(storage.store("0", pubkey, bytes, timestamp, timestamp + ttl));

    // bulk store
    {
        std::vector<Item> items;
        for (int i = 0; i < num_items; ++i) {
            items.emplace_back(std::to_string(i), pubkey, timestamp, timestamp + ttl, bytes);
        }

        CHECK(storage.bulk_store(items));
    }

    // retrieve
    {
        std::vector<Item> items;

        CHECK(storage.retrieve(pubkey, items, ""));
        CHECK(items.size() == num_items);
    }
}

TEST_CASE("storage - retrieve limit", "[storage]") {
    StorageRAIIFixture fixture;

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = std::string("hash") + std::to_string(i);
        storage.store(hash, "mypubkey", "bytesasstring", now, now + 100s);
    }

    // should return all items
    {
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("mypubkey", items, lastHash));
        CHECK(items.size() == num_entries);
    }

    // should return 10 items
    {
        const int num_results = 10;
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        CHECK(items.size() == num_results);
    }

    // should return 88 items
    {
        const int num_results = 88;
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        CHECK(items.size() == num_results);
    }

    // should return num_entries items
    {
        const int num_results = 2 * num_entries;
        std::vector<Item> items;
        const auto lastHash = "";
        CHECK(storage.retrieve("mypubkey", items, lastHash, num_results));
        CHECK(items.size() == num_entries);
    }
}
