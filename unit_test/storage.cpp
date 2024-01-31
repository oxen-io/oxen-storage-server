#include <oxenss/storage/database.hpp>

#include <oxenss/logging/oxen_logger.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <future>

#include <catch2/catch.hpp>

using namespace oxenss;

using namespace std::literals;

struct StorageDeleter {
    StorageDeleter() { std::filesystem::remove("storage.db"); }
    ~StorageDeleter() { std::filesystem::remove("storage.db"); }
};

TEST_CASE("storage - database file creation", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};
    CHECK(std::filesystem::exists("storage.db"));
}

TEST_CASE("storage - data persistence", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto ns = namespace_id::Default;
    const auto now = std::chrono::system_clock::now();
    {
        Database storage{"."};
        CHECK(storage.store({pubkey, hash, ns, now, now + ttl, bytes}) == StoreResult::New);

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        Database storage{"."};

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");

        REQUIRE(items.size() == 1);
        CHECK_FALSE(items[0].pubkey);  // pubkey is left unset when we retrieve for pubkey
        CHECK(items[0].hash == hash);
        CHECK(items[0].msg_namespace == namespace_id::Default);
        CHECK(items[0].expiry - items[0].timestamp == ttl);
        CHECK(items[0].data == bytes);
    }
}

TEST_CASE("storage - data persistence, namespace", "[storage][namespace]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const namespace_id ns{42};
    const auto now = std::chrono::system_clock::now();
    {
        Database storage{"."};
        CHECK(storage.store({pubkey, hash, ns, now, now + ttl, bytes}) == StoreResult::New);

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        Database storage{"."};

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        auto [items, more] = storage.retrieve(pubkey, ns, "");

        REQUIRE(items.size() == 1);
        CHECK_FALSE(items[0].pubkey);  // pubkey is left unset when we retrieve for pubkey
        CHECK(items[0].hash == hash);
        CHECK(items[0].msg_namespace == namespace_id{42});
        CHECK(items[0].expiry - items[0].timestamp == ttl);
        CHECK(items[0].data == bytes);
    }
}

TEST_CASE("storage - re-storing existing hash", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl1 = 200s;
    const auto timestamp = std::chrono::system_clock::now();

    Database storage{"."};

    auto ins = storage.store(
            {pubkey, hash, namespace_id::Default, timestamp, timestamp + ttl1, bytes});
    CHECK(ins == StoreResult::New);

    std::chrono::seconds ttl2 = ttl1 - 100s;
    SECTION("later expiry") {
        ttl2 = ttl1 + 100s;
    }
    SECTION("earlier expiry") {
        ttl2 = ttl1 - 100s;
    }
    ins = storage.store({pubkey, hash, namespace_id::Default, timestamp, timestamp + ttl2, bytes});
    if (ttl2 > ttl1)
        CHECK(ins == StoreResult::Extended);
    else
        CHECK(ins == StoreResult::Exists);

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 1);
}

TEST_CASE("storage - only return entries for specified pubkey", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey1, pubkey2;
    REQUIRE(pubkey1.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store(
                  {pubkey1, "hash0", namespace_id::Default, now, now + 100s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store(
                  {pubkey2, "hash1", namespace_id::Default, now, now + 100s, "bytesasstring1"}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == 2);

    const auto lastHash = "";
    {
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }

    {
        auto [items, more] = storage.retrieve(pubkey2, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash1");
    }
}

TEST_CASE("storage - return entries older than lasthash", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = "hash" + std::to_string(i);
        storage.store({pubkey, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 100);

    {
        const auto lastHash = "hash0";
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, lastHash);
        REQUIRE(items.size() == num_entries - 1);
        CHECK(items[0].hash == "hash1");
    }

    {
        const auto lastHash = std::string("hash") + std::to_string(num_entries / 2 - 1);
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, lastHash);
        REQUIRE(items.size() == num_entries / 2);
        CHECK(items[0].hash == "hash" + std::to_string(num_entries / 2));
    }
}

TEST_CASE("storage - remove expired entries", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey1, pubkey2, pubkey3;
    REQUIRE(pubkey1.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));
    REQUIRE(pubkey3.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcded"));

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store(
                  {pubkey1, "hash0", namespace_id::Default, now, now + 1s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey1, "hash1", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store(
                  {pubkey2, "hash2", namespace_id::Default, now, now + 1s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash3", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash4", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash5", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 3);
    CHECK(storage.get_message_count() == 6);

    {
        const auto lastHash = "";
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 2);
    }
    std::this_thread::sleep_for(5ms);
    storage.clean_expired();
    {
        const auto lastHash = "";
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == 2);
}

TEST_CASE("storage - bulk data storage", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // bulk store
    {
        std::vector<message> items;
        for (int i = 0; i < num_items; ++i) {
            items.emplace_back(
                    pubkey,
                    std::to_string(i),
                    namespace_id::Default,
                    timestamp,
                    timestamp + ttl,
                    bytes);
        }

        CHECK_NOTHROW(storage.bulk_store(items));
    }

    // retrieve
    {
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");
        CHECK(items.size() == num_items);
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == num_items);
}

TEST_CASE("storage - bulk storage with overlap", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // insert existing; the bulk store shouldn't fail when these conflicts already exist
    CHECK(storage.store({pubkey, "0", namespace_id::Default, timestamp, timestamp + ttl, bytes}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey, "5", namespace_id::Default, timestamp, timestamp + ttl, bytes}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 2);

    // bulk store
    {
        std::vector<message> items;
        for (int i = 0; i < num_items; ++i) {
            items.emplace_back(
                    pubkey,
                    std::to_string(i),
                    namespace_id::Default,
                    timestamp,
                    timestamp + ttl,
                    bytes);
        }

        CHECK_NOTHROW(storage.bulk_store(items));
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == num_items);

    // retrieve
    {
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");
        CHECK(items.size() == num_items);
    }
}

TEST_CASE("storage - retrieve limit", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = "hash" + std::to_string(i);
        storage.store({pubkey, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    user_pubkey pubkey2;
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));

    for (size_t i = 0; i < 5; i++) {
        const auto hash = "anotherhash" + std::to_string(i);
        storage.store({pubkey2, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == num_entries + 5);

    CHECK(storage.retrieve(pubkey, namespace_id::Default, "").first.size() == num_entries);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 10).first.size() == 10);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 88).first.size() == 88);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 99).first.size() == 99);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 100).first.size() == 100);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 101).first.size() == 100);
    CHECK(storage.retrieve(pubkey2, namespace_id::Default, "", 10).first.size() == 5);
}

namespace oxenss {
class TestSuiteHacks {
  public:
    static void db_block(Database& db, std::chrono::milliseconds duration) {
        db.test_suite_block_for(duration);
    }
    static int db_pool_size(Database& db) {
        std::lock_guard lock{db.impl_lock_};
        return db.impl_pool_.size();
    }
};
}  // namespace oxen

TEST_CASE("storage - connection pool", "[storage][pool]") {
    StorageDeleter fixture;

    Database storage{"."};

    auto n_blocked_threads = GENERATE(1, 2, 5, 10);

    user_pubkey pubkey1;
    REQUIRE(pubkey1.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    CHECK(oxenss::TestSuiteHacks::db_pool_size(storage) == 1);

    constexpr auto blocking_time =
#ifdef __APPLE__
            1s;  // Way to go making a nice fast filesystem, apple!
#else
            100ms;
#endif
    std::vector<std::thread> busy;
    for (int i = 0; i < n_blocked_threads; i++)
        busy.emplace_back([&] { oxenss::TestSuiteHacks::db_block(storage, blocking_time); });

    std::this_thread::sleep_for(20ms);
    CHECK(oxenss::TestSuiteHacks::db_pool_size(storage) == 0);
    auto now = std::chrono::system_clock::now();
    CHECK(storage.store(
                  {pubkey1, "hash0", namespace_id::Default, now, now + 1s, "bytesasstring0"}) ==
          StoreResult::New);
    // The blocking threads are still there, so our store should have created a new one then
    // returned it the pool:
    CHECK(oxenss::TestSuiteHacks::db_pool_size(storage) == 1);
    for (auto& b : busy)
        b.join();

    // Now we've waited for the blocking threads to finish, so the blocked conns should have been
    // returned to the pool:
    CHECK(oxenss::TestSuiteHacks::db_pool_size(storage) == 1 + n_blocked_threads);
}
