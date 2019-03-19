#include "service_node.h"

#include "Database.hpp"
#include "swarm.h"

#include "http_connection.h"
#include "Item.hpp"

#include <chrono>
#include <fstream>

#include <boost/algorithm/string.hpp>

#include <boost/log/trivial.hpp>

/// move this out
#include <openssl/evp.h>
#include <openssl/sha.h>

using service_node::storage::Item;

namespace loki {

void say_hello(const boost::system::error_code& ec) { std::cout << "hello\n"; }

/// TODO: can we reuse context (reset it)?
std::string hash_data(std::string data) {

    unsigned char result[EVP_MAX_MD_SIZE];

    /// Allocate and init digest context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    /// Set the method
    EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);

    /// Do the hashing, can be called multiple times (?)
    /// to hash
    EVP_DigestUpdate(mdctx, data.data(), data.size());

    unsigned int md_len;

    EVP_DigestFinal_ex(mdctx, result, &md_len);

    /// Clean up the context
    EVP_MD_CTX_destroy(mdctx);

    /// Not sure if this is needed
    EVP_cleanup();

    /// store into the string
    /// TODO: use binary instead?
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++) {
        ss << std::setw(2) << static_cast<unsigned>(result[i]);
    }

    return std::string(ss.str());
}

ServiceNode::ServiceNode(boost::asio::io_context& ioc, uint16_t port, const std::string& dbLocation)
    : ioc_(ioc),
      db_(std::make_unique<Database>(dbLocation)),
      our_sn_(port),
      update_timer_(ioc, std::chrono::milliseconds(100)) {

    update_timer_.async_wait(std::bind(&ServiceNode::update_swarms, this));
}

ServiceNode::~ServiceNode() = default;

/// make this async
void ServiceNode::relay_one(const message_ptr msg, uint16_t port) const {

    BOOST_LOG_TRIVIAL(trace) << "Relaying a message to " << port;

    request_t req;
    req.body() = msg->text_;
    req.target("/v1/swarms/push");
    req.set("X-Loki-recipient", msg->pk_);

    /// TODO: how to handle a failure here?
    make_http_request(ioc_, "0.0.0.0", port, req,
                      [](std::shared_ptr<std::string>) {

                      });
}

void ServiceNode::relay_batch(const std::string& data, uint16_t port) const {

    BOOST_LOG_TRIVIAL(trace) << "Relaying a batch to " << port;

    request_t req;
    req.body() = data;
    req.target("/v1/swarms/push_all");

    make_http_request(ioc_, "0.0.0.0", port, req,
                      [](std::shared_ptr<std::string>) {

                      });

}

/// initiate a /swarms/push request
void ServiceNode::push_message(const message_ptr msg) {

    auto others = swarm_->other_nodes();

    BOOST_LOG_TRIVIAL(trace) << "push_message to " << others.size() << " other nodes";

    for (auto& port : others) {
        /// send a request asyncronously (todo: collect confirmations)
        relay_one(msg, port);
    }
}

/// do this asyncronously on a different thread? (on the same thread?)
bool ServiceNode::process_store(const message_ptr msg) {

    // TODO: Enable swarm and push_message functionality again
    /// only accept a message if we are in a swarm
    // if (!swarm_) {
    //     return false;
    // }

    /// store to the database
    save_if_new(msg);

    /// initiate a /swarms/push request
    // this->push_message(msg);

    return true;
}

bool ServiceNode::process_push(const message_ptr msg) {

    save_if_new(msg);

}

bool ServiceNode::is_existing_msg(const std::string& hash) {

    const auto it = std::find_if(
        all_messages_.begin(), all_messages_.end(),
        [&hash](const saved_message_t& msg) { return msg.hash_ == hash; });

    return (it != all_messages_.end());
}


void ServiceNode::save_if_new(const message_ptr msg) {

    db_->store(msg->hash_, msg->pk_, msg->text_, msg->ttl_);

    /// Check if we already have this message
    std::string hash = hash_data(msg->text_);

    if (is_existing_msg(hash)) {
        return;
    }

    BOOST_LOG_TRIVIAL(trace) << "saving message: " << msg->text_;

    /// just append this to a file for simplicity
    std::ofstream file("db.txt", std::ios_base::app);
    file << msg->pk_ << " " << msg->text_ << "\n";

    // for now store the message in local data structure (rather than DB)
    all_messages_.push_back({hash, msg->pk_.c_str(), msg->text_.c_str()});

    BOOST_LOG_TRIVIAL(trace) << "It is done!";

}

void ServiceNode::on_swarm_update(std::shared_ptr<std::string> body) {

    /// TODO: firgure out if anything changed

    if (!body) {
        BOOST_LOG_TRIVIAL(error) << "FAILED to obtain swarm info from lokid";
        return;
    }

    boost::trim(*body);

    /// Note: parsing will most likely change, so don't worry about efficiency
    /// for now
    std::vector<std::string> swarms;

    all_swarms_t all_swarms;

    boost::split(swarms, *body, boost::is_any_of("\n"),
                 boost::token_compress_on);

    for (auto& swarm : swarms) {

        std::vector<sn_record_t> swarm_members;

        std::vector<std::string> nodes;

        boost::trim(swarm);

        boost::split(nodes, swarm, boost::is_any_of(" "),
                     boost::token_compress_on);

        /// the first entry is the swarm id
        uint64_t swarm_id = stoull(nodes[0]);

        for (auto i = 1u; i < nodes.size(); ++i) {

            uint16_t port = 0;

            try {
                port = stoi(nodes[i]);

            } catch (const std::exception& e) {
                BOOST_LOG_TRIVIAL(error) << "ERROR: invalid port: " << nodes[i];
                return;
            }

            swarm_members.push_back(port);
        }

        SwarmInfo si;

        si.snodes = swarm_members;
        si.swarm_id = swarm_id;

        all_swarms.push_back(si);
    }

    if (!swarm_) {
        swarm_ = std::make_unique<Swarm>(our_sn_);
    }

    const SwarmEvents events = swarm_->update_swarms(all_swarms);

    if (!events.new_snodes.empty()) {
        bootstrap_peers(events.new_snodes);
    }

    if (!events.new_swarms.empty()) {
        bootstrap_swarms(events.new_swarms);
    }

    if (events.decommissioned) {
        /// Go throguh all our PK and push them to accordingly
        salvage_data();
    }

    this->purge_outdated();
}

void ServiceNode::bootstrap_peers(const std::vector<sn_record_t>& peers) const {

    std::string data = serialize_all();

    for (const sn_record_t& sn : peers) {
        relay_batch(data, sn);
    }

}

template<typename T>
std::string vec_to_string(const std::vector<T>& vec) {

    std::stringstream ss;

    ss << "[";

    for (auto i = 0u; i < vec.size(); ++i) {
        ss << vec[i];

        if (i < vec.size() - 1) {
            ss << " ";
        }
    }

    ss << "]";

    return ss.str();

}

void ServiceNode::bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const {

    if (swarms.empty()) {
        BOOST_LOG_TRIVIAL(info) << "bootstrapping all swarms\n";
    } else {
        BOOST_LOG_TRIVIAL(info) << "bootstrapping swarms: " << vec_to_string(swarms) << std::endl;
    }

    const auto& all_swarms = swarm_->all_swarms();

    /// See what pubkeys we have

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (auto i = 0u; i < all_swarms.size(); ++i) {
        swarm_id_to_idx.insert({all_swarms[i].swarm_id, i});
    }

    std::unordered_map<std::string, swarm_id_t> cache;

    BOOST_LOG_TRIVIAL(trace)<< "we have " << all_messages_.size() << " messages\n";

    for (auto &msg : all_messages_) {

        const auto it = cache.find(msg.pk_);

        if (it == cache.end()) {
            swarm_id_t swarm_id = get_swarm_by_pk(all_swarms, msg.pk_);
            cache.insert({msg.pk_, swarm_id});
        }

        /// extra lookup?
        swarm_id_t swarm_id = cache[msg.pk_];

        bool relevant = false;
        for (const auto swarm : swarms) {

            if (swarm == swarm_id) {
                relevant = true;
            }

        }

        if (relevant || swarms.empty()) {

            /// what if not found?
            size_t idx = swarm_id_to_idx[swarm_id];

            for (const sn_record_t& sn : all_swarms[idx].snodes) {
                // TODO: Actually use the message values here
                relay_one(std::make_shared<message_t>(msg.pk_.c_str(), msg.text_.c_str(), "", 0), sn);
            }


        }

    }

}

void ServiceNode::salvage_data() const {

    /// This is very similar to ServiceNode::bootstrap_swarms, so might reuse it
    bootstrap_swarms({});

}

static std::string serialize(uint32_t a) {

    /// TODO: get rid of allocations
    std::string res;

    char b0 = static_cast<char>(((a & 0xFF000000) >> 24));
    char b1 = static_cast<char>(((a & 0xFF0000) >> 16));
    char b2 = static_cast<char>(((a & 0xFF00) >> 8));
    char b3 = static_cast<char>(((a & 0xFF)));

    res += b0;
    res += b1;
    res += b2;
    res += b3;

    return res;
}

static std::string serialize_message(const saved_message_t& msg) {

    std::string res;

    res += serialize(msg.text_.size());
    res += msg.pk_;
    res += msg.text_;

    return res;
}

std::string ServiceNode::get_all_messages() {

    pt::ptree messages;

    for (auto& msg : all_messages_) {

        pt::ptree msg_node;
        msg_node.put("pk", msg.pk_);
        msg_node.put("data", msg.text_);
        messages.push_back(std::make_pair("", msg_node));
    }

    pt::ptree root;

    if (messages.empty())
        return "";

    root.add_child("messages", messages);

    std::ostringstream buf;
    pt::write_json(buf, root);

    return buf.str();

}

bool ServiceNode::retrieve(const std::string& pubKey, const std::string& last_hash, std::vector<Item>& items) {
    return db_->retrieve(pubKey, items, last_hash);
}

std::string ServiceNode::get_all_messages(const std::string& pk) {

    pt::ptree messages;

    for (auto& msg : all_messages_) {

        if (msg.pk_ == pk) {

            pt::ptree msg_node;
            msg_node.put("data", msg.text_);
            messages.push_back(std::make_pair("", msg_node));
        }
    }

    pt::ptree root;

    if (messages.empty())
        return "";

    root.add_child("messages", messages);

    std::ostringstream buf;
    pt::write_json(buf, root);

    return buf.str();
}

std::string ServiceNode::serialize_all() const {
    /// IMPORTANT: need to be careful how we separate messages,
    /// as we cannot assume anything about the contents of
    /// the messages.
    /// But for know, every line is a new message, change this to
    /// a protocol that declares sizes of the following blobs messages

    /// Protocol 2:
    /// |body_size| client pk |  message  |
    /// | 4 bytes | 256 bytes |<body_size>|

    std::string result;

    for (auto& msg : all_messages_) {

        result += serialize_message(msg);
    }

    return result;
}

void ServiceNode::purge_outdated() {

    std::unordered_map<std::string, swarm_id_t> cache;

    std::vector<saved_message_t> to_keep;

    for (auto &msg : all_messages_) {

        const auto it = cache.find(msg.pk_);

        if (it == cache.end()) {
            swarm_id_t swarm_id = get_swarm_by_pk(swarm_->all_swarms(), msg.pk_);
            cache.insert({msg.pk_, swarm_id});
        }

        /// extra lookup?
        swarm_id_t swarm_id = cache[msg.pk_];

        if (swarm_id == swarm_->our_swarm_id()) {
            to_keep.push_back(msg);
        }

    }

    all_messages_ = std::move(to_keep);

}

void ServiceNode::update_swarms() {

    BOOST_LOG_TRIVIAL(trace) << "UPDATING SWARMS: begin";

    // const char* ip = "149.56.148.124";
    // const uint16_t port = 22023;

    const uint16_t port = 7777;
    const char* ip = "0.0.0.0";

    std::string req_body =
        R"#({
            "jsonrpc":"2.0",
            "id":"0",
            "method":"get_service_nodes",
            "params": {
                "height": 200
            }
        })#";

    make_http_request(
        ioc_, ip, port, "/json_rpc", req_body,
        std::bind(&ServiceNode::on_swarm_update, this, std::placeholders::_1));

    /// TODO: make an rpc request to lokid

    update_timer_.expires_after(std::chrono::seconds(2));

    update_timer_.async_wait(boost::bind(&ServiceNode::update_swarms, this));

    BOOST_LOG_TRIVIAL(trace) << "UPDATING SWARMS: end";
}

using iter_t = const char*;

static uint32_t deserialize_uint32(iter_t& it) {

    auto b1 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b2 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b3 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b4 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));

    return static_cast<uint32_t>(b1 << 24 | b2 << 16 | b3 << 8 | b4);
}

static std::vector<message_t> deserialize_messages(const std::string& blob) {

    BOOST_LOG_TRIVIAL(trace) << "=== Deserializing ===";

    uint32_t bytes_read = 0;

    iter_t it = blob.c_str();

    constexpr size_t PK_SIZE = 64; // characters in hex;

    std::vector<message_t> result;

    while (blob.size() > bytes_read) {

        if (blob.size() < 4 + PK_SIZE)
            return {};

        uint32_t msg_size = deserialize_uint32(it);
        bytes_read += 4;

        std::string pk = blob.substr(bytes_read, PK_SIZE);
        bytes_read += PK_SIZE;
        it += PK_SIZE;

        if (blob.size() < 4 + PK_SIZE + msg_size)
            return {};

        std::string msg = blob.substr(bytes_read, msg_size);
        bytes_read += msg_size;
        it += msg_size;

        BOOST_LOG_TRIVIAL(trace) << boost::format("size: %1%, pk: %2%, msg: %3%") %
                         msg_size % pk % msg;

        // TODO: Actually use the message values here
        result.push_back({pk.c_str(), msg.c_str(), "", 0});

    }

    BOOST_LOG_TRIVIAL(trace) << "=== END ===";

    return result;
}

void ServiceNode::process_push_all(std::shared_ptr<std::string> blob) {

    /// This should already be checked, but just to be sure
    if (!blob || *blob == "")
        return;

    if (*blob == "")
        return;

    /// Note: this code will likely change, so I'm not worried about performance

    std::vector<message_t> messages = deserialize_messages(*blob);

    // boost::trim(*blob);

    // boost::split(messages, *blob, boost::is_any_of("\n"),
    //  boost::token_compress_on);

    BOOST_LOG_TRIVIAL(trace) << "got " << messages.size() << " messages form peers";

    for (auto& msg : messages) {

        /// shouldn't have to create shared ptr here...
        // TODO: Actually use the message values here
        save_if_new(
            std::make_shared<message_t>(msg.pk_.c_str(), msg.text_.c_str(), "", 0));
    }
}

} // namespace loki
