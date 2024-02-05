#include "utils.h"

#include <oxenss/crypto/subaccount.h>

#include <oxenc/hex.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

static auto logcat = oxen::log::Cat("utils");

namespace oxenss {

oxenc::bt_value json_to_bt(nlohmann::json j) {
    if (j.is_object()) {
        oxenc::bt_dict res;
        for (auto& [k, v] : j.items())
            res[k] = json_to_bt(v);
        return res;
    }
    if (j.is_array()) {
        oxenc::bt_list res;
        for (auto& v : j)
            res.push_back(json_to_bt(v));
        return res;
    }
    if (j.is_string())
        return j.get<std::string>();
    if (j.is_boolean())
        return j.get<bool>() ? 1 : 0;
    if (j.is_number_unsigned())
        return j.get<uint64_t>();
    if (j.is_number_integer())
        return j.get<int64_t>();

    throw std::runtime_error{
            "client request returned json with an unhandled value type, unable to convert to bt"};
}

nlohmann::json bt_to_json(oxenc::bt_dict_consumer d) {
    nlohmann::json j = nlohmann::json::object();
    while (!d.is_finished()) {
        std::string key{d.key()};
        if (d.is_string())
            j[key] = d.consume_string();
        else if (d.is_dict())
            j[key] = bt_to_json(d.consume_dict_consumer());
        else if (d.is_list())
            j[key] = bt_to_json(d.consume_list_consumer());
        else if (d.is_negative_integer())
            j[key] = d.consume_integer<int64_t>();
        else if (d.is_integer())
            j[key] = d.consume_integer<uint64_t>();
        else
            assert(!"invalid bt type!");
    }
    return j;
}

nlohmann::json bt_to_json(oxenc::bt_list_consumer l) {
    nlohmann::json j = nlohmann::json::array();
    while (!l.is_finished()) {
        if (l.is_string())
            j.push_back(l.consume_string());
        else if (l.is_dict())
            j.push_back(bt_to_json(l.consume_dict_consumer()));
        else if (l.is_list())
            j.push_back(bt_to_json(l.consume_list_consumer()));
        else if (l.is_negative_integer())
            j.push_back(l.consume_integer<int64_t>());
        else if (l.is_integer())
            j.push_back(l.consume_integer<uint64_t>());
        else
            assert(!"invalid bt type!");
    }
    return j;
}

}  // namespace oxenss
