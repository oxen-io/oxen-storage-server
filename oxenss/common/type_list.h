#pragma once

#include <variant>

namespace oxen {

/// Helper types for storing/managing a compile-time list of types.
template <typename...>
struct type_list {};

/// Helper struct that grows a type_list by tacking additional types on the end:
template <typename...>
struct type_list_append;

template <typename... T, typename... S>
struct type_list_append<type_list<T...>, S...> {
    using type = type_list<T..., S...>;
};

template <typename... T>
using type_list_append_t = typename type_list_append<T...>::type;

template <typename...>
constexpr bool type_list_contains = false;

template <typename... S, typename T>
inline constexpr bool type_list_contains<T, type_list<S...>> = (std::is_same_v<T, S> || ...);

/// Helper for converting a type_list<T...> into a std::variant<T...>.  (Note that std::variant
/// requires at least one T).
template <typename... T>
struct type_list_variant;

template <typename... T>
struct type_list_variant<type_list<T...>> {
    static_assert(sizeof...(T) > 0, "std::variant requires at least one type");
    using type = std::variant<T...>;
};
template <typename... T>
using type_list_variant_t = typename type_list_variant<T...>::type;

}  // namespace oxen
