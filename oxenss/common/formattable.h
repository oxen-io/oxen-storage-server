#pragma once

#include <fmt/format.h>
#include <type_traits>

namespace oxenss {

// Types can opt-in to being fmt-formattable by defining a `to_string()` const member function
// that returns something string-like.  For scoped enums we instead look for a `to_string(Type
// t)` function in the same namespace.
//
// e.g.
// template <> inline constexpr bool to_string_formattable<MyType> = true;
template <typename T>
constexpr bool to_string_formattable = false;

#ifdef __cpp_lib_is_scoped_enum
using std::is_scoped_enum;
using std::is_scoped_enum_v;
#else
template <typename T, bool = std::is_enum_v<T>>
struct is_scoped_enum : std::false_type {};

template <typename T>
struct is_scoped_enum<T, true>
        : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>> {};

template <typename T>
constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;
#endif

}  // namespace oxenss

namespace fmt {
template <typename T>
struct formatter<T, char, std::enable_if_t<oxenss::to_string_formattable<T>>>
        : formatter<std::string_view> {
    template <typename FormatContext>
    auto format(const T& val, FormatContext& ctx) const {
        if constexpr (oxenss::is_scoped_enum_v<T>)
            return formatter<std::string_view>::format(to_string(val), ctx);
        else
            return formatter<std::string_view>::format(val.to_string(), ctx);
    }
};

}  // namespace fmt
