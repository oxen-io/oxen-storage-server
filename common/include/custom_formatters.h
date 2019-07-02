#include "loki_common.h"
#include "loki_logger.h"

namespace fmt {

template <>
struct formatter<sn_record_t> {

    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const sn_record_t& d, FormatContext& ctx) {
#ifdef INTEGRATION_TEST
        return format_to(ctx.out(), "{}", d.port());
#else
        return format_to(ctx.out(), "{}", d.sn_address());
#endif
    }
};

} // namespace fmt
