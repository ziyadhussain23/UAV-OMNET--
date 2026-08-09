#ifndef UAVAUTH_TESTS_TESTUTIL_H
#define UAVAUTH_TESTS_TESTUTIL_H

// Minimal assertion harness.
//
// Deliberately does NOT use <cassert>: the project's release build defines
// NDEBUG, which compiles assert() to nothing. The previous test file used
// assert() and would have silently passed under a release build.

#include <cstdio>
#include <cstdlib>
#include <string>

namespace uavauth {
namespace test {

inline int& failureCount() {
    static int count = 0;
    return count;
}

inline int& checkCount() {
    static int count = 0;
    return count;
}

inline void reportFailure(const char* file, int line, const std::string& what) {
    ++failureCount();
    std::fprintf(stderr, "  FAIL %s:%d  %s\n", file, line, what.c_str());
}

inline int summarise(const char* suiteName) {
    if (failureCount() == 0) {
        std::printf("PASS  %-28s (%d checks)\n", suiteName, checkCount());
        return 0;
    }
    std::printf("FAIL  %-28s (%d failures / %d checks)\n", suiteName, failureCount(),
                checkCount());
    return 1;
}

} // namespace test
} // namespace uavauth

#define CHECK(cond)                                                                    \
    do {                                                                               \
        ++::uavauth::test::checkCount();                                               \
        if (!(cond)) ::uavauth::test::reportFailure(__FILE__, __LINE__, #cond);        \
    } while (0)

#define CHECK_MSG(cond, msg)                                                           \
    do {                                                                               \
        ++::uavauth::test::checkCount();                                               \
        if (!(cond))                                                                   \
            ::uavauth::test::reportFailure(__FILE__, __LINE__,                         \
                                           std::string(#cond) + " -- " + (msg));       \
    } while (0)

#define CHECK_EQ(a, b)                                                                 \
    do {                                                                               \
        ++::uavauth::test::checkCount();                                               \
        if (!((a) == (b)))                                                             \
            ::uavauth::test::reportFailure(__FILE__, __LINE__,                         \
                                           std::string(#a) + " == " + #b);             \
    } while (0)

#define CHECK_HEX_EQ(actualBytes, expectedHex)                                         \
    do {                                                                               \
        ++::uavauth::test::checkCount();                                               \
        const std::string got = ::uavauth::core::toHex(actualBytes);                   \
        const std::string want = (expectedHex);                                        \
        if (got != want)                                                               \
            ::uavauth::test::reportFailure(__FILE__, __LINE__,                         \
                                           "got " + got + " want " + want);            \
    } while (0)

#define CHECK_THROWS(expr)                                                             \
    do {                                                                               \
        ++::uavauth::test::checkCount();                                               \
        bool threw = false;                                                            \
        try { (void)(expr); } catch (...) { threw = true; }                            \
        if (!threw)                                                                    \
            ::uavauth::test::reportFailure(__FILE__, __LINE__,                         \
                                           std::string(#expr) + " did not throw");     \
    } while (0)

#endif
