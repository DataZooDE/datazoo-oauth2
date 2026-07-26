#include <catch2/catch_test_macros.hpp>

// S-0.9: trivial pure test proving the Catch2 unit-test binary builds and
// runs with zero network and zero credentials.
TEST_CASE("scaffold: the unit test binary runs", "[scaffold]") {
    REQUIRE(1 + 1 == 2);
}
