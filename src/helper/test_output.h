#define ENABLE_TEST_OUTPUT 1

#if ENABLE_TEST_OUTPUT
#include <sstream>
#include <iostream>
#include <codecvt>
#include <locale>

#define TEST_OUTPUT(x) do { \
    std::wstringstream wss; \
    wss << x; \
    std::wcout << "\t" << wss.str() << std::endl; \
} while (0)

#else
#define TEST_OUTPUT(x)
#endif