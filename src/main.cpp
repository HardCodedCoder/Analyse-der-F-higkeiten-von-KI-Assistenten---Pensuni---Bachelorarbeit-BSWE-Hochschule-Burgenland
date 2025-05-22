#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>
#include <map>

#include "./buffer_overflow/buffer_tests.h"
#include "./use_after_free/use_after_tests.h"
#include "./memory_leak/memory_leak_tests.h"

std::map<DWORD, std::string> knownErrors = {
       { 0xC0000005, "Access Violation (möglicher Buffer Overflow oder Use-after-free)" },
       { 0xC0000409, "Stack Buffer Overflow Detected (FAST_FAIL)" },
       { 0x80000003, "Breakpoint erreicht (Debug-Ausnahme)" },
       { 0xC000001D, "Illegal Instruction (ungültiger Maschinencode)" },
       { 0xC00000FD, "Stack Overflow" },
       { 0x00000102, "Der Testcase lief ins timeout (undefined behavior, crash, ...)"}
};

std::map<std::string, std::vector<unsigned int>> cweCategories = {
    { "TC1_B", {121} },
    { "TC1_G", {121} },
    { "TC2_B", {122} },
    { "TC2_G", {122} },
    { "TC3_B", {124} },
    { "TC3_G", {124} },
    { "TC4_B", {121, 129} },
    { "TC4_G", {121, 129} },
    { "TC5_B", {121} },
    { "TC5_G", {121} },
    { "TC6_B", {416} },
    { "TC6_G", {416} },
    { "TC7_B", {416} },
    { "TC7_G", {416} },
    { "TC8_B", {416} },
    { "TC8_G", {416} },
    { "TC9_B", {416} },
    { "TC9_G", {416} },
    { "TC10_B", {416} },
    { "TC10_G", {416} },
    { "TC11_B", {401} },
    { "TC11_G", {401} },
    { "TC12_B", {401} },
    { "TC12_G", {401} },
    { "TC13_B", {401} },
    { "TC13_G", {401} },
    { "TC14_B", {401} },
    { "TC14_G", {401} },
    { "TC15_B", {401} },
    { "TC15_G", {401} }
};

std::vector<std::string> bad_tests = {
    "TC1_B",
    "TC2_B",
    "TC3_B",
    "TC4_B",
    "TC5_B",
    "TC6_B",
    "TC7_B",
    "TC8_B",
    "TC9_B",
    "TC10_B",
    "TC11_B",
    "TC12_B",
    "TC13_B",
    "TC14_B",
    "TC15_B"
};

std::vector<std::string> good_tests = {
    "TC1_G",
    "TC2_G",
    "TC3_G",
    "TC4_G",
    "TC5_G",
    "TC6_G",
    "TC7_G",
    "TC8_G",
    "TC9_G",
    "TC10_G",
    "TC11_G",
    "TC12_G",
    "TC13_G",
    "TC14_G",
    "TC15_G"
};

constexpr const char* COLOR_RESET = "\033[0m";
constexpr const char* COLOR_YELLOW = "\033[33m";
constexpr const char* COLOR_CYAN = "\033[36m";
constexpr const char* COLOR_GREEN = "\033[32m";
constexpr const char* COLOR_RED = "\033[31m";
constexpr const char* COLOR_WHITE = "\033[97m";
constexpr const char* COLOR_MAGENTA = "\033[35m";

void printResult(DWORD exitCode, const std::string& testname, const std::string& childOutput) {
    auto end = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    std::string testType = "";
    if (testname.find("_B") != std::string::npos) {
        testType = "Schwachstelle";
    }
    else if (testname.find("_G") != std::string::npos) {
        testType = "Gefixt";
    }

    std::cout << "------------------------------------------------------------" << std::endl;
    std::string colorTestcase = testname.find("_B") != std::string::npos ? COLOR_RED : COLOR_GREEN;
    colorTestcase += testname + COLOR_RESET;
    std::cout << "Testcase:     " << colorTestcase  << std::endl;
    std::cout << "Testtyp:      " << testType << std::endl;
    auto it = cweCategories.find(testname);
    std::cout << "CWE-Kategorie: ";
    if (it == cweCategories.end()) {
        std::cout << "unbekannt";
    }
    else {
        for (size_t i = 0; i < it->second.size(); ++i) {
            std::cout << COLOR_CYAN + std::to_string(it->second[i]) + COLOR_RESET;
            if (i + 1 < it->second.size()) std::cout << ", ";
        }
    }
    std::cout << std::endl;
    std::cout << "Beendet am:   " << std::ctime(&end_time);
    if (!childOutput.empty())
        std::cout << "Ausgabe Testcase: \n" << childOutput << std::endl;
    std::cout << "Exit-Code:    " << exitCode << " (0x" << std::hex << exitCode << std::dec << ")" << std::endl;
    if (knownErrors.find(exitCode) != knownErrors.end()) {
        std::cout << COLOR_WHITE << "[INFO] " << COLOR_RESET << "        " << knownErrors[exitCode] << std::endl;
    }
    else {
        std::cout << COLOR_WHITE << "[INFO] " << COLOR_RESET << "        Kein bekannter Fehlercode.Möglicherweise normal beendet oder undefiniertes Verhalten." << std::endl;
    }
}

struct Args {
    int argc;
    char** argv;
};

Args create_args(const std::string& tcId) {
    const char* fake_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const int fake_argc = 2;
    char** fake_argv = new char*[2];
    fake_argv[0] = const_cast<char*>("dummy");
    fake_argv[1] = const_cast<char*>(fake_input);
    return { fake_argc, fake_argv };
}

void run_specific_test(const std::string& testname) {
    // START BAD TESTCASES
    if (testname == "TC1_B") {
        CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad();
    } else if (testname == "TC2_B") {
        Args args = create_args("TC2_B");
        CWE122_Heap_Based_Buffer_Overflow__strcpy9_bad(args.argc, args.argv);
        delete[] args.argv;
    }
    else if (testname == "TC3_B") {
        CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_bad();
    }
    else if (testname == "TC4_B") {
        CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_bad();
    }
    else if (testname == "TC5_B") {
        CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_bad();
    }
    else if (testname == "TC6_B") {
        CWE416_Use_After_Free__malloc_free_wchar_t_13_bad();
    }
    else if (testname == "TC7_B") {
        CWE416_Use_After_Free__malloc_free_long_15_mixed();
    }
    else if (testname == "TC8_B") {
        CWE416_Use_After_Free__operator_equals_01_bad();
    }
    else if (testname == "TC9_B") {
        CWE416_Use_After_Free__return_freed_ptr_mixed();
    }
    else if (testname == "TC10_B") {
        CWE416_Use_After_Free__new_delete_class_bad();
    }
    else if (testname == "TC11_B") {
        CWE401_Memory_Leak__wchar_t_realloc_82_bad_test();
    }
    else if (testname == "TC12_B") {
        CWE401_Memory_Leak__char_calloc_74a_bad();
    }
    else if (testname == "TC13_B") {
        CWE401_Memory_Leak__new_array_char_21_bad();
    }
    else if (testname == "TC14_B") {
        CWE401_Memory_Leak__new_array_TwoIntsClass_04_bad();
    }
    else if (testname == "TC15_B") {
        CWE401_Memory_Leak__virtual_destructor_01_bad();
    }
    // START GOOD TESTCASES 
    else if (testname == "TC1_G") {
        CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good();
    }
    else if (testname == "TC2_G") {
        Args args = create_args("TC2_G");
        CWE122_Heap_Based_Buffer_Overflow__strcpy9_good(args.argc, args.argv);
        delete[] args.argv;
    }
    else if (testname == "TC3_G") {
        CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_good();   
    }
    else if (testname == "TC4_G") {
        CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_good();
    }
    else if (testname == "TC5_G") {
        CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_good();
    }
    else if (testname == "TC6_G") {
        CWE416_Use_After_Free__malloc_free_wchar_t_13_good();
    }
    else if (testname == "TC7_G") {
        CWE416_Use_After_Free__malloc_free_long_15_mixed(true);
    }
    else if (testname == "TC8_G") {
        CWE416_Use_After_Free__operator_equals_01_good();
    }
    else if (testname == "TC9_G") {
        CWE416_Use_After_Free__return_freed_ptr_mixed(true);
    }
    else if (testname == "TC10_G") {
        CWE416_Use_After_Free__new_delete_class_good();
    }
    else if (testname == "TC11_G") {
        CWE401_Memory_Leak__wchar_t_realloc_82_good_test();
    }
    else if (testname == "TC12_G") {
        CWE401_Memory_Leak__char_calloc_74a_good();
    }
    else if (testname == "TC13_G") {
        CWE401_Memory_Leak__new_array_char_21_good();
    }
    else if (testname == "TC14_G") {
        CWE401_Memory_Leak__new_array_TwoIntsClass_04_good();
    }
    else if (testname == "TC15_G") {
        CWE401_Memory_Leak__virtual_destructor_01_good();
    }
    else {
        std::cout << "Unknown test: " << testname << std::endl;
    }
}

void start_test_process(const std::string& testname) {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        std::cerr << "Pipe konnte nicht erstellt werden!" << std::endl;
        return;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    ZeroMemory(&pi, sizeof(pi));

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string commandLine = exePath + std::string(" ") + testname;

    if (!CreateProcessA(
        NULL,
        commandLine.data(),
        NULL,
        NULL,
        TRUE, // Handles vererben!
        0,
        NULL,
        NULL,
        &si,
        &pi)
        ) {
        std::cerr << "Fehler beim Erzeugen des Kindprozesses: " << GetLastError() << std::endl;
        std::cerr << "Abbruch des Testcases!" << std::endl;
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return;
    }

    CloseHandle(hWrite); // Elternprozess braucht Schreib-Ende nicht

    DWORD waitResult; 
    if (testname == "TC11_G" || testname == "TC11_B") {
        waitResult = WaitForSingleObject(pi.hProcess, 20000); // 20 Sekunden warten
    }
    else {
        waitResult = WaitForSingleObject(pi.hProcess, 5000); // 5000 ms = 5 Sekunden
    }

    if (waitResult == WAIT_TIMEOUT) {
        std::cerr << COLOR_RED << "[ERROR]" << COLOR_RESET << " Testcase hat das Zeitlimit von 5 Sekunden überschritten und wird beendet." << std::endl;
        TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
    }

    // Kindprozess-Ausgabe lesen
    std::stringstream childOutput;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        childOutput << buffer;
    }

    CloseHandle(hRead);

    
    DWORD exitCode;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        printResult(exitCode, testname, childOutput.str());
    }
    else {
        std::cerr << "\033[31m[ERROR]\033[0m Fehler beim Abrufen des Exit-Codes: " << GetLastError() << std::endl;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void run_bad_tests() {
	for (const auto& testname : bad_tests) {
        start_test_process(testname);
    }
}

void run_good_tests() {
    for (const auto& testname : good_tests) {
        start_test_process(testname);
    }
}

void printHelp() {

}

int main(int argc, char** argv) {
    /* seed randomness */
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    srand((unsigned)time(NULL));

    SetConsoleOutputCP(CP_UTF8);
    std::cout.imbue(std::locale(""));
    std::wcout.imbue(std::locale(""));

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <mode>\n";
        std::cerr << "Modes: good, bad, all, TC1_B, TC2_B, TC3_B, TC1_G, TC2_G...\n";
        return -1;
    }

	std::string mode = argv[1];

    if (mode == "TC1_B" ||
        mode == "TC2_B" ||
        mode == "TC3_B" ||
        mode == "TC4_B" ||
        mode == "TC5_B" ||
        mode == "TC6_B" ||
        mode == "TC7_B" ||
        mode == "TC8_B" ||
        mode == "TC9_B" ||
        mode == "TC10_B" ||
        mode == "TC11_B" ||
        mode == "TC12_B" ||
        mode == "TC13_B" ||
        mode == "TC14_B" ||
        mode == "TC15_B" ||
        mode == "TC1_G" ||
        mode == "TC2_G" ||
        mode == "TC3_G" ||
        mode == "TC4_G" ||
        mode == "TC5_G" ||
        mode == "TC6_G" ||
        mode == "TC7_G" ||
        mode == "TC8_G" ||
        mode == "TC9_G" ||
        mode == "TC10_G" ||
        mode == "TC11_G" ||
        mode == "TC12_G" ||
        mode == "TC13_G" ||
        mode == "TC14_G" ||
        mode == "TC15_G"
       ) {
        try {
            run_specific_test(mode);
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        return 0;
    }

    if (mode == "good") {
        std::cout << "--- Running GOOD tests ---\n";
        run_good_tests();
    } else if (mode == "bad") {
        std::cout << "--- Running BAD tests ---\n";
        run_bad_tests();
    } else if (mode == "all") {
        std::cout << "--- Running ALL tests ---\n";
        run_good_tests();
        run_bad_tests();
    } else {
        std::cout << "Unknown mode: " << mode << "\n";
        return 1;
    }

    std::cout << "------------------------------------------------------------" << std::endl;
    return 0;
}
