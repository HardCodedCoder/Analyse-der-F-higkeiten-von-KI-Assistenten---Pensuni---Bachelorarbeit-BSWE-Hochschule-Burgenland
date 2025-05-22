#include "memory_leak_tests.h"
#include "../helper/test_output.h"
#include "../helper/helper_structures.h"

#include <iostream>
#include <wchar.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <map>

#define LOOP_COUNT 100

size_t getCurrentMemoryUsage()
{
    _CrtMemState state;
    _CrtMemCheckpoint(&state);
    return state.lSizes[_NORMAL_BLOCK];
}

void CWE401_Memory_Leak__wchar_t_realloc_82_bad_test()
{
    TEST_OUTPUT(L"[BAD] Memory leak measurement\n");
    size_t before = getCurrentMemoryUsage();
    std::cout << "Memory Before: " << before << " bytes" << std::endl;
    for (int i = 0; i < LOOP_COUNT; ++i)
    {
        wchar_t* data = NULL;
        data = (wchar_t*)realloc(data, 100 * sizeof(wchar_t));
        if (data == NULL) { exit(-1); }
        /* Initialize and make use of data */
        wcscpy(data, L"A String");
        TEST_OUTPUT(data);
        CWE401_Memory_Leak__wchar_t_realloc_82_base* baseObject = new CWE401_Memory_Leak__wchar_t_realloc_82_bad;
        baseObject->action(data);
        delete baseObject;
        size_t tmp = getCurrentMemoryUsage();
        std::cout << "Memory Usage After Iteration " << i << ": " << tmp << " bytes" << std::endl;
    }
    size_t after = getCurrentMemoryUsage();
    std::cout << "Memory Before: " << before << " bytes" << std::endl;
    std::cout << "Memory After: " << after << " bytes" << std::endl;
    std::cout << "Memory Leak: " << (after - before) << " bytes" << std::endl;
}

void CWE401_Memory_Leak__wchar_t_realloc_82_good_test()
{
    std::cout << "[GOOD] No memory leak expected\n";
    size_t before = getCurrentMemoryUsage();
    for (int i = 0; i < LOOP_COUNT; ++i)
    {
        wchar_t* data = NULL;
        data = (wchar_t*)realloc(data, 100 * sizeof(wchar_t));
        if (data == NULL) exit(-1);
        wcscpy(data, L"Safe String");
        TEST_OUTPUT(data);
        CWE401_Memory_Leak__wchar_t_realloc_82_base* baseObject = new CWE401_Memory_Leak__wchar_t_realloc_82_good;
        baseObject->action(data);
        delete baseObject;
    }
    size_t after = getCurrentMemoryUsage();
    std::cout << "Memory Before: " << before << " bytes" << std::endl;
    std::cout << "Memory After: " << after << " bytes" << std::endl;
    std::cout << "Memory Leak: " << (after - before) << " bytes" << std::endl;
}

// ==================================================================================

void badSink(std::map<int, char*> dataMap)
{
    /* copy data out of dataMap */
    char* data = dataMap[2];
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

void goodSink(std::map<int, char*> dataMap)
{
    char* data = dataMap[2];
    /* FIX: Deallocate memory */
    free(data);
}

void CWE401_Memory_Leak__char_calloc_74a_bad() {
    TEST_OUTPUT(L"[BAD] Memory leak measurement\n");
    size_t before = getCurrentMemoryUsage();
    for (int i = 0; i < LOOP_COUNT; ++i)
    {
        char* data;
        std::map<int, char*> dataMap;
        data = NULL;
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (char*)calloc(100, sizeof(char));
        /* Initialize and make use of data */
        strcpy(data, "A String");
        TEST_OUTPUT(data);
        /* Put data in a map */
        dataMap[0] = data;
        dataMap[1] = data;
        dataMap[2] = data;
        badSink(dataMap);
    }  
    size_t after = getCurrentMemoryUsage();
    std::cout << "Memory Before: " << before << " bytes" << std::endl;
    std::cout << "Memory After: " << after << " bytes" << std::endl;
    std::cout << "Memory Leak: " << (after - before) << " bytes" << std::endl;
}

void CWE401_Memory_Leak__char_calloc_74a_good()
{
    TEST_OUTPUT(L"[GOOD] No Memory leak expected\n");
    size_t before = getCurrentMemoryUsage();
    for (int i = 0; i < LOOP_COUNT; ++i)
    {
        char* data;
        std::map<int, char*> dataMap;
        data = NULL;
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = (char*)calloc(100, sizeof(char));
        /* Initialize and make use of data */
        strcpy(data, "A String");
        TEST_OUTPUT(data);
        /* Put data in a map */
        dataMap[0] = data;
        dataMap[1] = data;
        dataMap[2] = data;
        goodSink(dataMap);
    }
    size_t after = getCurrentMemoryUsage();
    std::cout << "Memory Before: " << before << " bytes" << std::endl;
    std::cout << "Memory After: " << after << " bytes" << std::endl;
    std::cout << "Memory Leak: " << (after - before) << " bytes" << std::endl;
}

// ===============================================================================

/* The static variable below is used to drive control flow in the sink function */
static int badStatic = 1;

static void badSink1(char* data)
{
    if (badStatic)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

void CWE401_Memory_Leak__new_array_char_21_bad()
{
    char* data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = new char[100];
    /* Initialize and make use of data */
    strcpy(data, "A String");
    TEST_OUTPUT(data);
    badStatic = 1; /* true */
    badSink1(data);
}

/* The static variables below are used to drive control flow in the sink functions. */
static int goodB2G1Static = 0;
static int goodB2G2Static = 0;
static int goodG2bStatic = 0;

static void goodB2G1Sink(char* data)
{
    if (goodB2G1Static)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        TEST_OUTPUT("Benign, fixed string");
    }
    else
    {
        /* FIX: Deallocate memory */
        delete[] data;
    }
}

static void goodB2G1()
{
    char* data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = new char[100];
    /* Initialize and make use of data */
    strcpy(data, "A String");
    TEST_OUTPUT(data);
    goodB2G1Static = 0; /* false */
    goodB2G1Sink(data);
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the if in the sink function */
static void goodB2G2Sink(char* data)
{
    if (goodB2G2Static)
    {
        /* FIX: Deallocate memory */
        delete[] data;
    }
}

static void goodB2G2()
{
    char* data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = new char[100];
    /* Initialize and make use of data */
    strcpy(data, "A String");
    TEST_OUTPUT(data);
    goodB2G2Static = 1; /* true */
    goodB2G2Sink(data);
}

/* goodG2B() - use goodsource and badsink */
static void goodG2BSink(char* data)
{
    if (goodG2bStatic)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

static void goodG2B()
{
    char* data;
    data = NULL;
    /* FIX: Use memory allocated on the stack */
    char dataGoodBuffer[100];
    data = dataGoodBuffer;
    /* Initialize and make use of data */
    strcpy(data, "A String");
    TEST_OUTPUT(data);
    goodG2bStatic = 1; /* true */
    goodG2BSink(data);
}

void CWE401_Memory_Leak__new_array_char_21_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B();
}

// ===========================================================================

/* The two variables below are declared "const", so a tool should
   be able to identify that reads of these will always return their
   initialized values. */
static const int STATIC_CONST_TRUE = 1; /* true */
static const int STATIC_CONST_FALSE = 0; /* false */

void CWE401_Memory_Leak__new_array_TwoIntsClass_04_bad()
{
    TwoIntsClass* data;
    data = NULL;
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = new TwoIntsClass[100];
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        TEST_OUTPUT(data[0].intOne);
        TEST_OUTPUT(data[0].intTwo);
    }
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodB2G1() - use badsource and goodsink by changing the second STATIC_CONST_TRUE to STATIC_CONST_FALSE */
static void goodB2G1_TwoInts()
{
    TwoIntsClass* data;
    data = NULL;
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = new TwoIntsClass[100];
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        TEST_OUTPUT(data[0].intOne);
        TEST_OUTPUT(data[0].intTwo);
    }
    if (STATIC_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        TEST_OUTPUT("Benign, fixed string");
    }
    else
    {
        /* FIX: Deallocate memory */
        delete[] data;
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2_TwoInts()
{
    TwoIntsClass* data;
    data = NULL;
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Allocate memory on the heap */
        data = new TwoIntsClass[100];
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        TEST_OUTPUT(data[0].intOne);
        TEST_OUTPUT(data[0].intTwo);
    }
    if (STATIC_CONST_TRUE)
    {
        /* FIX: Deallocate memory */
        delete[] data;
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first STATIC_CONST_TRUE to STATIC_CONST_FALSE */
static void goodG2B1_TwoInts()
{
    TwoIntsClass* data;
    data = NULL;
    if (STATIC_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        TEST_OUTPUT("Benign, fixed string");
    }
    else
    {
        /* FIX: Use memory allocated on the stack */
        TwoIntsClass dataGoodBuffer[100];
        data = dataGoodBuffer;
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        TEST_OUTPUT(data[0].intOne);
        TEST_OUTPUT(data[0].intTwo);
    }
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2_TwoInts()
{
    TwoIntsClass* data;
    data = NULL;
    if (STATIC_CONST_TRUE)
    {
        /* FIX: Use memory allocated on the stack */
        TwoIntsClass dataGoodBuffer[100];
        data = dataGoodBuffer;
        /* Initialize and make use of data */
        data[0].intOne = 0;
        data[0].intTwo = 0;
        TEST_OUTPUT(data[0].intOne);
        TEST_OUTPUT(data[0].intTwo);
    }
    if (STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: No deallocation */
        ; /* empty statement needed for some flow variants */
    }
}
void CWE401_Memory_Leak__new_array_TwoIntsClass_04_good()
{
    goodB2G1_TwoInts();
    goodB2G2_TwoInts();
    goodG2B1_TwoInts();
    goodG2B2_TwoInts();
}

// ==================================================================================

void CWE401_Memory_Leak__virtual_destructor_01_bad()
{
    BadBaseClass* baseClassObject = new BadDerivedClass("BadClass");
    delete baseClassObject;
}

void CWE401_Memory_Leak__virtual_destructor_01_good()
{
    GoodBaseClass* baseClassObject = new GoodDerivedClass("GoodClass");
    delete baseClassObject;
}