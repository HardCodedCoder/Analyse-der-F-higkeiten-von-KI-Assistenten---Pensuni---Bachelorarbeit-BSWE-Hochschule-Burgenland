#include <iostream>
#include <cstring>

#include "buffer_tests.h"
#include "../helper/test_output.h"
#include "../helper/helper_structures.h"

#include <WinSock2.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") // include ws2_32.lib when linking
#define CLOSE_SOCKET closesocket
#define MAXSIZE 40
#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

// =================================================================================================

typedef struct charVoid {
	char charFirst[16];
	void* voidSecond;
	void* voidThird;
} charVoid;

void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad() {

	const char* SRC_STR = "0123456789abcdef0123456789abcde";

	charVoid cv;
	cv.voidSecond = (void*)SRC_STR;

	TEST_OUTPUT("Vor memcpy: " << (char*)cv.voidSecond);

	// Fehler: memcpy kopiert zu viel und überschreibt voidSecond
	memcpy(cv.charFirst, SRC_STR, sizeof(cv));

	cv.charFirst[sizeof(cv.charFirst) - 1] = '\0'; // Null-Terminierung

	TEST_OUTPUT("Nach memcpy (Overflow): " << cv.charFirst);

	TEST_OUTPUT("Möglicherweise beschädigt: " << (char*)cv.voidSecond);
}

void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good() {
	const char* SRC_STR = "0123456789abcdef0123456789abcde";

	charVoid cv;
	cv.voidSecond = (void*)SRC_STR;

	TEST_OUTPUT("Vor memcpy: " << (char*)cv.voidSecond);

	// Korrekt: memcpy kopiert nur die Größe von charFirst
	memcpy(cv.charFirst, SRC_STR, sizeof(cv.charFirst));

	cv.charFirst[sizeof(cv.charFirst) - 1] = '\0'; // Null-Terminierung

	TEST_OUTPUT("Nach memcpy (Kein Overflow): " << cv.charFirst);
	TEST_OUTPUT("Unverändert: " << (char*)cv.voidSecond);
}

// ==========================================================================================

char* shortstr(char* p, int n, int targ) {
	if (n > targ) 
		return shortstr(p+1, n-1, targ);
	return p;
}

void test(char* str) {
	char* buf; 

	buf = (char*)malloc(MAXSIZE);
	if (!buf)
		return;
	
    strcpy(buf, str);   // potential FLAW depending on the size of str
	TEST_OUTPUT("result: " << buf);

	free(buf);
}

void CWE122_Heap_Based_Buffer_Overflow__strcpy9_bad(int argc, char** argv) {
	char* userstr, * str2;

	if (argc > 1) {
		userstr = argv[1];
		str2 = shortstr(userstr, strlen(userstr), 80); // FLAW
		test(str2);
	}
}

void CWE122_Heap_Based_Buffer_Overflow__strcpy9_good(int argc, char** argv) {
	char* userstr, * str2;
	if (argc > 1) {
		userstr = argv[1];
		str2 = shortstr(userstr, strlen(userstr), MAXSIZE - 1);	/* FIX */
		test(str2);
	}
}

//===========================================================================================

#define SIZE 100

void CWE124_Buffer_Underwrite_execute(wchar_t* data) {
	{
		wchar_t source[SIZE];
		wmemset(source, L'C', SIZE - 1);
		source[SIZE - 1] = L'\0'; // Null-Terminierung
		TEST_OUTPUT(L"data vor wcsncpy: " << data);
		wcsncpy(data, source, SIZE - 1);
		data[SIZE - 1] = L'\0'; // Null-Terminierung
		TEST_OUTPUT(L"data nach wcsncpy: " << data);
	}
}

void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_bad() {
	wchar_t* data; 
	data = NULL; 
	{
		wchar_t* dataBuffer = (wchar_t*)malloc(SIZE * sizeof(wchar_t));
        if (dataBuffer == NULL) { exit(-1); }
		wmemset(dataBuffer, L'A', SIZE - 1);
        dataBuffer[SIZE - 1] = L'\0'; // Null-Terminierung
        // FLAW: Setze den Zeiger auf einen Speicherbereich, der vor dem zugewiesenen Speicher liegt
        data = dataBuffer - 8;
	}
	CWE124_Buffer_Underwrite_execute(data);
	free(data);
}

void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_good() {
	wchar_t* data;
	data = NULL;
	{
		wchar_t* dataBuffer = (wchar_t*)malloc(SIZE * sizeof(wchar_t));
		if (dataBuffer == NULL) { exit(-1); }
		wmemset(dataBuffer, L'A', SIZE - 1);
        dataBuffer[SIZE - 1] = L'\0'; // Null-Terminierung
		// FIX: Setze den Zeiger auf den zugewiesenen Speicherpuffer
		data = dataBuffer;
	}
	CWE124_Buffer_Underwrite_execute(data);
	free(data);
}

//===========================================================================================

void connect_socket_helper(int& data, bool good) {
    // Normally the testcase would read from a socket , but for this example we will just simulate the behavior
	if (good)
		data = 7;
	else if (!good)
		data = 1024;

	return;
}

void CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_bad() {
	int data;
	/* Initialize data */
	data = -1;
	connect_socket_helper(data, false);
	{
		int i;
		int buffer[10] = { 0 };
		/* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
		* This code does check to see if the array index is negative */
		
		if (data >= 0)
		{
			buffer[data] = 1;
			/* Print the array values */
			for (i = 0; i < 10; i++)
			{
				TEST_OUTPUT(buffer[i]);
			}
		}
		else
		{
			TEST_OUTPUT("ERROR: Array index is negative.");
		}
	}
}

void CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_good()
{
	int data;
	/* Initialize data */
	data = -1;
	connect_socket_helper(data, true);
	{
		int i;
		int buffer[10] = { 0 };
		/* FIX: Properly validate the array index and prevent a buffer overflow */
		if (data >= 0 && data < (10))
		{
			buffer[data] = 1;
			/* Print the array values */
			for (i = 0; i < 10; i++)
			{
				TEST_OUTPUT(buffer[i]);
			}
		}
		else
		{
			TEST_OUTPUT("ERROR: Array index is out-of-bounds");
		}
	}
}

//===========================================================================================

void CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_bad() {
	char* data;
	char*& dataRef = data;
	char dataBadBuffer[sizeof(OneIntClass)];
	/* POTENTIAL FLAW: Initialize data to a buffer smaller than the sizeof(TwoIntsClass) */
	data = dataBadBuffer;
	{
		char* data = dataRef;
		{
			/* POTENTIAL FLAW: data may not be large enough to hold a TwoIntsClass */
			TwoIntsClass* classTwo = new(data) TwoIntsClass;
			/* Initialize and make use of the class */
			classTwo->intOne = 5;
			classTwo->intTwo = 10; /* POTENTIAL FLAW: If sizeof(data) < sizeof(TwoIntsClass) then this line will be a buffer overflow */
			std::wcout << sizeof(OneIntClass) << std::endl;
			std::wcout << sizeof(TwoIntsClass) << std::endl;
			TEST_OUTPUT("Zahl 1: " << classTwo->intOne);
			TEST_OUTPUT("Zahl 2: " << classTwo->intTwo);
		}
	}
}

void CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_good()
{
	char* data;
	char*& dataRef = data;
	char dataGoodBuffer[sizeof(TwoIntsClass)];
    /* FIX: Initialize data to a buffer large enough to hold a TwoIntsClass */
	data = dataGoodBuffer;
	{
		char* data = dataRef;
		{
			TwoIntsClass* classTwo = new(data) TwoIntsClass;
			classTwo->intOne = 5;
			classTwo->intTwo = 10;
			std::wcout << sizeof(TwoIntsClass) << std::endl;
			TEST_OUTPUT("Zahl 1: " << classTwo->intOne);
			TEST_OUTPUT("Zahl 2: " << classTwo->intTwo);
		}
	}
}
