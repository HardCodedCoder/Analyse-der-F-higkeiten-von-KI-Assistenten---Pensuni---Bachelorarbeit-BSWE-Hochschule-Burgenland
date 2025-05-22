#include "use_after_tests.h"
#include "../helper/test_output.h"
#include "../helper/helper_structures.h"
#define GLOBAL_CONST_FIVE 5

#include <string>

class BadClass
{
public:
    BadClass()
    {
        name = NULL;
    }

    BadClass(const char* name)
    {
        if (name)
        {
            this->name = new char[strlen(name) + 1];
            strcpy(this->name, name);
        }
        else
        {
            this->name = new char[1];
            *(this->name) = '\0';
        }
    }

    ~BadClass()
    {
        delete[] name;
    }

    /* copy constructor is only here to avoid double free incidentals */
    BadClass(BadClass& badClassObject)
    {
        this->name = new char[strlen(badClassObject.name) + 1];
        strcpy(this->name, badClassObject.name);
    }

    BadClass& operator=(const BadClass& badClassObject)
    {
        /* No check for self-assignment */
        delete[] this->name;
        this->name = new char[strlen(badClassObject.name) + 1];
        strcpy(this->name, badClassObject.name); /* FLAW - if this is a self-assignment,
            badClassObject.name has already been deleted, so this is a use after free (CWE-416). */
        return *this;
    }

    char* name;
};

class GoodClass
{
public:
    GoodClass()
    {
        name = NULL;
    }

    GoodClass(const char* name)
    {
        if (name)
        {
            this->name = new char[strlen(name) + 1];
            strcpy(this->name, name);
        }
        else
        {
            this->name = new char[1];
            *(this->name) = '\0';
        }
    }

    ~GoodClass()
    {
        delete[] name;
    }

    /* copy constructor is only here to avoid double free incidentals */
    GoodClass(GoodClass& goodClassObject)
    {
        this->name = new char[strlen(goodClassObject.name) + 1];
        strcpy(this->name, goodClassObject.name);
    }

    GoodClass& operator=(const GoodClass& goodClassObject)
    {
        /* FIX - Check for self assignment and basically do nothing in that case */
        if (this != &goodClassObject)
        {
            delete[] this->name;
            this->name = new char[strlen(goodClassObject.name) + 1];
            strcpy(this->name, goodClassObject.name);
        }
        return *this;
    }

    char* name;
};

void CWE416_Use_After_Free__malloc_free_wchar_t_13_bad() {
    wchar_t* data;
    /* Initialize data */
    data = NULL;
    if (GLOBAL_CONST_FIVE == 5)
    {
        data = (wchar_t*)malloc(100 * sizeof(wchar_t));
        if (data == NULL) { exit(-1); }
        wmemset(data, L'A', 100 - 1);
        data[100 - 1] = L'\0';
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free(data);
    }
    if (GLOBAL_CONST_FIVE == 5)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        TEST_OUTPUT(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

void CWE416_Use_After_Free__malloc_free_wchar_t_13_good()
{
    wchar_t* data;
    /* Initialize data */
    data = NULL;
    if (GLOBAL_CONST_FIVE == 5)
    {
        data = (wchar_t*)malloc(100 * sizeof(wchar_t));
        if (data == NULL) { exit(-1); }
        wmemset(data, L'A', 100 - 1);
        data[100 - 1] = L'\0';
        free(data);
    }
    if (GLOBAL_CONST_FIVE == 5)
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

//===============================================================================

void helper_bad(int*& data) {
    data = (int*)malloc(100 * sizeof(int));
    if (data == NULL) { exit(-1); }
    {
        size_t i;
        for (i = 0; i < 100; i++)
        {
            data[i] = 5;
        }
    }
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free(data);
}
 
void helper_good(int*& data) {
    data = (int*)malloc(100 * sizeof(int));
    if (data == NULL) { exit(-1); }
    {
        size_t i;
        for (i = 0; i < 100; i++)
        {
            data[i] = 5;
        }
    }
    /* FIX: Do not free data */
}

void CWE416_Use_After_Free__malloc_free_long_15_mixed(bool good)
{
    int* data;
    /* Initialize data */
    data = NULL;
    if (good)
        helper_good(data);
    else
        helper_bad(data);
    /* POTENTIAL FLAW: Use of data that may have been freed */
    TEST_OUTPUT(data[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

//===============================================================================

void CWE416_Use_After_Free__operator_equals_01_bad()
{
    BadClass badClassObject("BadClass");
    badClassObject = badClassObject;
    TEST_OUTPUT(badClassObject.name);
}

void CWE416_Use_After_Free__operator_equals_01_good()
{
    GoodClass goodClassObject("GoodClass");
    goodClassObject = goodClassObject;
    TEST_OUTPUT(goodClassObject.name);
}

//===============================================================================

char* helperBad(const char* aString)
{
    size_t i = 0;
    size_t j;
    char* reversedString = NULL;
    if (aString != NULL)
    {
        i = strlen(aString);
        reversedString = (char*)malloc(i + 1);
        if (reversedString == NULL) { exit(-1); }
        for (j = 0; j < i; j++)
        {
            reversedString[j] = aString[i - j - 1];
        }
        reversedString[i] = '\0';
        /* FLAW: Freeing a memory block and then returning a pointer to the freed memory */
        free(reversedString);
        return reversedString;
    }
    else
    {
        return NULL;
    }
}

char* helperGood(const char* aString)
{
    size_t i = 0;
    size_t j;
    char* reversedString = NULL;
    if (aString != NULL)
    {
        i = strlen(aString);
        reversedString = (char*)malloc(i + 1);
        if (reversedString == NULL) { exit(-1); }
        for (j = 0; j < i; j++)
        {
            reversedString[j] = aString[i - j - 1];
        }
        reversedString[i] = '\0';
        /* FIX: Do not free the memory before returning */
        return reversedString;
    }
    else
    {
        return NULL;
    }
}

void CWE416_Use_After_Free__return_freed_ptr_mixed(bool good)
{
    /* Call the bad helper function */
    char* reversedString;
    if (good)
        reversedString = helperGood("GoodCase");
    else
        reversedString = helperBad("BadCase");

    TEST_OUTPUT(reversedString);
    /* free(reversedString);
     * This call to free() was removed because we want the tool to detect the use after free,
     * but we don't want that function to be free(). Essentially we want to avoid a double free
     */
}

// ===============================================================================
int globalReturnsTrueOrFalse()
{
    return (rand() % 2);
}

void CWE416_Use_After_Free__new_delete_class_bad()
{
    TwoIntsClass* data;
    /* Initialize data */
    data = NULL;
    if (globalReturnsTrueOrFalse())
    {
        data = new TwoIntsClass;
        data->intOne = 1;
        data->intTwo = 2;
        /* POTENTIAL FLAW: Delete data in the source */
        delete data;
    }
    else
    {
        data = new TwoIntsClass;
        data->intOne = 1;
        data->intTwo = 2;
        /* FIX: Do not delete data in the source */
    }
    if (globalReturnsTrueOrFalse())
    {
        /* POTENTIAL FLAW: Use of data that may have been deleted */
        TEST_OUTPUT(data->intOne);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
    }
    else
    {
        /* FIX: Don't use data that may have been deleted already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

void CWE416_Use_After_Free__new_delete_class_good()
{
    TwoIntsClass* data;
    /* Initialize data */
    data = NULL;
    if (globalReturnsTrueOrFalse())
    {
        data = new TwoIntsClass;
        data->intOne = 1;
        data->intTwo = 2;
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete data;
    }
    else
    {
        data = new TwoIntsClass;
        data->intOne = 1;
        data->intTwo = 2;
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete data;
    }
    if (globalReturnsTrueOrFalse())
    {
        /* FIX: Don't use data that may have been deleted already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
        /* do nothing */
    }
    else
    {
        /* FIX: Don't use data that may have been deleted already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
        /* do nothing */
    }
}
