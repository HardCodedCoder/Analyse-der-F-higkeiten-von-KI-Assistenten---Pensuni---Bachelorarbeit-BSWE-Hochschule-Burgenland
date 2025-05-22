#include "../helper/test_output.h"
#include <sstream>
class OneIntClass {
public:
	int intOne;
};

class TwoIntsClass
{
public:
	int intOne;
	int intTwo;
};

class CWE401_Memory_Leak__wchar_t_realloc_82_base
{
public:
	virtual void action(wchar_t* data) = 0;
	virtual ~CWE401_Memory_Leak__wchar_t_realloc_82_base() {}
};

class CWE401_Memory_Leak__wchar_t_realloc_82_bad : public CWE401_Memory_Leak__wchar_t_realloc_82_base
{
public:
    void action(wchar_t* data) override
    {
        /* POTENTIAL FLAW: No deallocation */
        (void)data;
    }
};

/* Good derived: proper deallocation */
class CWE401_Memory_Leak__wchar_t_realloc_82_good : public CWE401_Memory_Leak__wchar_t_realloc_82_base
{
public:
    void action(wchar_t* data) override
    {
        /* FIX: Deallocate memory */
        free(data);
    }
};

class BadBaseClass
{
public:
    BadBaseClass()
    {
        TEST_OUTPUT("Constructor: BadBaseClass");
    }

    /* FLAW: Non-virtual destructor - the destructor of the
     * derived class will not be called */
    ~BadBaseClass()
    {
        TEST_OUTPUT("Destructor : BadBaseClass");
    }
};

class BadDerivedClass : public BadBaseClass
{
public:
    BadDerivedClass(const char* name)
    {
        TEST_OUTPUT("Constructor: BadDerivedClass");
        if (name)
        {
            this->name = new char[strlen(name) + 1];
            strcpy(this->name, name);
            TEST_OUTPUT(this->name);
        }
        else
        {
            this->name = new char[1];
            *(this->name) = '\0';
        }
    }

    ~BadDerivedClass()
    {
        /* This should never be executed */
        TEST_OUTPUT("Destructor : BadDerivedClass");
        delete[] name;
    }

    /* copy constructor is only here to avoid double free incidentals */
    BadDerivedClass(BadDerivedClass& derivedClassObject)
    {
        this->name = new char[strlen(derivedClassObject.name) + 1];
        strcpy(this->name, derivedClassObject.name);
    }

    /* operator= is only here to avoid double free incidentals */
    BadDerivedClass& operator=(const BadDerivedClass& derivedClassObject)
    {
        if (&derivedClassObject != this)
        {
            this->name = new char[strlen(derivedClassObject.name) + 1];
            strcpy(this->name, derivedClassObject.name);
        }
        return *this;
    }

private:
    char* name;
};


class GoodBaseClass
{
public:
    GoodBaseClass()
    {
        TEST_OUTPUT("Constructor: GoodBaseClass");
    }

    /* FIX: Use a virtual destructor in the base class */
    virtual ~GoodBaseClass()
    {
        TEST_OUTPUT("Destructor : GoodBaseClass");
    }
};

class GoodDerivedClass : public GoodBaseClass
{
public:
    GoodDerivedClass(const char* name)
    {
        TEST_OUTPUT("Constructor: GoodDerivedClass");
        if (name)
        {
            this->name = new char[strlen(name) + 1];
            strcpy(this->name, name);
            TEST_OUTPUT(this->name);
        }
        else
        {
            this->name = new char[1];
            *(this->name) = '\0';
        }
    }

    ~GoodDerivedClass()
    {
        TEST_OUTPUT("Destructor : GoodDerivedClass");
        delete[] name;
    }

    /* copy constructor is only here to avoid double free incidentals */
    GoodDerivedClass(GoodDerivedClass& derivedClassObject)
    {
        this->name = new char[strlen(derivedClassObject.name) + 1];
        strcpy(this->name, derivedClassObject.name);
    }

    /* operator= is only here to avoid double free incidentals */
    GoodDerivedClass& operator=(const GoodDerivedClass& derivedClassObject)
    {
        if (&derivedClassObject != this)
        {
            this->name = new char[strlen(derivedClassObject.name) + 1];
            strcpy(this->name, derivedClassObject.name);
        }
        return *this;
    }

private:
    char* name;
};
