/*
 * @brief
 * Demonstriert einen Memory Leak, indem Speicher per realloc alloziert, aber nie freigegeben wird.
 * CWE: 401 Memory Leak
 * Details:
 * - Ein wchar_t-Puffer wird in jeder Iteration per realloc alloziert.
 * - Der Puffer wird nicht mit free() freigegeben, sodass Speicherlecks entstehen.
 * - Misst den Heap-Verbrauch vor und nach der Schleife, um die gesamte Leckgr��e zu berechnen.
 * - Ben�tigt die CRT-Debug-Heap-Flags (_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF)
 *   am Programmstart unter Windows f�r genaue Messungen.
 * Beispielaufruf: `CWE401_Memory_Leak__wchar_t_realloc_82_bad_test();`
 * URL: https://samate.nist.gov/SARD/test-cases/240070/versions/2.0.0
 */
void CWE401_Memory_Leak__wchar_t_realloc_82_bad_test();

/*
 * @brief
 * Demonstriert korrekte Speicherfreigabe und verhindert Memory Leaks.
 * CWE: 401 Memory Leak (Guter Pfad)
 * Details:
 * - Ein wchar_t-Puffer wird in jeder Iteration per realloc alloziert.
 * - Der Puffer wird mit free() �ber die good action()-Implementierung freigegeben.
 * - Misst den Heap-Verbrauch vor und nach der Schleife, um sicherzustellen, dass kein Leak auftritt.
 * Beispielaufruf: `CWE401_Memory_Leak__wchar_t_realloc_82_good_test();`
 * URL: https://samate.nist.gov/SARD/test-cases/240070/versions/2.0.0
 */
void CWE401_Memory_Leak__wchar_t_realloc_82_good_test();

/*
 * @brief
 * Demonstriert einen Memory Leak, indem Speicher per calloc alloziert, aber nie freigegeben wird.
 * CWE: 401 Memory Leak
 * Details:
 * - Ein char-Puffer wird in jeder Iteration per calloc alloziert.
 * - Der Puffer wird nicht mit free() freigegeben, sodass Speicherlecks entstehen.
 * Beispielaufruf: `CWE401_Memory_Leak__char_calloc_74a_bad();`
 * URL: https://samate.nist.gov/SARD/test-cases/99244/versions/1.0.0
 */
void CWE401_Memory_Leak__char_calloc_74a_bad();

/*
 * @brief
 * Demonstriert korrekte Speicherfreigabe und verhindert Memory Leaks.
 * CWE: 401 Memory Leak (Guter Pfad)
 * Details:
 * - Ein char-Puffer wird in jeder Iteration per calloc alloziert.
 * - Der Puffer wird mit free() �ber die goodSink()-Implementierung freigegeben.
 * Beispielaufruf: `CWE401_Memory_Leak__char_calloc_74a_good();
 * URL: https://samate.nist.gov/SARD/test-cases/99244/versions/1.0.0
 */
void CWE401_Memory_Leak__char_calloc_74a_good();

/*
 * @brief
 * Demonstriert einen Memory Leak durch Nichtfreigabe von per new[] alloziertem Speicher.
 * CWE: 401 Memory Leak
 * Details:
 * - Speicher wird mit new[] alloziert.
 * - Abh�ngig von der statischen Variablen `badStatic` wird kein delete[] aufgerufen.
 * - F�hrt zu dauerhaft belegtem Heap-Speicher ohne Freigabe.
 * Beispielaufruf: `CWE401_Memory_Leak__new_array_char_21_bad();`
 * URL: https://samate.nist.gov/SARD/test-cases/99760/versions/1.0.0
 */
void CWE401_Memory_Leak__new_array_char_21_bad();

/*
 * @brief
 * Demonstriert drei Varianten korrekter Speicherfreigabe und -verwaltung.
 * CWE: 401 Memory Leak (Guter Pfad)
 * Details:
 * - goodB2G1(): Memory wird per new[] alloziert und �ber delete[] im "else"-Zweig freigegeben.
 * - goodB2G2(): Memory wird per new[] alloziert und �ber delete[] im "if"-Zweig freigegeben.
 * - goodG2B(): Memory wird auf dem Stack alloziert; delete[] wird nicht aufgerufen, f�hrt aber nicht zu einem Leak.
 * Beispielaufruf: `CWE401_Memory_Leak__new_array_char_21_good();`
 * URL: https://samate.nist.gov/SARD/test-cases/99760/versions/1.0.0
 */
void CWE401_Memory_Leak__new_array_char_21_good();

/*
 * @brief
 * Demonstriert einen Memory Leak bei Heap-Allokation von TwoIntsClass.
 * CWE: 401 Memory Leak
 * Details:
 * - Ein Array von TwoIntsClass wird per new[] auf dem Heap alloziert.
 * - L�scht das Array nie, da delete[] im if-Zweig nicht aufgerufen wird.
 * - Steuerung erfolgt durch STATIC_CONST_TRUE, die immer true ist.
 * Beispielaufruf: `CWE401_Memory_Leak__new_array_TwoIntsClass_04_bad();`
 * URL: https://samate.nist.gov/SARD/test-cases/99829/versions/1.0.0
 */
void CWE401_Memory_Leak__new_array_TwoIntsClass_04_bad();

/*
 * @brief
 * Demonstriert vier sichere Pfade zur Vermeidung von Memory Leaks bei TwoIntsClass.
 * CWE: 401 Memory Leak (Good Paths)
 * Details:
 * - goodB2G1_TwoInts(): Heap-Allokation per new[] und L�schung im else-Zweig (STATIC_CONST_FALSE).
 * - goodB2G2_TwoInts(): Heap-Allokation per new[] und L�schung im if-Zweig (STATIC_CONST_TRUE).
 * - goodG2B1_TwoInts(): Stack-Allokation eines TwoIntsClass-Arrays, kein delete[] n�tig.
 * - goodG2B2_TwoInts(): Stack-Allokation eines TwoIntsClass-Arrays, kein delete[] n�tig.
 * Alle vier Varianten werden durch einen Aufruf von `CWE401_Memory_Leak__new_array_TwoIntsClass_04_good();`
 * ausgef�hrt.
 * URL: https://samate.nist.gov/SARD/test-cases/99829/versions/1.0.0
 */
void CWE401_Memory_Leak__new_array_TwoIntsClass_04_good();

/*
 * @brief
 * Demonstriert einen Speicher-Freigabe-Fehler aufgrund eines fehlenden virtuellen Destruktors.
 * CWE: 401 Memory Leak (durch Nichtaufruf des Derived-Destruktors)
 * Details:
 * - Ein Objekt der abgeleiteten Klasse BadDerivedClass wird �ber einen Pointer vom Typ
 *   BadBaseClass zugewiesen.
 * - BadBaseClass besitzt keinen virtuellen Destruktor, daher wird beim L�schen nur
 *   der Basisklassen-Destruktor ausgef�hrt.
 * - Der Derived-Destruktor (inkl. delete[] name) wird nicht aufgerufen, was zu
 *   Memory Leaks f�r `name` f�hrt.
 * Beispielaufruf: `CWE401_Memory_Leak__virtual_destructor_01_bad();`
 * URL: https://samate.nist.gov/SARD/test-cases/100714/versions/1.0.0
 */
void CWE401_Memory_Leak__virtual_destructor_01_bad();

/*
 * @brief
 * Korrekte Nutzung eines virtuellen Destruktors zur vollst�ndigen Freigabe von Derived-Ressourcen.
 * CWE: 401 Memory Leak (guter Pfad)
 * Details:
 * - Ein Objekt der abgeleiteten Klasse GoodDerivedClass wird �ber einen Pointer vom Typ
 *   GoodBaseClass zugewiesen.
 * - GoodBaseClass definiert einen virtuellen Destruktor, sodass beim `delete`
 *   sowohl der Basisklassen- als auch der Derived-Destruktor aufgerufen wird.
 * - Dadurch wird auch der bei GoodDerivedClass allozierte Speicher via `delete[] name`
 *   korrekt freigegeben.
 * Beispielaufruf: `CWE401_Memory_Leak__virtual_destructor_01_good();`
 * URL: https://samate.nist.gov/SARD/test-cases/100714/versions/1.0.0
 */
void CWE401_Memory_Leak__virtual_destructor_01_good();
