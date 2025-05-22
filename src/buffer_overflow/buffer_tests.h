#pragma once



/*
 * @brief
 * Demonstriert eine stackbasierte Buffer-Overflow-Sicherheitslücke, die durch die fehlerhafte Nutzung von `memcpy` verursacht wird.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `memcpy` kopiert die Größe der gesamten Struktur (`sizeof(cv)`) anstelle der Größe des Zielpuffers (`cv.charFirst`).
 * - Dies führt zu einem Überlauf, der den Zeiger `voidSecond` in der Struktur überschreibt.
 * - Der Überlauf resultiert in undefiniertem Verhalten und potenzieller Beschädigung des Zeigers `voidSecond`.
 * Dieser Testfall entspricht Test Case 231444 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/231444/versions/2.0.0
 */
void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad();

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um einen stackbasierten Buffer Overflow durch korrekte Nutzung von `memcpy` zu vermeiden.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `memcpy` kopiert nur die Größe des Zielpuffers (`sizeof(cv.charFirst)`).
 * - Der Zielpuffer wird explizit nullterminiert, um sicherzustellen, dass er ein gültiger String ist.
 * - Dies verhindert das Überschreiben von angrenzendem Speicher und stellt sicher, dass der Zeiger `voidSecond` intakt bleibt.
 * Dieser Testfall entspricht Test Case 231444 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/231444/versions/2.0.0
 */
void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good();

/*
 * @brief
 * Demonstriert eine heapbasierte Buffer-Overflow-Sicherheitslücke, die durch die fehlerhafte Nutzung von `strcpy` verursacht wird.
 * CWE: 122 Heapbasierter Buffer Overflow
 * Details:
 * - Die Funktion `strcpy` kopiert den Inhalt des Quellpuffers (`src`) in den Zielpuffer (`dest`).
 * - Wenn der Quellpuffer größer ist als der Zielpuffer, führt dies zu einem Überlauf und potenzieller Speicherbeschädigung.
 * Dieser Testfall entspricht Test Case 149083 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/149083/versions/2.0.0
 */
void CWE122_Heap_Based_Buffer_Overflow__strcpy9_bad(int argc, char** argv);

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um einen heapbasierten Buffer Overflow durch korrekte Nutzung von `strcpy` zu vermeiden.
 * CWE: 122 Heapbasierter Buffer Overflow
 * Details:
 * - Die Funktion `strcpy` wird verwendet, um einen String in einen Heap-Puffer zu kopieren.
 * - Der Aufrufer kürzt den String, um zu verhindern, dass ein Buffer Overflow auftritt.
 * - Der Zielpuffer wird mit einer Größe allokiert, die groß genug ist, um den Inhalt des Quellpuffers aufzunehmen.
 * - Dies stellt sicher, dass der Speicher korrekt verwaltet wird.
 * Dieser Testfall entspricht Test Case 149083 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/149084/versions/2.0.0
 */
void CWE122_Heap_Based_Buffer_Overflow__strcpy9_good(int argc, char** argv);

/*
 * @brief
 * Demonstriert eine Buffer-Underwrite-Sicherheitslücke, die durch die fehlerhafte Nutzung von wcsncpy verursacht wird.
 * CWE: 124 Buffer Underwrite
 * Details:
 *  - Es wird ein Puffer mit malloc allokiert und mit Daten beschrieben, aber der Zeiger wird vor dem Puffer gesetzt.
 *  - Die Funktion `wcsncpy` wird verwendet, um Daten in den Puffer zu kopieren.
 *  - Dies führt zu einem Buffer Underwrite, da der Zeiger auf einen ungültigen Speicherbereich zeigt und versucht wird, Daten in einen Bereich zu schreiben, der nicht dem Puffer gehört.
 *  Dieser Testfall entspricht Test Case 149083 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/234602/versions/2.0.0
 */
void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_bad();
/*
 * @brief
 * Demonstriert eine sichere Implementierung, um einen Buffer Underwrite durch korrekte Nutzung von wcsncpy zu vermeiden.
 * CWE: 124 Buffer Underwrite
 * Details:
 * - Ein Puffer wird mit malloc allokiert und mit Daten beschrieben.
 * - Der Zeiger wird korrekt auf den Anfang des Puffers gesetzt.
 * - Die Funktion `wcsncpy` wird verwendet, um Daten in den Puffer zu kopieren.
 * - Dies stellt sicher, dass der Puffer nicht unterlaufen wird und die Daten korrekt in den Puffer geschrieben werden.
 * Dieser Testfall entspricht Test Case 234602 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/234602/versions/2.0.0
 */
void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_good();

/*
 * @brief
 * Demonstriert eine stackbasierte Buffer-Overflow-Sicherheitslücke. Der Test simuliert das Lesen von Daten von einem Socket und erhält einen Index, welcher außerhalb des Puffers liegt.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `connect_socket_helper` wird verwendet, um Daten von einem Socket zu lesen.
 * - Der Index für den Puffer wird nicht ordnungsgemäß validiert, was zu einem Buffer Overflow führen kann.
 * Dieser Testfall entspricht Test Case 149083 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/62542/versions/1.0.0
 */
void CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_bad();

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um einen stackbasierten Buffer Overflow zu vermeiden. Der Test simuliert das Lesen von Daten von einem Socket und erhält einen Index, welcher innerhalb des Puffers liegt.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `connect_socket_helper` wird verwendet, um Daten von einem Socket zu lesen.
 * - Der Index für den Puffer wird ordnungsgemäß validiert, um sicherzustellen, dass er innerhalb der Grenzen des Puffers liegt.
 * Dieser Testfall entspricht Test Case 149083 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/62542/versions/1.0.0
 */
void CWE121_Stack_BasedCWE121_Stack_Based_Buffer_OverflowWE129_connect_socket_43_good();
/*
 * @brief
 * Demonstriert eine stackbasierte Buffer-Overflow-Sicherheitslücke, die durch die fehlerhafte Nutzung von `placement new` verursacht wird.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `placement new` wird verwendet, um ein Objekt in einem Puffer zu erstellen.
 * - Der Puffer wird zu klein initialisiert, was zu einem Buffer Overflow führt.
 * Dieser Testfall entspricht Test Case 67044 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/67044/versions/2.0.0
 */
void CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_bad();

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um einen stackbasierten Buffer Overflow durch korrekte Nutzung von `placement new` zu vermeiden.
 * CWE: 121 Stackbasierter Buffer Overflow
 * Details:
 * - Die Funktion `placement new` wird verwendet, um ein Objekt in einem Puffer zu erstellen.
 * - Der Puffer wird ordnungsgemäß dimensioniert, um sicherzustellen, dass er groß genug ist, um das Objekt aufzunehmen.
 * Dieser Testfall entspricht Test Case 67044 der im nist SARD-Repository gespeicherten Testfälle.
 * URL: https://samate.nist.gov/SARD/test-cases/67044/versions/2.0.0
 */
void CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_good();
