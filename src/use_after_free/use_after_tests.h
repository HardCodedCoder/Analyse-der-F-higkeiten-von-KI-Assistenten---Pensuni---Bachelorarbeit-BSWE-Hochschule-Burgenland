/*
 * @brief
 * Demonstriert eine Use-After-Free-Sicherheitsl�cke, die durch die Nutzung eines bereits freigegebenen Heap-Puffers entsteht.
 * CWE: 416 Use After Free
 * Details:
 * - Ein Puffer wird mit malloc allokiert und mit Daten beschrieben.
 * - Der Puffer wird mit free freigegeben.
 * - Nach dem Free-Vorgang wird weiterhin auf den Speicherbereich zugegriffen, was zu undefiniertem Verhalten f�hren kann.
 * - Dies kann zu Programmabst�rzen, Datenkorruption oder Sicherheitsl�cken f�hren.
 * Dieser Testfall entspricht Test Case 240375 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/240375/versions/2.0.0
 */
void CWE416_Use_After_Free__malloc_free_wchar_t_13_bad();

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um eine Use-After-Free-Sicherheitsl�cke zu vermeiden.
 * CWE: 416 Use After Free
 * Details:
 * - Ein Puffer wird mit malloc allokiert und mit Daten beschrieben.
 * - Der Puffer wird entweder nicht vor der weiteren Nutzung freigegeben oder es wird sichergestellt, dass nach dem Free kein Zugriff mehr erfolgt.
 * - Dadurch wird verhindert, dass auf bereits freigegebenen Speicher zugegriffen wird.
 * Dieser Testfall entspricht Test Case 240375 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/240375/versions/2.0.0
 */
void CWE416_Use_After_Free__malloc_free_wchar_t_13_good();

/*
 * @brief
 * Demonstriert eine Use-After-Free-Sicherheitsl�cke, die durch die Nutzung eines bereits freigegebenen Heap-Puffers entsteht.
 * CWE: 416 Use After Free
 * Details:
 * - Ein Puffer wird mit malloc allokiert und mit Daten beschrieben.
 * - Der Puffer wird mit free freigegeben.
 * - Nach dem Free-Vorgang wird weiterhin auf den Speicherbereich zugegriffen, was zu undefiniertem Verhalten f�hren kann.
 * - Dies kann zu Programmabst�rzen, Datenkorruption oder Sicherheitsl�cken f�hren.
 * - Der gute Testfall (good und bad werden hier in einem Testfall zusammengefasst) l�scht den Speicher nicht mehr, was aber zu einem Memory Leak f�hrt.
 * Dieser Testfall entspricht Test Case 240322 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/240322/versions/2.0.0
 */
void CWE416_Use_After_Free__malloc_free_long_15_mixed(bool good = false);

/*
 * @brief
 * Demonstriert eine Use-After-Free-Sicherheitsl�cke, die durch fehlerhafte Implementierung des Zuweisungsoperators (`operator=`) entsteht.
 * CWE: 416 Use After Free
 * Details:
 * - Die Klasse `BadClass` implementiert einen Zuweisungsoperator ohne �berpr�fung auf Selbstzuweisung.
 * - Bei einer Selbstzuweisung (`obj = obj`) wird der Speicher von `name` freigegeben und anschlie�end versucht, auf denselben Speicherbereich zuzugreifen.
 * - Dies f�hrt zu einem Zugriff auf bereits freigegebenen Speicher (Use-After-Free), was zu undefiniertem Verhalten f�hren kann.
 * - Der Testfall demonstriert dieses Verhalten explizit durch die Anweisung `badClassObject = badClassObject;`.
 * Dieser Testfall entspricht Test Case 102645 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/102645/versions/1.0.0
 */
void CWE416_Use_After_Free__operator_equals_01_bad();

/*
 * @brief
 * Demonstriert eine sichere Implementierung, um eine Use-After-Free-Sicherheitsl�cke zu vermeiden.
 * CWE: 416 Use After Free
 * Details:
 * - Die Klasse `GoodClass` implementiert einen Zuweisungsoperator, der auf Selbstzuweisung �berpr�ft.
 * - Bei einer Selbstzuweisung (`obj = obj`) wird der Speicher von `name` nicht freigegeben, was zu einem sicheren Verhalten f�hrt.
 * - Dadurch wird verhindert, dass auf bereits freigegebenen Speicher zugegriffen wird.
 * Dieser Testfall entspricht Test Case 102645 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/102645/versions/1.0.0
 */
void CWE416_Use_After_Free__operator_equals_01_good();

/*
 * @brief
 * Demonstriert eine Use-After-Free-Sicherheitsl�cke, die durch das Zur�ckgeben eines bereits freigegebenen Zeigers entsteht.
 * CWE: 416 Use After Free
 * Details:
 * - Die Hilfsfunktion `helperBad` allokiert einen Puffer, f�llt ihn mit einer umgekehrten Zeichenkette, gibt den Speicher mit `free` frei und gibt anschlie�end den Zeiger auf den freigegebenen Speicher zur�ck.
 * - Im Testfall wird dieser Zeiger weiterverwendet, was zu undefiniertem Verhalten f�hren kann (z.B. Programmabsturz, Datenkorruption, Sicherheitsl�cke).
 * - Die sichere Variante (`helperGood`) gibt den Speicher nicht vor dem R�ckgabewert frei und vermeidet so das Problem, verursacht aber ein Memory Leak, wenn der Aufrufer nicht selbst `free` aufruft.
 * - Der Parameter `good` steuert, ob die unsichere (`false`) oder sichere (`true`) Variante ausgef�hrt wird.
 * Beispielaufruf: `CWE416_Use_After_Free__return_freed_ptr_mixed(false);`
 * Dieser Testfall entspricht Test Case 102524 der im nist SARD-Repository gespeicherten Testf�lle.
 * URL: https://samate.nist.gov/SARD/test-cases/102524/versions/1.0.0
 */
void CWE416_Use_After_Free__return_freed_ptr_mixed(bool good = false);

/*
 * @brief
 * Demonstriert eine Use-After-Free-Sicherheitsl�cke durch Zugriff auf ein bereits freigegebenes Objekt.
 * CWE: 416 Use After Free
 * Details:
 * - Das Objekt `data` wird dynamisch mit `new` alloziert.
 * - Abh�ngig vom R�ckgabewert von `globalReturnsTrueOrFalse()` wird es m�glicherweise sofort mit `delete` freigegeben.
 * - In einem zweiten Zweig erfolgt erneut eine Entscheidung mittels `globalReturnsTrueOrFalse()`, ob auf `data` zugegriffen wird.
 * - Falls `data` zuvor gel�scht wurde, kommt es dabei zu einem Zugriff auf bereits freigegebenen Speicher.
 * - Das Verhalten ist nicht deterministisch: Der Fehler tritt nur bei einer bestimmten Pfadkombination auf.
 * Beispielaufruf: `CWE416_Use_After_Free__new_delete_class_bad();`
 * URL: https://samate.nist.gov/SARD/test-cases/102524/versions/1.0.0
 */
void CWE416_Use_After_Free__new_delete_class_bad();

/*
 * @brief
 * Sichere Variante des Testfalls zu CWE-416 (Use After Free), bei der auf gel�schten Speicher nicht mehr zugegriffen wird.
 * CWE: 416 Use After Free
 * Details:
 * - Das Objekt `data` wird wie in der fehlerhaften Variante mit `new` alloziert und anschlie�end mit `delete` freigegeben.
 * - Unabh�ngig vom Kontrollfluss erfolgt **kein Zugriff** mehr auf das Objekt nach dem L�schen.
 * - Dadurch wird ein Use-After-Free sicher vermieden.
 * - Die Funktion enth�lt jedoch potenzielle Memory Leaks, falls `delete` nicht aufgerufen wird.
 * - Diese Variante demonstriert die korrekte Trennung von Speicherfreigabe und sp�terer Nutzung.
 * Beispielaufruf: `CWE416_Use_After_Free__new_delete_class_good();`
 * URL: https://samate.nist.gov/SARD/test-cases/102524/versions/1.0.0
 */
void CWE416_Use_After_Free__new_delete_class_good();
