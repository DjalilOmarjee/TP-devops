#include <criterion/criterion.h>
#include <stdio.h>
#include "../include/my_secmalloc.private.h"
#include <sys/mman.h>
#include <stdint.h>

// Fonction auxiliaire pour initialiser les données dans la mémoire allouée pour les tests
void fill_data(int *ptr, int size) {
    for (int i = 0; i < size; i++) {
        ptr[i] = i;
    }
}

// Fonction auxiliaire pour vérifier l'intégrité des données dans la mémoire allouée
void check_data(int *ptr, int size) {
    for (int i = 0; i < size; i++) {
        cr_expect(ptr[i] == i, "Corruption des données à l'index %d : attendu %d, obtenu %d", i, i, ptr[i]);
    }
}

// Test pour une allocation mémoire simple
Test(secmalloc, simple_malloc) {
    int size = 5000;
    int *ptr = (int *)my_malloc(size);

    // Valider l'allocation mémoire et l'intégrité des données
    cr_expect_not_null(ptr, "Allocation échouée!");
    fill_data(ptr, size);
    check_data(ptr, size);
}

// Test pour des allocations consécutives sans chevauchement

Test(secmalloc, double_malloc) {
    int size = 1000;

    // Allouer et valider le premier bloc
    int *ptr1 = (int *)my_malloc(size);
    fill_data(ptr1, size);
    cr_expect_not_null(ptr1, "Première allocation échouée!");

    // Allouer et valider le deuxième bloc
    int *ptr2 = (int *)my_malloc(500);
    fill_data(ptr2, size);
    cr_expect_not_null(ptr2, "Deuxième allocation échouée!");

    // Assurer qu'il n'y a pas de chevauchement entre les allocations consécutives
    cr_expect((uintptr_t)ptr2 > (uintptr_t)ptr1 + size, "Chevauchement détecté entre les allocations!");
}

// Test pour des allocations de tailles aléatoires multiples
Test(secmalloc, multiple_malloc) {
    int num_allocs = 1165; 
    void **pointers = malloc(num_allocs * sizeof(void *));
    cr_expect_not_null(pointers, "Échec de l'allocation du tableau de pointeurs");

    for (int i = 0; i < num_allocs; i++) {
        size_t size = (rand() % 10002) + 1;  // Taille aléatoire entre 1 et 10002
        pointers[i] = my_malloc(size);
        cr_expect_not_null(pointers[i], "Allocation %d échouée", i);
    }

    free(pointers);
}

// Tests pour la fonctionnalité de realloc
Test(secmalloc, realloc_basic) {
    // Allocation initiale et remplissage des données
    int initial_size = 10;
    int *ptr = (int *)my_malloc(initial_size * sizeof(int));
    fill_data(ptr, initial_size);

    // Réallocation à une taille plus grande et vérification de l'intégrité
    int new_size = 20;
    int *new_ptr = (int *)my_realloc(ptr, new_size * sizeof(int));
    cr_expect_not_null(new_ptr, "realloc a retourné NULL");
    check_data(new_ptr, initial_size);  // Seules les données initiales peuvent être vérifiées pour l'intégrité

    my_free(new_ptr);  // Nettoyage
}

// Test pour realloc avec réduction de la taille
Test(secmalloc, realloc_reduce) {
    // Allocation initiale et remplissage des données
    int initial_size = 10;
    int *ptr = (int *)my_malloc(initial_size * sizeof(int));
    fill_data(ptr, initial_size);

    // Réallocation à une taille plus petite et vérification de l'intégrité des données
    int reduced_size = 5;
    int *new_ptr = (int *)my_realloc(ptr, reduced_size * sizeof(int));
    cr_expect_not_null(new_ptr, "realloc a retourné NULL");
    check_data(new_ptr, reduced_size);  // Vérifiez uniquement jusqu'à la taille réduite

    my_free(new_ptr);  // Nettoyage
}
// Test pour vérifier le merge avec un bloc libre qui suit
Test(secmalloc, realloc_merge_with_free_block) {
    // Allocation initiale
    size_t initial_size = 10;
    int *ptr = (int *)my_malloc(initial_size * sizeof(int));
    cr_expect_not_null(ptr, "my_malloc a échoué pour size=%zu", initial_size);
    fill_data(ptr, initial_size);

    // Allouer un deuxième bloc pour garantir qu'il existe un bloc suivant
    size_t second_block_size = 20;
    int *second_ptr = (int *)my_malloc(second_block_size * sizeof(int));
    cr_expect_not_null(second_ptr, "my_malloc a échoué pour le second bloc de size=%zu", second_block_size);

    // Libérer le deuxième bloc pour qu'il soit disponible pour la fusion
    my_free(second_ptr);

    // Réallocation à une taille qui devrait fusionner avec le bloc libre suivant
    size_t new_size = initial_size + second_block_size / 2;
    int *new_ptr = (int *)my_realloc(ptr, new_size * sizeof(int));
    cr_expect_not_null(new_ptr, "my_realloc a échoué pour size=%zu", new_size);

    // Vérifier que les données initiales sont toujours intègres
    check_data(new_ptr, initial_size);

    // Nettoyage
    my_free(new_ptr);
}

Test(my_calloc, basic_allocation) {
    // Test de my_calloc
    size_t nmemb = 10;
    size_t size = 20;
    void *ptr = my_calloc(nmemb, size);

    cr_assert_not_null(ptr, "Allocation my_calloc a échoué");
    for (size_t i = 0; i < nmemb * size; i++) {
        cr_assert(((char *)ptr)[i] == 0, "La mémoire allouée par my_calloc n'est pas initialisée à zéro");
    }

    my_free(ptr);
}

Test(my_calloc, zero_allocation) {
    void *ptr = my_calloc(0, 10);
    cr_assert_null(ptr, "my_calloc avec nmemb=0 devrait retourner NULL");

    ptr = my_calloc(10, 0);
    cr_assert_null(ptr, "my_calloc avec size=0 devrait retourner NULL");
}

Test(my_calloc, large_allocation) {
    size_t nmemb = 1024;
    size_t size = 1024;
    void *ptr = my_calloc(nmemb, size);

    cr_assert_not_null(ptr, "Allocation large my_calloc a échoué");
    for (size_t i = 0; i < nmemb * size; i++) {
        cr_assert(((char *)ptr)[i] == 0, "La mémoire allouée par my_calloc n'est pas initialisée à zéro");
    }

    my_free(ptr);
}

Test(my_free, canary_check) {
    size_t size = 100;
    void *ptr = my_malloc(size);
    cr_assert_not_null(ptr, "my_malloc a échoué pour size=%zu", size);

    fill_data(ptr, 101);
   
    // Libérer la mémoire et vérifier les logs
    my_free(ptr);

    // Lire les logs pour vérifier l'alerte canary
    FILE *file = fopen("execution_log.txt", "r");
    cr_assert_not_null(file, "Impossible d'ouvrir le fichier de log");

    char line[256];
    bool found_alert = false;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "Canary alert")) {
            found_alert = true;
            break;
        }
    }
    fclose(file);

    cr_assert(found_alert, "L'alerte de corruption du canary n'a pas été trouvée dans les logs");
}

Test(my_secmalloc, test_my_free) {
    void *ptr = my_malloc(100);
    cr_assert_not_null(ptr, "my_malloc(100) failed");

    my_free(ptr);

    // No specific assertion for free, as it is hard to check
    // but we can check for segmentation faults or errors
}

Test(my_secmalloc, test_my_calloc) {
    void *ptr = my_calloc(10, 20);
    cr_assert_not_null(ptr, "my_calloc(10, 20) failed");

    for (size_t i = 0; i < 200; i++) {
        cr_assert(((char *)ptr)[i] == 0, "my_calloc did not zero-initialize memory at index %zu", i);
    }

    my_free(ptr);
}

Test(my_secmalloc, test_my_realloc) {
    void *ptr = my_malloc(100);
    cr_assert_not_null(ptr, "my_malloc(100) failed");

    void *new_ptr = my_realloc(ptr, 200);
    cr_assert_not_null(new_ptr, "my_realloc(ptr, 200) failed");

    my_free(new_ptr);
}

Test(my_secmalloc, test_my_malloc) {
    void *ptr1 = my_malloc(100);
    printf("%p",ptr1);
    cr_assert_not_null(ptr1, "my_malloc(100) failed");

    void *ptr2 = my_malloc(200);
    cr_assert_not_null(ptr2, "my_malloc(200) failed");

    my_free(ptr1);
    my_free(ptr2);
}

