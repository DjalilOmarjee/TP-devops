#define _GNU_SOURCE
#include "../include/my_secmalloc.private.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>

#define MAX_METADATA_COUNT 1000

typedef struct metadata_t {
    struct metadata_t *previous; // Pointeur vers la struct metadata précédente
    struct metadata_t *next;     // Pointeur vers la struct metadata suivante
    void *data_ptr;              // Pointeur vers les données dans le pool de données
    size_t size;                 // Taille des données
    bool free;                   // Indique si le bloc est libre ou non
    unsigned char canary[16];     // Stockage du canary pour la sécurité
    void *canary_ptr;
} metadata_t;

size_t pagesize;
void *metadatapool_ptr = NULL;
void *datapool_ptr = NULL;
metadata_t *first = NULL;
metadata_t *last = NULL;
size_t datapool_size = 0;
int metadata_count = 0;

void log_execution(const char *format, ...) {
    char *log_file = getenv("MSM_OUTPUT");
    if (!log_file) {
        perror("MSM_OUTPUT environment variable not set");
        return;
    }

    FILE *file = fopen(log_file, "a");
    if (!file) {
        perror("Failed to open log file");
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    fprintf(file, "\n");
    va_end(args);

    fclose(file);
}

void *allocate_new_metadata_pool() {
    log_execution("Initializing new datapools");
    size_t metadatapool_size = (sizeof(metadata_t) * MAX_METADATA_COUNT + pagesize - 1) & ~(pagesize - 1);
    void *new_metadatapool_ptr = mmap(NULL, metadatapool_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (new_metadatapool_ptr == MAP_FAILED) {
        perror("Failed to allocate new metadata pool");
        return NULL;
    }
    return new_metadatapool_ptr;
}

void *init_pools(size_t initial_datapool_size) {
    log_execution("Initializing memory pools with size %zu", initial_datapool_size);

    pagesize = sysconf(_SC_PAGE_SIZE);
    size_t metadatapool_size = (sizeof(metadata_t) * 1000 + pagesize - 1) & ~(pagesize - 1);

    metadatapool_ptr = mmap(NULL, metadatapool_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (metadatapool_ptr == MAP_FAILED) {
        perror("Failed to allocate metadata pool");
        exit(EXIT_FAILURE);
    }

    metadata_t *chunk_init = metadatapool_ptr;
    chunk_init->previous = NULL;
    chunk_init->next = NULL;
    chunk_init->free = true;

    datapool_ptr = (void *)(((uintptr_t)metadatapool_ptr + metadatapool_size + pagesize - 1) & ~(pagesize - 1));
    datapool_size = (initial_datapool_size + sizeof(chunk_init->canary) + pagesize - 1) & ~(pagesize - 1);
    datapool_ptr = mmap(datapool_ptr, datapool_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (datapool_ptr == MAP_FAILED) {
        perror("Failed to allocate data pool");
        exit(EXIT_FAILURE);
    }

    chunk_init->data_ptr = datapool_ptr;
    chunk_init->size = initial_datapool_size + sizeof(chunk_init->canary);

    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0 || read(fd, chunk_init->canary, sizeof(chunk_init->canary)) < 0) {
        perror("Failed to initialize canary");
        exit(EXIT_FAILURE);
    }
    close(fd);

    chunk_init->canary_ptr = (unsigned char *)((uintptr_t)chunk_init->data_ptr + chunk_init->size - sizeof(chunk_init->canary));
    memcpy(chunk_init->canary_ptr, chunk_init->canary, sizeof(chunk_init->canary));

    first = chunk_init;
    last = chunk_init;
    metadata_count = 1;

    size_t remaining_size = datapool_size - chunk_init->size;
    if (remaining_size > sizeof(metadata_t)) {
        metadata_t *remaining_chunk = (metadata_t *)((uintptr_t)metadatapool_ptr + sizeof(metadata_t));
        remaining_chunk->previous = chunk_init;
        remaining_chunk->next = NULL;
        remaining_chunk->data_ptr = (void *)((uintptr_t)datapool_ptr + chunk_init->size);
        remaining_chunk->size = remaining_size;

        remaining_chunk->free = true;

        fd = open("/dev/random", O_RDONLY);
        if (fd < 0 || read(fd, remaining_chunk->canary, sizeof(remaining_chunk->canary)) < 0) {
            perror("Failed to initialize canary");
            exit(EXIT_FAILURE);
        }
        close(fd);

        remaining_chunk->canary_ptr = (unsigned char *)((uintptr_t)remaining_chunk->data_ptr + remaining_chunk->size - sizeof(remaining_chunk->canary));
        memcpy(remaining_chunk->canary_ptr, remaining_chunk->canary, sizeof(remaining_chunk->canary));

        chunk_init->next = remaining_chunk;
        last = remaining_chunk;
        metadata_count++;
    }

    log_execution("Memory pools initialized successfully");
    return chunk_init->data_ptr;
}

void *my_malloc(size_t size) {
    if (size == 0) return NULL;
    if (metadatapool_ptr == NULL || datapool_ptr == NULL) init_pools(size);

    if (metadata_count >= MAX_METADATA_COUNT) {
        metadatapool_ptr = allocate_new_metadata_pool();
        if (metadatapool_ptr == NULL) {
            return NULL;
        }
        metadata_count = 0; // Reset metadata count for the new pool
    }

    metadata_t *meta_chunk = first;
    while (meta_chunk != NULL) {
        if (meta_chunk->free && meta_chunk->size >= size + sizeof(meta_chunk->canary)) {
            meta_chunk->free = false;

            // Reinitialize canary
            int fd = open("/dev/random", O_RDONLY);
            if (fd < 0 || read(fd, meta_chunk->canary, sizeof(meta_chunk->canary)) < 0) {
                perror("Failed to initialize canary");
                exit(EXIT_FAILURE);
            }
            close(fd);
            meta_chunk->canary_ptr = (unsigned char *)((uintptr_t)meta_chunk->data_ptr + meta_chunk->size - sizeof(meta_chunk->canary));
            memcpy(meta_chunk->canary_ptr, meta_chunk->canary, sizeof(meta_chunk->canary));

            log_execution("malloc: size=%zu, address=%p", size, meta_chunk->data_ptr);
            return meta_chunk->data_ptr;
        }
        meta_chunk = meta_chunk->next;
    }

    size_t new_size = (size + sizeof(first->canary)+ pagesize - 1) & ~(pagesize - 1);
    void *new_memory = mmap((void *)((uintptr_t)datapool_ptr + datapool_size), new_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (new_memory == MAP_FAILED) {
        perror("Failed to allocate more memory");
        return NULL;
    }
    void *new_address = (void *)((uintptr_t)datapool_ptr + datapool_size);
    datapool_size += new_size;

    metadata_t *new_meta = (metadata_t *)((uintptr_t)metadatapool_ptr + (sizeof(metadata_t) * metadata_count));
    metadata_count++;

    new_meta->previous = last;
    new_meta->next = NULL;
    new_meta->data_ptr = new_address;
    new_meta->size = new_size;
    new_meta->free = false;

    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0 || read(fd, new_meta->canary, sizeof(new_meta->canary)) < 0) {
        perror("Failed to initialize canary");
        exit(EXIT_FAILURE);
    }
    close(fd);

    new_meta->canary_ptr = (unsigned char *)((uintptr_t)new_meta->data_ptr + new_meta->size - sizeof(new_meta->canary));
    memcpy(new_meta->canary_ptr, new_meta->canary, sizeof(new_meta->canary));

    last->next = new_meta;
    last = new_meta;

    log_execution("malloc: size=%zu, address=%p", size, new_meta->data_ptr);
    return new_meta->data_ptr;
}

void my_free(void *ptr) {
    if (ptr == NULL) return;

    metadata_t *meta_chunk = first;

    while (meta_chunk != NULL) {
        if (meta_chunk->data_ptr == ptr) {
            if (memcmp(meta_chunk->canary, meta_chunk->canary_ptr, sizeof(meta_chunk->canary)) != 0) {
                log_execution("Canary alert: memory corruption detected at address=%p", ptr);
            }

            meta_chunk->free = true;
            log_execution("free: address=%p", ptr);
            if (meta_chunk->previous && meta_chunk->previous->free) {
                meta_chunk->previous->size += meta_chunk->size + sizeof(meta_chunk->canary);
                meta_chunk->previous->next = meta_chunk->next;
                if (meta_chunk->next) {
                    meta_chunk->next->previous = meta_chunk->previous;
                }
                meta_chunk->free = false;
            }
            if (meta_chunk->next && meta_chunk->next->free) {
                meta_chunk->size += meta_chunk->next->size + sizeof(meta_chunk->canary);
                meta_chunk->next = meta_chunk->next->next;
                if (meta_chunk->next) {
                    meta_chunk->next->previous = meta_chunk;
                }
            }
            return;
        }
        meta_chunk = meta_chunk->next;
    }
}

void *my_calloc(size_t nmemb, size_t size) {
    if (size == 0 || nmemb == 0) return NULL;
    size_t total_size = nmemb * size;
    void *ptr = my_malloc(total_size);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    log_execution("calloc: nmemb=%zu, size=%zu, address=%p", nmemb, size, ptr);
    return ptr;
}

void *my_realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        // Si ptr est NULL, allouer un nouveau bloc de mémoire
        void *new_ptr = my_malloc(size);
        log_execution("realloc: old_address=NULL, new_size=%zu, new_address=%p", size, new_ptr);
        return new_ptr;
    }
    if (size == 0) {
        // Si size est 0, libérer la mémoire et retourner NULL
        log_execution("realloc: old_address=%p, new_size=0, new_address=NULL", ptr);
        my_free(ptr);
        return NULL;
    }

    // Rechercher le bloc de métadonnées correspondant à ptr
    metadata_t *meta_chunk = first;
    while (meta_chunk != NULL && meta_chunk->data_ptr != ptr) {
        meta_chunk = meta_chunk->next;
    }

    // Si le bloc de métadonnées n'est pas trouvé
    if (meta_chunk == NULL) {
        log_execution("realloc: old_address=%p not found", ptr);
        return NULL;
    }
    // Si le bloc actuel est suffisamment grand pour contenir la nouvelle taille
    if (meta_chunk->size + meta_chunk->next->size >= size + sizeof(meta_chunk->canary)) {
        
        meta_chunk->size += size - meta_chunk->size + sizeof(meta_chunk->canary);
        meta_chunk->next->data_ptr = (void *)((uintptr_t)meta_chunk->data_ptr + meta_chunk->size);
        
        log_execution("realloc: old_address=%p, new_size=%zu, new_address=%p", ptr, size, ptr);
        return ptr;
    } else {
    // //verifier que le bloc suivant est libre est et de taille assez grande 
    // if (meta_chunk->next && meta_chunk->next->free && 
    //     meta_chunk->next->size + meta_chunk->size >= size + sizeof(meta_chunk->canary)) {
    //     metadata_t *next_chunk = meta_chunk->next;
    //     // Fusionner les deux blocs
    //     meta_chunk->size += next_chunk->size + sizeof(meta_chunk->canary);
    //     meta_chunk->next = next_chunk->next;
    //     if (next_chunk->next) {
    //         next_chunk->next->previous = meta_chunk;
    //     }
        
    //     // Mettre à jour les canaries
    //     int fd = open("/dev/random", O_RDONLY);
    //     if (fd < 0 || read(fd, meta_chunk->canary, sizeof(meta_chunk->canary)) < 0) {
    //         perror("Failed to initialize canary");
    //         exit(EXIT_FAILURE);
    //     }
    //     close(fd);
    //     meta_chunk->canary_ptr = (unsigned char *)((uintptr_t)meta_chunk->data_ptr + meta_chunk->size - sizeof(meta_chunk->canary));
    //     memcpy(meta_chunk->canary_ptr, meta_chunk->canary, sizeof(meta_chunk->canary));

    //     // Ajuster l'adresse de début de la suivante
    //     if (meta_chunk->next) {
    //         next_chunk = meta_chunk->next;
    //         next_chunk->data_ptr = (unsigned char *)((uintptr_t)meta_chunk->data_ptr + meta_chunk->size - sizeof(meta_chunk->canary));
    //         next_chunk->canary_ptr = (unsigned char *)((uintptr_t)next_chunk->data_ptr + next_chunk->size - sizeof(next_chunk->canary));
    //     }

    //     log_execution("realloc: old_address=%p, new_size=%zu, merged with next free block, address=%p", ptr, size, meta_chunk->data_ptr);
    //     return meta_chunk->data_ptr;
    
    // } else {
        // Si le bloc actuel n'est pas assez grand, allouer un nouveau bloc
        void *new_ptr = my_malloc(size);
        if (new_ptr) {
            // Copier les données de l'ancien bloc vers le nouveau
            memcpy(new_ptr, ptr, meta_chunk->size - sizeof(meta_chunk->canary));
            // Libérer l'ancien bloc
            my_free(ptr);
        }
        log_execution("realloc: old_address=%p, new_size=%zu, new_address=%p", ptr, size, new_ptr);
        return new_ptr;
    }
}

#ifdef DYNAMIC
void *malloc(size_t size) {
    return my_malloc(size);
}
void free(void *ptr) {
    my_free(ptr);
}
void *calloc(size_t nmemb, size_t size) {
    return my_calloc(nmemb, size);
}
void *realloc(void *ptr, size_t size) {
    return my_realloc(ptr);
}
#endif