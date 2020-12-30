#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#define malloc mm_malloc
#define free mm_free
/* Function pointers to hw3 functions */
void* (*mm_malloc)(size_t);
void* (*mm_realloc)(void*, size_t);
void (*mm_free)(void*);

void load_alloc_functions() {
    void *handle = dlopen("hw3lib.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    char* error;
    mm_malloc = dlsym(handle, "mm_malloc");
    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    mm_realloc = dlsym(handle, "mm_realloc");
    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    mm_free = dlsym(handle, "mm_free");
    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }
}

int main() {
    load_alloc_functions();

    int *data = (int*) mm_malloc(sizeof(int));
    int *data2 = (int*) mm_malloc(sizeof(int)*2);
    int *data3 = (int*) mm_malloc(sizeof(int));
    int *data4 = (int*) mm_malloc(sizeof(int));
    mm_free(data);
    mm_free(data2);
    data = (int*) mm_malloc(8);
    data[0] =6;
    data[1] = 5;
    mm_free(data4);
    printf("malloc test successful! %d %d\n", data[0], data[1]);
    mm_free(data);
    mm_free(data3);
    int* p = mm_malloc(5 * sizeof(int));
    int i;
    for(i = 0; i < 5; i++){
        p[i] = i;
    }
    for(i = 0; i < 5; i++){
        printf("address: %p, value: %d\n", p + i, p[i]);
    }
	mm_free(p);
    p = mm_malloc(1);
    mm_free(p);

    printf("p has been freed\n");
    p = malloc(sizeof(int));
    *((int*)p) = 5;
    printf("integer: address: %p, value: %d\n", p, *((int*)p));
    free(p);
    char* c = "Hello World"; 
    p = malloc(sizeof(char) * (strlen(c) + 1));
    memcpy(p, c, strlen(c));
    printf("String: address: %p, value: %s\n", p, (char*)p);
    free(p);
    p = malloc(sizeof(float));
    *((float*)p) = 1.2345;
    printf("float: address: %p, value: %f\n", p, *((float*)p));
    free(p);

    // for(i = 1; (p = malloc(i)) != NULL; i*=2){
    //     printf("%d bytes allocated\n", i);
    //     free(p);
    // }

    return 0;
}
