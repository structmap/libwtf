#include <stdlib.h>
static void *wtf_malloc(size_t s) { return malloc(s); }
static void  wtf_free(void *p)  { free(p); }
