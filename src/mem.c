#include <stdlib.h>
void *wtf_malloc(size_t s) { return malloc(s); }
void  wtf_free(void *p)  { free(p); }
