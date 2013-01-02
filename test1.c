#include <dlfcn.h>


int main()
{
    void *bla;
    bla = dlopen("./libsegfault.so",RTLD_LAZY);
    return 0;
}
