

// #include <assert.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// #include "ss.h"
// #include "ssconf.h"

// int main(int argc, char const *argv[]) {
//     assert(argc >= 2);
//     assert(argv[1]);
//     const char *file = argv[1];
//     ssconf_t *cf = ssconf_init(100, 100);
//     assert(cf);
//     int rt = ssconf_load(cf, file);
//     assert(rt == _OK);
//     for (int i = 0; i < cf->items_cnt; i++) {
//         printf("%s:%s\n", cf->items[i]->key, cf->items[i]->value);
//     }
//     ssconf_free(cf);
//     return 0;
// }