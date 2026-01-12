#include "db.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    Db db;
    db_init(&db);

    // set/get/del basics
    {
        const uint8_t k[] = "a";
        const uint8_t v[] = "b";
        assert(db_set_str(&db, k, 1, v, 1));

        DbEntry *e = db_get(&db, k, 1);
        assert(e);
        assert(e->v.type == DB_V_STR);
        assert(e->v.as.str.len == 1);
        assert(memcmp(e->v.as.str.data, "b", 1) == 0);

        assert(db_del(&db, k, 1));
        assert(db_get(&db, k, 1) == NULL);

        assert(db_del(&db, (const uint8_t *)"missing", 7) == false);
    }

    // type mismatch: key already string => cannot create zset
    {
        const uint8_t k[] = "t";
        const uint8_t v[] = "x";
        assert(db_set_str(&db, k, 1, v, 1));

        ZSet *zs = NULL;
        DbZRes r = db_get_or_create_zset(&db, k, 1, &zs);
        assert(r == DBZ_TYPE);
        assert(zs == NULL);
    }

    db_destroy(&db);
    puts("db_test: OK");
    return 0;
}
