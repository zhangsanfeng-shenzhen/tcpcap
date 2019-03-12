#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "sqlite.h"
#include "sds.h"

int sql_insert(char *method, char* host ,uint32_t t)
{
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char sql[1024*10];

   rc = sqlite3_open("/tmp/test.db", &db);
   if( rc ){
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      exit(0);
   }
	strcpy(sql,"CREATE TABLE IF NOT EXISTS HTTP("  \
		 "TIME           TEXT    NOT NULL," \
         "METHOD         TEXT    NOT NULL," \
         "HOST           TEXT    NOT NULL);");
   rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
   fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }

	sds tv = sdsempty();
	tv = sdscatprintf(tv, "%u", t);
   sprintf(sql,"INSERT INTO HTTP (TIME,METHOD,HOST) "  \
         "VALUES ('%s', '%s', '%s');",(char *)tv,method,host);
   sdsfree(tv);

   rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   sqlite3_close(db);

   return 0;
}