/* Database handling routines with PostgreSQL support.
 *
 * Services is copyright (c) 1996-1999 Andy Church.
 *     E-mail: <achurch@dragonfire.net>
 * This program is free but copyrighted software; see the file COPYING for
 * details.
 *
 * DarkuBots es una adaptación de Javier Fernández Viña, ZipBreake.
 * E-Mail: javier@jfv.es || Web: http://jfv.es/
 * 
 * PostgreSQL support added on April 21, 2025 by reverse
 *
 */

#include "services.h"
#include "datafiles.h"
#include <fcntl.h>
#include <libpq-fe.h>

/*************************************************************************/
/************************* DATABASE CONFIGURATION ************************/
/*************************************************************************/

/* PostgreSQL connection parameters - could be moved to config.c */
static char *DB_Host = "localhost";
static char *DB_Port = "5432";
static char *DB_Name = "darkubots";
static char *DB_User = "darkubots";
static char *DB_Pass = "secure_password_here"; /* TODO: Move this to a secure config */

/* Global PostgreSQL connection handle */
static PGconn *pg_conn = NULL;

/* Initialize database connection */
int db_init(void) 
{
    char conninfo[512];
    
    snprintf(conninfo, sizeof(conninfo), 
             "host=%s port=%s dbname=%s user=%s password=%s",
             DB_Host, DB_Port, DB_Name, DB_User, DB_Pass);
    
    pg_conn = PQconnectdb(conninfo);
    
    if (PQstatus(pg_conn) != CONNECTION_OK) {
#ifndef NOT_MAIN
        log("Failed to connect to PostgreSQL database: %s", 
            PQerrorMessage(pg_conn));
#endif
        PQfinish(pg_conn);
        pg_conn = NULL;
        return 0;
    }
    
    /* Start a transaction - we'll use this for all database operations */
    PGresult *res = PQexec(pg_conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
#ifndef NOT_MAIN
        log("Error starting transaction: %s", PQerrorMessage(pg_conn));
#endif
        PQclear(res);
        PQfinish(pg_conn);
        pg_conn = NULL;
        return 0;
    }
    PQclear(res);
    
#ifndef NOT_MAIN
    log("Connected to PostgreSQL database: %s", DB_Name);
#endif
    return 1;
}

/* Close database connection */
void db_cleanup(void)
{
    if (pg_conn != NULL) {
        /* Commit any pending changes before closing */
        PGresult *res = PQexec(pg_conn, "COMMIT");
        PQclear(res);
        
        PQfinish(pg_conn);
        pg_conn = NULL;
#ifndef NOT_MAIN
        log("PostgreSQL database connection closed");
#endif
    }
}

/*************************************************************************/
/*************************************************************************/

/* Return the version number on the file or database.
 * Return 0 if there is no version number or the number doesn't make sense 
 * (i.e. less than 1 or greater than FILE_VERSION).
 */

int get_file_version(dbFILE *f)
{
    int version = 0;
    PGresult *res;
    char query[256];
    
    if (f->mode == 'r') {
        /* Query the version from the versions table */
        snprintf(query, sizeof(query),
                 "SELECT version FROM versions WHERE filename = '%s'",
                 f->filename);
        
        res = PQexec(pg_conn, query);
        
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
#ifndef NOT_MAIN
            log("Error retrieving version for %s: %s", 
                f->filename, PQerrorMessage(pg_conn));
#endif
            PQclear(res);
            return 0;
        }
        
        /* Check if we got a result */
        if (PQntuples(res) > 0) {
            version = atoi(PQgetvalue(res, 0, 0));
        } else {
#ifndef NOT_MAIN
            log("No version found for %s", f->filename);
#endif
            version = 0;
        }
        
        PQclear(res);
        
        if (version > FILE_VERSION || version < 1) {
#ifndef NOT_MAIN
            log("Invalid version number (%d) for %s", version, f->filename);
#endif
            return 0;
        }
    }
    
    return version;
}

/*************************************************************************/

/* Write the current version number to the database.
 * Return 0 on error, 1 on success.
 */

int write_file_version(dbFILE *f)
{
    PGresult *res;
    char query[512];
    
    /* Create versions table if it doesn't exist */
    res = PQexec(pg_conn, 
          "CREATE TABLE IF NOT EXISTS versions ("
          "    filename VARCHAR(255) PRIMARY KEY,"
          "    version INTEGER NOT NULL,"
          "    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
          ")");
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
#ifndef NOT_MAIN
        log("Error creating versions table: %s", PQerrorMessage(pg_conn));
#endif
        PQclear(res);
        return 0;
    }
    PQclear(res);
    
    /* Update or insert version record */
    snprintf(query, sizeof(query),
             "INSERT INTO versions (filename, version) VALUES ('%s', %d) "
             "ON CONFLICT (filename) DO UPDATE SET version = %d, "
             "last_modified = CURRENT_TIMESTAMP",
             f->filename, FILE_VERSION, FILE_VERSION);
    
    res = PQexec(pg_conn, query);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
#ifndef NOT_MAIN
        log("Error writing version number for %s: %s", 
            f->filename, PQerrorMessage(pg_conn));
#endif
        PQclear(res);
        return 0;
    }
    
    PQclear(res);
    return 1;
}

/*************************************************************************/
/*************************************************************************/

/* Structure to hold binary data for PostgreSQL */
typedef struct {
    char *data;      /* Binary data buffer */
    size_t size;     /* Current size of data */
    size_t alloc;    /* Allocated size of buffer */
} BinaryBuffer;

/* Initialize a binary buffer */
static void init_binary_buffer(BinaryBuffer *buf)
{
    buf->data = NULL;
    buf->size = 0;
    buf->alloc = 0;
}

/* Append data to a binary buffer */
static int append_binary_buffer(BinaryBuffer *buf, const void *data, size_t size)
{
    /* Allocate or expand buffer if needed */
    if (buf->size + size > buf->alloc) {
        size_t new_size = buf->alloc ? buf->alloc * 2 : 8192;
        while (new_size < buf->size + size)
            new_size *= 2;
        
        char *new_data = realloc(buf->data, new_size);
        if (!new_data)
            return 0;
        
        buf->data = new_data;
        buf->alloc = new_size;
    }
    
    /* Copy data to buffer */
    memcpy(buf->data + buf->size, data, size);
    buf->size += size;
    
    return 1;
}

/* Free a binary buffer */
static void free_binary_buffer(BinaryBuffer *buf)
{
    if (buf->data) {
        free(buf->data);
    }
    buf->data = NULL;
    buf->size = 0;
    buf->alloc = 0;
}

/*************************************************************************/

static dbFILE *open_db_read(const char *service, const char *filename)
{
    dbFILE *f;
    PGresult *res;
    char query[512];

    /* Ensure we have a database connection */
    if (!pg_conn && !db_init()) {
#ifndef NOT_MAIN
        log_perror("Cannot connect to database for reading %s database %s", 
                   service, filename);
#endif
        return NULL;
    }

    f = malloc(sizeof(*f));
    if (!f) {
#ifndef NOT_MAIN
        log_perror("Can't allocate memory for %s database %s", service, filename);
#endif
        return NULL;
    }
    
    strscpy(f->filename, filename, sizeof(f->filename));
    f->mode = 'r';
    f->pg_binary = malloc(sizeof(BinaryBuffer));
    
    if (!f->pg_binary) {
#ifndef NOT_MAIN
        log_perror("Can't allocate memory for binary buffer for %s database %s", 
                   service, filename);
#endif
        free(f);
        return NULL;
    }
    
    init_binary_buffer(f->pg_binary);
    
    /* Check if the data exists in the database */
    snprintf(query, sizeof(query), 
             "SELECT data FROM dbfiles WHERE filename = '%s'", filename);
    
    res = PQexec(pg_conn, query);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
#ifndef NOT_MAIN
        log("Database error when reading %s database %s: %s", 
            service, filename, PQerrorMessage(pg_conn));
#endif
        free(f->pg_binary);
        free(f);
        PQclear(res);
        return NULL;
    }
    
    /* Check if we found data */
    if (PQntuples(res) == 0) {
        /* No data found - this is not necessarily an error */
#ifndef NOT_MAIN
        if (debug)
            log("Database file %s not found", filename);
#endif
        free(f->pg_binary);
        free(f);
        PQclear(res);
        errno = ENOENT;
        return NULL;
    }
    
    /* Get the binary data */
    size_t data_size = PQgetlength(res, 0, 0);
    const unsigned char *data_ptr = (const unsigned char *)PQgetvalue(res, 0, 0);
    
    /* Store the data in our buffer */
    if (!append_binary_buffer(f->pg_binary, data_ptr, data_size)) {
#ifndef NOT_MAIN
        log_perror("Can't allocate memory for data buffer for %s database %s", 
                   service, filename);
#endif
        free(f->pg_binary);
        free(f);
        PQclear(res);
        return NULL;
    }
    
    /* Set up the memory buffer as a FILE* for compatibility with old code */
    f->fp = fmemopen(f->pg_binary->data, f->pg_binary->size, "rb");
    if (!f->fp) {
#ifndef NOT_MAIN
        log_perror("Can't create memory stream for %s database %s", 
                   service, filename);
#endif
        free_binary_buffer(f->pg_binary);
        free(f->pg_binary);
        free(f);
        PQclear(res);
        return NULL;
    }
    
    f->backupfp = NULL;
    *f->backupname = 0;
    
    PQclear(res);
    return f;
}

/*************************************************************************/

static dbFILE *open_db_write(const char *service, const char *filename)
{
    dbFILE *f;
    PGresult *res;
    
    /* Ensure we have a database connection */
    if (!pg_conn && !db_init()) {
#ifndef NOT_MAIN
        log_perror("Cannot connect to database for writing %s database %s", 
                   service, filename);
#endif
        return NULL;
    }
    
    /* First, create the dbfiles table if it doesn't exist */
    res = PQexec(pg_conn, 
          "CREATE TABLE IF NOT EXISTS dbfiles ("
          "    filename VARCHAR(255) PRIMARY KEY,"
          "    data BYTEA NOT NULL,"
          "    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
          ")");
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
#ifndef NOT_MAIN
        log("Error creating dbfiles table: %s", PQerrorMessage(pg_conn));
#endif
        PQclear(res);
        return NULL;
    }
    PQclear(res);
    
    f = malloc(sizeof(*f));
    if (!f) {
#ifndef NOT_MAIN
        log_perror("Can't allocate memory for %s database %s", service, filename);
#endif
        return NULL;
    }
    
    strscpy(f->filename, filename, sizeof(f->filename));
    f->mode = 'w';
    
    /* Allocate a binary buffer to store data for later writing to the database */
    f->pg_binary = malloc(sizeof(BinaryBuffer));
    if (!f->pg_binary) {
#ifndef NOT_MAIN
        log_perror("Can't allocate memory for binary buffer for %s database %s", 
                   service, filename);
#endif
        free(f);
        return NULL;
    }
    
    init_binary_buffer(f->pg_binary);
    
    /* Create a temporary file for writing */
    f->fp = tmpfile();
    if (!f->fp) {
#ifndef NOT_MAIN
        log_perror("Can't create temporary file for %s database %s", 
                   service, filename);
#endif
        free(f->pg_binary);
        free(f);
        return NULL;
    }
    
    /* No need for backup handling - PostgreSQL handles this better */
    *f->backupname = 0;
    f->backupfp = NULL;
    
    /* Write the version number */
    if (!write_file_version(f)) {
#ifndef NOT_MAIN
        log_perror("Can't write version to %s database %s", service, filename);
#endif
        fclose(f->fp);
        free(f->pg_binary);
        free(f);
        return NULL;
    }
    
    return f;
}

/*************************************************************************/

/* Open a database connection for reading (*mode == 'r') or writing (*mode == 'w').
 * Return the dbFILE pointer, or NULL on error.
 */

dbFILE *open_db(const char *service, const char *filename, const char *mode)
{
    if (*mode == 'r') {
        return open_db_read(service, filename);
    } else if (*mode == 'w') {
        return open_db_write(service, filename);
    } else {
        errno = EINVAL;
        return NULL;
    }
}

/*************************************************************************/

/* Close a database connection.
 * For files opened for writing, the data is written to the database.
 */

void close_db(dbFILE *f)
{
    if (f->mode == 'w') {
        /* Copy data from the temporary file to our binary buffer */
        char buffer[8192];
        size_t bytes_read;
        
        /* Seek to beginning of file */
        rewind(f->fp);
        
        /* Read data into our binary buffer */
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), f->fp)) > 0) {
            if (!append_binary_buffer(f->pg_binary, buffer, bytes_read)) {
#ifndef NOT_MAIN
                log_perror("Error buffering data for %s", f->filename);
#endif
                break;
            }
        }
        
        /* Now store the data in the database */
        char *query_str;
        size_t query_size;
        PGresult *res;
        
        /* Escape binary data for SQL */
        size_t escaped_len;
        char *escaped_data = PQescapeByteaConn(pg_conn, 
                                            (unsigned char *)f->pg_binary->data, 
                                            f->pg_binary->size, 
                                            &escaped_len);
        
        if (!escaped_data) {
#ifndef NOT_MAIN
            log("Error escaping binary data for %s: %s", 
                f->filename, PQerrorMessage(pg_conn));
#endif
        } else {
            /* Build and execute query */
            query_size = escaped_len + 256;
            query_str = malloc(query_size);
            
            if (query_str) {
                snprintf(query_str, query_size,
                         "INSERT INTO dbfiles (filename, data) VALUES ('%s', E'%s') "
                         "ON CONFLICT (filename) DO UPDATE SET data = E'%s', "
                         "last_modified = CURRENT_TIMESTAMP",
                         f->filename, escaped_data, escaped_data);
                
                res = PQexec(pg_conn, query_str);
                
                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
#ifndef NOT_MAIN
                    log("Error storing data for %s: %s", 
                        f->filename, PQerrorMessage(pg_conn));
#endif
                } else {
#ifndef NOT_MAIN
                    if (debug)
                        log("Database file %s saved successfully", f->filename);
#endif
                }
                
                PQclear(res);
                free(query_str);
            }
            
            PQfreemem(escaped_data);
        }
    }
    
    if (f->fp)
        fclose(f->fp);
    if (f->backupfp)
        fclose(f->backupfp);
    
    /* Free binary buffer if it exists */
    if (f->pg_binary) {
        free_binary_buffer(f->pg_binary);
        free(f->pg_binary);
    }
    
    free(f);
}

/*************************************************************************/

/* Restore the database file to its condition before open_db().
 * For PostgreSQL, we use transaction rollback for writing operations.
 */

void restore_db(dbFILE *f)
{
    int errno_save = errno;

    if (f->mode == 'w') {
        /* Roll back any pending changes */
        PGresult *res = PQexec(pg_conn, "ROLLBACK");
        PQclear(res);
        
        /* Start a new transaction */
        res = PQexec(pg_conn, "BEGIN");
        PQclear(res);
    }
    
    /* Clean up resources */
    fclose(f->fp);
    
    if (f->pg_binary) {
        free_binary_buffer(f->pg_binary);
        free(f->pg_binary);
    }
    
    free(f);
    errno = errno_save;
}

/*************************************************************************/
/*************************************************************************/

/* Read and write 2- and 4-byte quantities, pointers, and strings.
 * These functions work exactly the same as before, since we're still
 * using FILE* interfaces for compatibility.
 */

int read_int16(uint16 *ret, dbFILE *f)
{
    int c1, c2;

    c1 = fgetc(f->fp);
    c2 = fgetc(f->fp);
    if (c1 == EOF || c2 == EOF)
	return -1;
    *ret = c1<<8 | c2;
    return 0;
}

int write_int16(uint16 val, dbFILE *f)
{
    if (fputc((val>>8) & 0xFF, f->fp) == EOF || fputc(val & 0xFF, f->fp) == EOF)
	return -1;
    return 0;
}


int read_int32(uint32 *ret, dbFILE *f)
{
    int c1, c2, c3, c4;

    c1 = fgetc(f->fp);
    c2 = fgetc(f->fp);
    c3 = fgetc(f->fp);
    c4 = fgetc(f->fp);
    if (c1 == EOF || c2 == EOF || c3 == EOF || c4 == EOF)
	return -1;
    *ret = c1<<24 | c2<<16 | c3<<8 | c4;
    return 0;
}

int write_int32(uint32 val, dbFILE *f)
{
    if (fputc((val>>24) & 0xFF, f->fp) == EOF)
	return -1;
    if (fputc((val>>16) & 0xFF, f->fp) == EOF)
	return -1;
    if (fputc((val>> 8) & 0xFF, f->fp) == EOF)
	return -1;
    if (fputc((val    ) & 0xFF, f->fp) == EOF)
	return -1;
    return 0;
}


int read_ptr(void **ret, dbFILE *f)
{
    int c;

    c = fgetc(f->fp);
    if (c == EOF)
	return -1;
    *ret = (c ? (void *)1 : (void *)0);
    return 0;
}

int write_ptr(const void *ptr, dbFILE *f)
{
    if (fputc(ptr ? 1 : 0, f->fp) == EOF)
	return -1;
    return 0;
}


int read_string(char **ret, dbFILE *f)
{
    char *s;
    uint16 len;

    if (read_int16(&len, f) < 0)
	return -1;
    if (len == 0) {
	*ret = NULL;
	return 0;
    }
    s = smalloc(len);
    if (len != fread(s, 1, len, f->fp)) {
	free(s);
	return -1;
    }
    *ret = s;
    return 0;
}

int write_string(const char *s, dbFILE *f)
{
    uint32 len;

    if (!s)
	return write_int16(0, f);
    len = strlen(s);
    if (len > 65534)
	len = 65534;
    if (write_int16((uint16)(len+1), f) < 0)
	return -1;
    if (len > 0 && fwrite(s, 1, len, f->fp) != len)
	return -1;
    if (fputc(0, f->fp) == EOF)
	return -1;
    return 0;
}

/*************************************************************************/
/*************************************************************************/
