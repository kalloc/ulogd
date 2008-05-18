/* ulogd_PGSQL.c, Version $Revision$
 *
 * ulogd output plugin for logging to a PGSQL database
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org> 
 * This software is distributed under the terms of GNU GPL 
 * 
 * This plugin is based on the MySQL plugin made by Harald Welte.
 * The support PostgreSQL were made by Jakab Laszlo.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <libpq-fe.h>
#include <inttypes.h>

#ifdef DEBUG_PGSQL
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct _field {
	char name[ULOGD_MAX_KEYLEN];
	unsigned int id;
	unsigned int str;
	struct _field *next;
};

/* the database handle we are using */
static PGconn *dbh;

/* a linked list of the fields the table has */
static struct _field *fields;

/* buffer for our insert statement */
static char *stmt;

/* size of our insert statement buffer */
static size_t stmt_siz;

/* pointer to the beginning of the "VALUES" part */
static char *stmt_val;

/* pointer to current inser position in statement */
static char *stmt_ins;

/* our configuration directives */
static config_entry_t db_ce = { 
	.key = "db", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t host_ce = { 
	.next = &db_ce, 
	.key = "host", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
};

static config_entry_t user_ce = { 
	.next = &host_ce, 
	.key = "user", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t pass_ce = { 
	.next = &user_ce, 
	.key = "pass", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
};

static config_entry_t table_ce = { 
	.next = &pass_ce, 
	.key = "table", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t schema_ce = { 
	.next = &table_ce, 
	.key = "schema", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
	.u = { .string = "public" },
};

static config_entry_t port_ce = {
	.next = &schema_ce,
	.key = "port",
	.type = CONFIG_TYPE_INT,
	.options = CONFIG_OPT_NONE,
};

static unsigned char pgsql_have_schemas;

#define STMT_ADD(pos,fmt...) \
	do { \
		if ((pos) >= stmt && stmt_siz > (pos) - stmt) \
			snprintf((pos), stmt_siz-((pos)-stmt), ##fmt); \
	} while(0)

/* our main output function, called by ulogd */
static int pgsql_output(ulog_iret_t *result)
{
	struct _field *f;
	ulog_iret_t *res;
	PGresult   *pgres;
#ifdef IP_AS_STRING
	char *tmpstr;		/* need this for --log-ip-as-string */
	struct in_addr addr;
#endif
	size_t esclen;

	if( stmt_val == NULL)
		return 1;

	stmt_ins = stmt_val;

	for (f = fields; f; f = f->next) {
		res = keyh_getres(f->id);

		if (!res) {
			ulogd_log(ULOGD_NOTICE,
				"no result for %s ?!?\n", f->name);
		}

		if (!res || !IS_VALID((*res))) {
			/* no result, we have to fake something */
			STMT_ADD(stmt_ins, "NULL,");
			stmt_ins = stmt + strlen(stmt);
			continue;
		}

		switch (res->type) {
			case ULOGD_RET_INT8:
				STMT_ADD(stmt_ins, "%d,", res->value.i8);
				break;
			case ULOGD_RET_INT16:
				STMT_ADD(stmt_ins, "%d,", res->value.i16);
				break;
			case ULOGD_RET_INT32:
				STMT_ADD(stmt_ins, "%d,", res->value.i32);
				break;
			case ULOGD_RET_INT64:
				STMT_ADD(stmt_ins, "%"PRId64",",res->value.i64);
				break;
			case ULOGD_RET_UINT8:
				STMT_ADD(stmt_ins, "%u,", res->value.ui8);
				break;
			case ULOGD_RET_UINT16:
				STMT_ADD(stmt_ins, "%u,", res->value.ui16);
				break;
			case ULOGD_RET_IPADDR:
#ifdef IP_AS_STRING
				if (f->str) {
					addr.s_addr = ntohl(res->value.ui32);
					tmpstr = (char *)inet_ntoa(addr);
					esclen = (strlen(tmpstr)*2) + 4;
					if (stmt_siz <= (stmt_ins-stmt)+esclen)
					{
						STMT_ADD(stmt_ins,"'',");
						break;
					}
					*stmt_ins++ = '\'';
					PQescapeString(stmt_ins,tmpstr,
							strlen(tmpstr)); 
					stmt_ins = stmt + strlen(stmt);
					STMT_ADD(stmt_ins, "',");
					break;
				}
#endif /* IP_AS_STRING */
				/* EVIL: fallthrough when logging IP as
				 * u_int32_t */

			case ULOGD_RET_UINT32:
				STMT_ADD(stmt_ins, "%u,", res->value.ui32);
				break;
			case ULOGD_RET_UINT64:
				STMT_ADD(stmt_ins,"%"PRIu64",",res->value.ui64);
				break;
			case ULOGD_RET_BOOL:
				STMT_ADD(stmt_ins, "'%d',", res->value.b);
				break;
			case ULOGD_RET_STRING:
				esclen = (strlen(res->value.ptr)*2) + 4;
				if (stmt_siz <= (stmt_ins-stmt) + esclen) {
					STMT_ADD(stmt_ins, "'',");
					break;
				}
				*stmt_ins++ = '\'';
				PQescapeString(stmt_ins,res->value.ptr,
						strlen(res->value.ptr)); 
				stmt_ins = stmt + strlen(stmt);
				STMT_ADD(stmt_ins, "',");
				break;
			case ULOGD_RET_RAW:
				ulogd_log(ULOGD_NOTICE,
					"%s: pgsql doesn't support type RAW\n",
					res->key);
				STMT_ADD(stmt_ins, "NULL,");
				break;
			default:
				ulogd_log(ULOGD_NOTICE,
					"unknown type %d for %s\n",
					res->type, res->key);
				break;
		}
		stmt_ins = stmt + strlen(stmt);
	}
	*(stmt_ins - 1) = ')';

	DEBUGP("stmt=#%s#\n", stmt);

	/* now we have created our statement, insert it */
	/* Added code by Jaki */
	pgres = PQexec(dbh, stmt);
	if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "sql error during insert: %s\n",
				PQresultErrorMessage(pgres));
		return 1;
	}

	PQclear(pgres);

	return 0;
}

#define PGSQL_HAVE_NAMESPACE_TEMPLATE \
	"SELECT nspname FROM pg_namespace n WHERE n.nspname='%s'"

/* Determine if server support schemas */
static int pgsql_namespace(void) {
	PGresult *result;
	char pgbuf[strlen(PGSQL_HAVE_NAMESPACE_TEMPLATE)+
		   	strlen(schema_ce.u.string)+1];

	if (!dbh)
		return 1;

	snprintf(pgbuf, sizeof(pgbuf), PGSQL_HAVE_NAMESPACE_TEMPLATE,
			schema_ce.u.string);
	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);
	
	result = PQexec(dbh, pgbuf);
	if (!result) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "using schema %s\n", schema_ce.u.string);
		pgsql_have_schemas = 1;
	} else {
		pgsql_have_schemas = 0;
	}

	PQclear(result);
	
	return 0;
}

#define PGSQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define PGSQL_VALSIZE	100

/* create the static part of our insert statement */
static int pgsql_createstmt(void)
{
	struct _field *f;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;

	if (stmt) {
		ulogd_log(ULOGD_NOTICE, "createstmt called, but stmt"
			" already existing\n");
		return 1;
	}

	/* caclulate the size for the insert statement */
	stmt_siz = strlen(PGSQL_INSERTTEMPL) +
		   strlen(table_ce.u.string) +
		   strlen(schema_ce.u.string) + 1;

	for (f = fields; f; f = f->next) {
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		stmt_siz += strlen(f->name) + 1 + PGSQL_VALSIZE;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", stmt_siz);

	stmt = (char *) malloc(stmt_siz);

	if (!stmt) {
		stmt_siz = 0;
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return 1;
	}

	if (pgsql_have_schemas) {
		snprintf(stmt, stmt_siz, "insert into %s.%s (",
			schema_ce.u.string, table_ce.u.string);
	} else {
		snprintf(stmt, stmt_siz, "insert into %s (",
			table_ce.u.string);
	}

	stmt_val = stmt + strlen(stmt);

	for (f = fields; f; f = f->next) {
		strncpy(buf, f->name, ULOGD_MAX_KEYLEN-1);
		buf[ULOGD_MAX_KEYLEN-1] = '\0';
		while ((underscore = strchr(buf, '.')))
			*underscore = '_';
		STMT_ADD(stmt_val, "%s,", buf);
		stmt_val = stmt + strlen(stmt);
	}
	*(stmt_val - 1) = ')';

	STMT_ADD(stmt_val, " values (");
	stmt_val = stmt + strlen(stmt);

	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", stmt);

	return 0;
}

#define PGSQL_GETCOLUMN_TEMPLATE \
	"SELECT  a.attname,t.typname FROM pg_class c, pg_attribute a, "\
	"pg_type t WHERE c.relname ='%s' AND a.attnum>0 AND a.attrelid="\
	"c.oid AND a.atttypid=t.oid ORDER BY a.attnum"

#define PGSQL_GETCOLUMN_TEMPLATE_SCHEMA "SELECT a.attname,t.typname FROM "\
	"pg_attribute a, pg_type t, pg_class c LEFT JOIN pg_namespace n ON "\
	"c.relnamespace=n.oid WHERE c.relname ='%s' AND n.nspname='%s' AND "\
	"a.attnum>0 AND a.attrelid=c.oid AND a.atttypid=t.oid AND "\
	"a.attisdropped=FALSE ORDER BY a.attnum"

/* find out which columns the table has */
static int pgsql_get_columns(const char *table)
{
	PGresult *result;
	char buf[ULOGD_MAX_KEYLEN];
	char pgbuf[strlen(PGSQL_GETCOLUMN_TEMPLATE_SCHEMA)+
		   strlen(table)+strlen(schema_ce.u.string)+2];
	char *underscore;
	struct _field *f;
	int id;
	int intaux;
	char *typename;

	if (!dbh)
		return 1;

	if (pgsql_have_schemas) {
		snprintf(pgbuf, sizeof(pgbuf)-1,
			PGSQL_GETCOLUMN_TEMPLATE_SCHEMA,
			table, schema_ce.u.string);
	} else {
		snprintf(pgbuf, sizeof(pgbuf)-1,
			PGSQL_GETCOLUMN_TEMPLATE, table);
	}

	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);

	result = PQexec(dbh, pgbuf);
	if (!result) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "\n pres_command_not_ok");
		return 1;
	}

	for (intaux=0; intaux<PQntuples(result); intaux++) {

		/* replace all underscores with dots */
		strncpy(buf, PQgetvalue(result, intaux, 0), ULOGD_MAX_KEYLEN-1);
		buf[ULOGD_MAX_KEYLEN-1] = '\0';
		while ((underscore = strchr(buf, '_')))
			*underscore = '.';

		DEBUGP("field '%s' found: ", buf);

		if (!(id = keyh_getid(buf))) {
			DEBUGP(" no keyid!\n");
			continue;
		}

		DEBUGP("keyid %u\n", id);

		/* prepend it to the linked list */
		f = (struct _field *) malloc(sizeof *f);
		if (!f) {
			ulogd_log(ULOGD_ERROR, "OOM!\n");
			return 1;
		}
		strncpy(f->name, buf, ULOGD_MAX_KEYLEN-1);
		f->name[ULOGD_MAX_KEYLEN-1] = '\0';
		f->id = id;
		f->str = 0;
		if( (typename = PQgetvalue(result, intaux, 1)) != NULL)
		{
			if(strcmp(typename, "inet") == 0 ||
			   strstr(typename, "char") != NULL)
				f->str = 1;
		}
		f->next = fields;
		fields = f;
	}

	PQclear(result);
	return 0;
}

static int exit_nicely(PGconn *conn)
{
	PQfinish(conn);
	return 0;;
}

/* make connection and select database */
static int pgsql_open_db(char *server, int port, char *user, char *pass, 
			 char *db)
{
	int len;
	char *connstr;

	/* 80 is more than what we need for the fixed parts below */
	len = 80 + strlen(user) + strlen(db);

	/* hostname and  and password are the only optionals */
	if (server)
		len += strlen(server);
	if (pass)
		len += strlen(pass);
	if (port)
		len += 20;

	connstr = (char *) malloc(len+1);
	if (!connstr)
		return 1;
	*connstr = '\0';

	if (server) {
		strncat(connstr, " host=", len-strlen(connstr));
		strncat(connstr, server, len-strlen(connstr));
	}

	if (port) {
		char portbuf[20];
		snprintf(portbuf, sizeof(portbuf), " port=%u", port);
		strncat(connstr, portbuf, len-strlen(connstr));
	}

	strncat(connstr, " dbname=", len-strlen(connstr));
	strncat(connstr, db, len-strlen(connstr));
	strncat(connstr, " user=", len-strlen(connstr));
	strncat(connstr, user, len-strlen(connstr));

	if (pass) {
		strncat(connstr, " password=", len-strlen(connstr));
		strncat(connstr, pass, len-strlen(connstr));
	}
	
	dbh = PQconnectdb(connstr);
	free(connstr);
	if (PQstatus(dbh)!=CONNECTION_OK) {
		exit_nicely(dbh);
		dbh = NULL;
		return 1;
	}

	return 0;
}

static int pgsql_init(void)
{
	/* have the opts parsed */
	config_parse_file("PGSQL", &port_ce);

	if (pgsql_open_db(host_ce.u.string, port_ce.u.value, user_ce.u.string,
			   pass_ce.u.string, db_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		return 1;
	}

	if (pgsql_namespace()) {
		PQfinish(dbh);
		dbh = NULL;
		ulogd_log(ULOGD_ERROR, "unable to test for pgsql schemas\n");
		return 1;
	}

	/* read the fieldnames to know which values to insert */
	if (pgsql_get_columns(table_ce.u.string)) {
		PQfinish(dbh);
		dbh = NULL;
		ulogd_log(ULOGD_ERROR, "unable to get pgsql columns\n");
		return 1;
	}

	if (pgsql_createstmt()) {
		PQfinish(dbh);
		dbh = NULL;
		return 1;
	}

	return 0;
}

static void pgsql_fini(void)
{
	if (dbh)
		PQfinish(dbh);
	if (stmt)
	{
		free(stmt);
		stmt = NULL;
		stmt_val = NULL;
	}
}

static ulog_output_t pgsql_plugin = { 
	.name = "pgsql", 
	.output = &pgsql_output,
	.init = &pgsql_init,
	.fini = &pgsql_fini,
};

void _init(void)
{
	register_output(&pgsql_plugin);
}
