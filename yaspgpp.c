#include <ctype.h>
#include <limits.h>
#include <unistd.h>

#ifdef USE_CRACKLIB
#include <crack.h>
#endif

#include "postgres.h"
#include "funcapi.h"
#include "miscadmin.h"

#include "access/heapam.h"
#include "access/htup_details.h"

#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_auth_members.h"
#include "catalog/pg_authid.h"
#include "commands/user.h"
#if PG_VERSION_NUM >= 140000
#include "common/hmac.h"
#endif
#include "common/sha2.h"
#include "executor/spi.h"
#include "libpq/auth.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "nodes/pg_list.h"
#include "postmaster/postmaster.h"
#include "tcop/utility.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"
#include "utils/varlena.h"

#define Password_encryption = PASSWORD_TYPE_SCRAM_SHA_256;
#define PGPH_DUMP_FILE_OLD "global/pg_password_history"
#define PGPH_DUMP_FILE "pg_password_history"

#define PG_PASSWORD_HISTORY_COLS 3
#define PG_BANNED_ROLE_COLS 3

static const uint32 PGPH_FILE_HEADER = 0x48504750;
static const uint32 PGPH_VERSION = 100;
#define PGPH_TRANCHE_NAME "yaspgpp_history"
#define PGAF_TRANCHE_NAME "yaspgpp_auth_failure"

static bool statement_has_password = false;
static bool no_password_logging = true;

#define PEL_PROCESSUTILITY_PROTO PlannedStmt *pstmt, const char *queryString,         \
								 bool readOnlyTree,                                   \
								 ProcessUtilityContext context, ParamListInfo params, \
								 QueryEnvironment *queryEnv, DestReceiver *dest,      \
								 QueryCompletion *qc
#define PEL_PROCESSUTILITY_ARGS pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc

PG_MODULE_MAGIC;

/* Hold previous check_password_hook */
static check_password_hook_type prev_check_password_hook = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static shmem_request_hook_type prev_shmem_request_hook = NULL;

static ClientAuthentication_hook_type prev_ClientAuthentication = NULL;
static emit_log_hook_type prev_log_hook = NULL;
typedef struct pgphHashKey
{
	char rolename[NAMEDATALEN];
	char password_hash[PG_SHA256_DIGEST_STRING_LENGTH];
} pgphHashKey;

typedef struct pgphEntry
{
	pgphHashKey key;
	TimestampTz password_date;
} pgphEntry;

typedef struct pgphSharedState
{
	LWLock *lock;
	int num_entries;
} pgphSharedState;

/* Links to shared memory state */
static pgphSharedState *pgph = NULL;
static HTAB *pgph_hash = NULL;
static int pgph_max = 65535;
static int pgaf_max = 1024;
static int fail_max = 0;
static bool reset_superuser = false;
static bool encrypted_password_allowed = false;
typedef struct pgafHashKey
{
	Oid roleid;
} pgafHashKey;

typedef struct pgafEntry
{
	pgafHashKey key;
	float failure_count;
	TimestampTz banned_date;
} pgafEntry;

typedef struct pgafSharedState
{
	LWLock *lock;
	int num_entries;
} pgafSharedState;

static pgafSharedState *pgaf = NULL;
static HTAB *pgaf_hash = NULL;

extern void _PG_init(void);
extern void _PG_fini(void);
static void cc_ProcessUtility(PEL_PROCESSUTILITY_PROTO);

static void flush_password_history(void);
static pgphEntry *pgph_entry_alloc(pgphHashKey *key, TimestampTz password_date);
static pgafEntry *pgaf_entry_alloc(pgafHashKey *key, float failure_count);
static void pghist_shmem_request(void);
static void pghist_shmem_startup(void);
static void pgph_shmem_startup(void);
static void pgaf_shmem_startup(void);
static int entry_cmp(const void *lhs, const void *rhs);
static Size pgph_memsize(void);
static void pg_password_history_internal(FunctionCallInfo fcinfo);
static void fix_log(ErrorData *edata);
static Size pgaf_memsize(void);
static void yaspgpp_max_auth_failure(Port *port, int status);
static float get_auth_failure(const char *username, Oid userid, int status);
static float save_auth_failure(Port *port, Oid userid);
static void remove_auth_failure(const char *username, Oid userid);
static void pg_banned_role_internal(FunctionCallInfo fcinfo);

/* Username flags*/
static int username_min_length = 1;
static int username_min_special = 0;
static int username_min_digit = 0;
static int username_min_upper = 0;
static int username_min_lower = 0;
static int username_min_repeat = 0;
static char *username_not_contain = NULL;
static char *username_contain = NULL;
static bool username_contain_password = true;
static bool username_ignore_case = false;
static char *username_whitelist = NULL;
static char *max_auth_whitelist = NULL;

/* Password flags*/
static int password_min_length = 1;
static int password_min_special = 0;
static int password_min_digit = 0;
static int password_min_upper = 0;
static int password_min_lower = 0;
static int password_min_repeat = 0;
static char *password_not_contain = NULL;
static char *password_contain = NULL;
static bool password_contain_username = true;
static bool password_ignore_case = false;
static int password_valid_until = 0;
static int password_valid_max = 0;
static int auth_delay_milliseconds = 0;

static int password_reuse_history = 0;
static int password_reuse_interval = 0;
char *str_to_sha256(const char *str, const char *salt);

bool check_whitelist(char **newval, void **extra, GucSource source);
bool is_in_whitelist(char *username, char *whitelist);

static char *to_nlower(const char *str, size_t max)
{
	char *lower_str;
	int i = 0;

	lower_str = (char *)calloc(strlen(str), sizeof(char));

	for (const char *p = str; *p && i < max; p++)
	{
		lower_str[i++] = tolower(*p);
	}
	lower_str[i] = '\0';
	return lower_str;
}

static bool str_contains(const char *chars, const char *str)
{
	for (const char *i = str; *i; i++)
	{
		for (const char *j = chars; *j; j++)
		{
			if (*i == *j)
			{
				return true;
			}
		}
	}

	return false;
}

static void check_str_counters(const char *str, int *lower, int *upper,
							   int *digit, int *special)
{
	for (const char *i = str; *i; i++)
	{
		if (islower(*i))
		{
			(*lower)++;
		}
		else if (isupper(*i))
		{
			(*upper)++;
		}
		else if (isdigit(*i))
		{
			(*digit)++;
		}
		else
		{
			(*special)++;
		}
	}
}

static bool char_repeat_exceeds(const char *str, int max_repeat)
{
	int occurred = 1;
	size_t len = strlen(str);

	if (len == 1)
	{
		return false;
	}

	for (size_t i = 0; i < len;)
	{
		occurred = 1;
		for (size_t j = (i + 1), k = 1; j < len; j++, k++)
		{
			if (str[i] == str[j])
			{
				if (i + k == j)
				{
					occurred++;
					if (occurred > max_repeat)
					{
						return true;
					}
				}
			}

			if (j + 1 == len)
			{
				return false;
			}

			if (str[i] != str[j])
			{
				i = j;
				break;
			}
		}
	}
	return false;
}

static void username_check(const char *username, const char *password)
{
	int user_total_special = 0;
	int user_total_digit = 0;
	int user_total_upper = 0;
	int user_total_lower = 0;

	char *tmp_pass = NULL;
	char *tmp_user = NULL;
	char *tmp_contains = NULL;
	char *tmp_not_contains = NULL;

	if (strcasestr(debug_query_string, "PASSWORD") != NULL)
		statement_has_password = true;

	if (username_ignore_case)
	{
		if (password != NULL && strlen(password) > 0)
			tmp_pass = to_nlower(password, INT_MAX);
		tmp_user = to_nlower(username, INT_MAX);
		tmp_contains = to_nlower(username_contain, INT_MAX);
		tmp_not_contains = to_nlower(username_not_contain, INT_MAX);
	}
	else
	{
		if (password != NULL && strlen(password) > 0)
			tmp_pass = strndup(password, INT_MAX);
		tmp_user = strndup(username, INT_MAX);
		tmp_contains = strndup(username_contain, INT_MAX);
		tmp_not_contains = strndup(username_not_contain, INT_MAX);
	}

	if (strnlen(tmp_user, INT_MAX) < username_min_length)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg(gettext_noop("username length should match the configured %s (%d)"),
						"yaspgpp.username_min_length", username_min_length)));
		goto clean;
	}

	if (tmp_pass != NULL && username_contain_password)
	{
		if (strstr(tmp_user, tmp_pass))
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("username should not contain password"))));
			goto clean;
		}
	}

	if (tmp_contains != NULL && strlen(tmp_contains) > 0)
	{
		if (str_contains(tmp_contains, tmp_user) == false)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("username does not contain the configured %s characters: %s"),
							"yaspgpp.username_contain", tmp_contains)));
			goto clean;
		}
	}

	if (tmp_not_contains != NULL && strlen(tmp_not_contains) > 0)
	{
		if (str_contains(tmp_not_contains, tmp_user) == true)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("username contains the configured %s unauthorized characters: %s"),
							"yaspgpp.username_not_contain", tmp_not_contains)));
			goto clean;
		}
	}

	check_str_counters(tmp_user, &user_total_lower, &user_total_upper,
					   &user_total_digit, &user_total_special);

	if (!username_ignore_case && user_total_upper < username_min_upper)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("username does not contain the configured %s characters (%d)",
						"yaspgpp.username_min_upper", username_min_upper)));
		goto clean;
	}

	if (!username_ignore_case && user_total_lower < username_min_lower)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("username does not contain the configured %s characters (%d)",
						"yaspgpp.username_min_lower", username_min_lower)));
		goto clean;
	}

	if (user_total_digit < username_min_digit)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("username does not contain the configured %s characters (%d)",
						"yaspgpp.username_min_digit", username_min_digit)));
		goto clean;
	}

	if (user_total_special < username_min_special)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("username does not contain the configured %s characters (%d)",
						"yaspgpp.username_min_special", username_min_special)));
		goto clean;
	}

	if (username_min_repeat)
	{
		if (char_repeat_exceeds(tmp_user, username_min_repeat))
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("%s characters are repeated more than the "
										 "configured %s times (%d)"),
							"username", "yaspgpp.username_min_repeat", username_min_repeat)));
			goto clean;
		}
	}
clean:

	free(tmp_pass);
	free(tmp_user);
	free(tmp_contains);
	free(tmp_not_contains);
}

bool check_whitelist(char **newval, void **extra, GucSource source)
{
	char *rawstring;
	List *elemlist;

	rawstring = pstrdup(*newval);
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		GUC_check_errdetail("List syntax is invalid.");
		pfree(rawstring);
		list_free(elemlist);
		return false;
	}

	pfree(rawstring);
	list_free(elemlist);

	return true;
}

bool is_in_whitelist(char *username, char *whitelist)
{
	char *rawstring;
	List *elemlist;
	ListCell *l;
	int len = 0;

	Assert(username != NULL);
	Assert(whitelist != NULL);

	len = strlen(whitelist);
	if (len == 0)
		return false;

	rawstring = palloc0(sizeof(char) * (len + 1));
	strcpy(rawstring, whitelist);
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("username list is invalid: %s", whitelist)));
		list_free(elemlist);
		pfree(rawstring);
		return false;
	}

	foreach (l, elemlist)
	{
		char *tok = (char *)lfirst(l);

		if (pg_strcasecmp(tok, username) == 0)
		{
			list_free(elemlist);
			pfree(rawstring);
			return true;
		}
	}

	list_free(elemlist);
	pfree(rawstring);

	return false;
}

static void password_check(const char *username, const char *password)
{

	int pass_total_special = 0;
	int pass_total_digit = 0;
	int pass_total_upper = 0;
	int pass_total_lower = 0;

	char *tmp_pass = NULL;
	char *tmp_user = NULL;
	char *tmp_contains = NULL;
	char *tmp_not_contains = NULL;

	Assert(username != NULL);
	Assert(password != NULL);

	if (password_ignore_case)
	{
		tmp_pass = to_nlower(password, INT_MAX);
		tmp_user = to_nlower(username, INT_MAX);
		tmp_contains = to_nlower(password_contain, INT_MAX);
		tmp_not_contains = to_nlower(password_not_contain, INT_MAX);
	}
	else
	{
		tmp_pass = strndup(password, INT_MAX);
		tmp_user = strndup(username, INT_MAX);
		tmp_contains = strndup(password_contain, INT_MAX);
		tmp_not_contains = strndup(password_not_contain, INT_MAX);
	}

	if (strnlen(tmp_pass, INT_MAX) < password_min_length)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg(gettext_noop("password length should match the configured %s (%d)"),
						"yaspgpp.password_min_length", password_min_length)));
		goto clean;
	}

	if (password_contain_username)
	{
		if (strstr(tmp_pass, tmp_user))
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("password should not contain username"))));
			goto clean;
		}
	}

	if (tmp_contains != NULL && strlen(tmp_contains) > 0)
	{
		if (str_contains(tmp_contains, tmp_pass) == false)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("password does not contain the configured %s characters: %s"),
							"yaspgpp.password_contain", tmp_contains)));
			goto clean;
		}
	}

	if (tmp_not_contains != NULL && strlen(tmp_not_contains) > 0)
	{
		if (str_contains(tmp_not_contains, tmp_pass) == true)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("password contains the configured %s unauthorized characters: %s"),
							"yaspgpp.password_not_contain", tmp_not_contains)));
			goto clean;
		}
	}

	check_str_counters(tmp_pass, &pass_total_lower, &pass_total_upper,
					   &pass_total_digit, &pass_total_special);

	if (!password_ignore_case && pass_total_upper < password_min_upper)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("password does not contain the configured %s characters (%d)",
						"yaspgpp.password_min_upper", password_min_upper)));
		goto clean;
	}

	if (!password_ignore_case && pass_total_lower < password_min_lower)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("password does not contain the configured %s characters (%d)",
						"yaspgpp.password_min_lower", password_min_lower)));
		goto clean;
	}

	if (pass_total_digit < password_min_digit)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("password does not contain the configured %s characters (%d)",
						"yaspgpp.password_min_digit", password_min_digit)));
		goto clean;
	}

	if (pass_total_special < password_min_special)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg("password does not contain the configured %s characters (%d)",
						"yaspgpp.password_min_special", password_min_special)));
		goto clean;
	}

	if (password_min_repeat)
	{
		if (char_repeat_exceeds(tmp_pass, password_min_repeat))
		{
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg("%s characters are repeated more than the "
							"configured %s times (%d)",
							"password",
							"yaspgpp.password_min_repeat", password_min_repeat)));
			goto clean;
		}
	}

clean:

	free(tmp_pass);
	free(tmp_user);
	free(tmp_contains);
	free(tmp_not_contains);
}

static void username_guc()
{
	DefineCustomIntVariable("yaspgpp.username_min_length",
							gettext_noop("minimum username length"), NULL,
							&username_min_length, 1, 1, INT_MAX, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.username_min_special",
							gettext_noop("minimum username special characters"),
							NULL, &username_min_special, 0, 0, INT_MAX,
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.username_min_digit",
							gettext_noop("minimum username digits"), NULL,
							&username_min_digit, 0, 0, INT_MAX, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.username_min_upper",
							gettext_noop("minimum username uppercase letters"),
							NULL, &username_min_upper, 0, 0, INT_MAX, PGC_SUSET,
							0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.username_min_lower",
							gettext_noop("minimum username lowercase letters"),
							NULL, &username_min_lower, 0, 0, INT_MAX, PGC_SUSET,
							0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.username_min_repeat",
							gettext_noop("minimum username characters repeat"),
							NULL, &username_min_repeat, 0, 0, INT_MAX,
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.username_contain_password",
							 gettext_noop("username contains password"), NULL,
							 &username_contain_password, true, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.username_ignore_case",
							 gettext_noop("ignore case while username checking"),
							 NULL, &username_ignore_case, false, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable(
		"yaspgpp.username_not_contain",
		gettext_noop("username should not contain these characters"), NULL,
		&username_not_contain, "", PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomStringVariable(
		"yaspgpp.username_contain",
		gettext_noop("password should contain these characters"), NULL,
		&username_contain, "", PGC_SUSET, 0, NULL, NULL, NULL);
}

static void password_guc()
{
	DefineCustomIntVariable("yaspgpp.password_min_length",
							gettext_noop("minimum password length"), NULL,
							&password_min_length, 1, 1, INT_MAX, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_min_special",
							gettext_noop("minimum special characters"), NULL,
							&password_min_special, 0, 0, INT_MAX, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_min_digit",
							gettext_noop("minimum password digits"), NULL,
							&password_min_digit, 0, 0, INT_MAX, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_min_upper",
							gettext_noop("minimum password uppercase letters"),
							NULL, &password_min_upper, 0, 0, INT_MAX, PGC_SUSET,
							0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_min_lower",
							gettext_noop("minimum password lowercase letters"),
							NULL, &password_min_lower, 0, 0, INT_MAX, PGC_SUSET,
							0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_min_repeat",
							gettext_noop("minimum password characters repeat"),
							NULL, &password_min_repeat, 0, 0, INT_MAX,
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.password_contain_username",
							 gettext_noop("password contains username"), NULL,
							 &password_contain_username, true, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.password_ignore_case",
							 gettext_noop("ignore case while password checking"),
							 NULL, &password_ignore_case, false, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable(
		"yaspgpp.password_not_contain",
		gettext_noop("password should not contain these characters"), NULL,
		&password_not_contain, "", PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomStringVariable(
		"yaspgpp.password_contain",
		gettext_noop("password should contain these characters"), NULL,
		&password_contain, "", PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_reuse_history",
							gettext_noop("minimum number of password changes before permitting reuse"),
							NULL, &password_reuse_history, 0, 0, 100,
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_reuse_interval",
							gettext_noop("minimum number of days elapsed before permitting reuse"),
							NULL, &password_reuse_interval, 0, 0, 730, /* max 2 years */
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_valid_until",
							gettext_noop("force use of VALID UNTIL clause in CREATE ROLE statement"
										 " with a minimum number of days"),
							NULL, &password_valid_until, 0, 0, INT_MAX,
							PGC_SUSET, 0, NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.password_valid_max",
							gettext_noop("force use of VALID UNTIL clause in CREATE ROLE statement"
										 " with a maximum number of days"),
							NULL, &password_valid_max, 0, 0, INT_MAX,
							PGC_SUSET, 0, NULL, NULL, NULL);
}

static void save_password_in_history(const char *username, const char *password)
{
	char *encrypted_password;
	pgphHashKey key;
	pgphEntry *entry;
	TimestampTz dt_now = GetCurrentTimestamp();

	Assert(username != NULL);
	Assert(password != NULL);

	if (password_reuse_history == 0 && password_reuse_interval == 0)
		return;

	/* Safety check... */
	if (!pgph || !pgph_hash)
		return;

	/* Encrypt the password to the requested format. */
	encrypted_password = strdup(str_to_sha256(password, username));

	/* Store the password into share memory and password history file */
	/* Set up key for hashtable search */
	strcpy(key.rolename, username);
	strcpy(key.password_hash, encrypted_password);

	/* Lookup the hash table entry with exclusive lock. */
	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	/* Create new entry, if not present */
	entry = (pgphEntry *)hash_search(pgph_hash, &key, HASH_FIND, NULL);
	if (!entry)
	{
		dt_now = GetCurrentTimestamp();

		elog(DEBUG1, "Add new entry in history hash table: (%s, '%s', '%s')",
			 username, encrypted_password,
			 timestamptz_to_str(dt_now));

		/* OK to create a new hashtable entry */
		entry = pgph_entry_alloc(&key, dt_now);

		/* Flush the new entry to disk */
		if (entry)
		{
			elog(DEBUG1, "entry added, flush change to disk");
			flush_password_history();
		}
	}

	LWLockRelease(pgph->lock);

	free(encrypted_password);
}

static void rename_user_in_history(const char *username, const char *newname)
{
	pgphEntry *entry;
	HASH_SEQ_STATUS hash_seq;
	int num_changed = 0;

	if (password_reuse_history == 0 && password_reuse_interval == 0)
		return;

	Assert(username != NULL);
	Assert(newname != NULL);

	/* Safety check ... shouldn't get here unless shmem is set up. */
	if (!pgph || !pgph_hash)
		return;

	elog(DEBUG1, "renaming user %s to %s into password history", username, newname);

	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgph_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		/* update the key of matching entries */
		if (strcmp(entry->key.rolename, username) == 0)
		{
			pgphHashKey key;
			strcpy(key.rolename, newname);
			strcpy(key.password_hash, entry->key.password_hash);
			hash_update_hash_key(pgph_hash, entry, &key);
			num_changed++;
		}
	}

	if (num_changed > 0)
	{
		elog(DEBUG1, "%d entries in paswword history hash table have been mofidied for user %s",
			 num_changed,
			 username);

		/* Flush the new entry to disk */
		flush_password_history();
	}

	LWLockRelease(pgph->lock);
}

static int entry_cmp(const void *lhs, const void *rhs)
{
	TimestampTz l_password_date = (*(pgphEntry *const *)lhs)->password_date;
	TimestampTz r_password_date = (*(pgphEntry *const *)rhs)->password_date;

	if (l_password_date < r_password_date)
		return -1;
	else if (l_password_date > r_password_date)
		return +1;
	else
		return 0;
}

static void remove_password_from_history(const char *username, const char *password, int numentries)
{
	char *encrypted_password;
	int32 num_entries;
	int32 num_user_entries = 0;
	int32 num_removed = 0;
	pgphEntry *entry;
	HASH_SEQ_STATUS hash_seq;
	pgphEntry **entries;
	int i = 0;

	if (password_reuse_history == 0 && password_reuse_interval == 0)
		return;

	Assert(username != NULL);
	Assert(password != NULL);

	/* Safety check ... shouldn't get here unless shmem is set up. */
	if (!pgph || !pgph_hash)
		return;

	/* Encrypt the password to the requested format. */
	encrypted_password = strdup(str_to_sha256(password, username));

	elog(DEBUG1, "attempting to remove historized password = '%s' for user = '%s'", encrypted_password, username);

	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	num_entries = hash_get_num_entries(pgph_hash);
	hash_seq_init(&hash_seq, pgph_hash);

	entries = palloc(num_entries * sizeof(pgphEntry *));

	/* stores entries related to the username to be sorted by date */
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (strcmp(entry->key.rolename, username) == 0)
			entries[i++] = entry;
	}

	if (i == 0)
	{
		elog(DEBUG1, "no entry in the history for user: %s", username);

		LWLockRelease(pgph->lock);

		pfree(entries);

		return;
	}

	num_user_entries = i;

	qsort(entries, i, sizeof(pgphEntry *), entry_cmp);

	for (i = 0; i < num_user_entries; i++)
	{
		bool keep = false;

		if (password_reuse_interval > 0)
		{
			TimestampTz dt_now = GetCurrentTimestamp();
			float8 result;

			result = ((float8)(dt_now - entries[i]->password_date)) / 1000000.0; /* in seconds */
			result /= 86400;													 /* in days */

			elog(DEBUG1, "password_reuse_interval: %d, entry age: %d",
				 password_reuse_interval,
				 (int)result);

			if (password_reuse_interval >= (int)result)
				keep = true;
			else
				elog(DEBUG1, "remove_password_from_history(): this history entry has expired");
		}

		if (!keep)
		{
			if ((num_user_entries - i) >= password_reuse_history)
			{
				elog(DEBUG1, "removing entry %d from the history (%s, %s)", i,
					 entries[i]->key.rolename,
					 entries[i]->key.password_hash);
				hash_search(pgph_hash, &entries[i]->key, HASH_REMOVE, NULL);
				num_removed++;
			}
		}
	}
	pfree(entries);

	if (num_removed > 0)
		flush_password_history();

	LWLockRelease(pgph->lock);
}

static void remove_user_from_history(const char *username)
{
	int32 num_removed = 0;
	pgphEntry *entry;
	HASH_SEQ_STATUS hash_seq;

	if (password_reuse_history == 0 && password_reuse_interval == 0)
		return;

	Assert(username != NULL);

	if (!pgph || !pgph_hash)
		return;

	elog(DEBUG1, "removing user %s from password history", username);

	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgph_hash);

	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (strcmp(entry->key.rolename, username) == 0)
		{
			hash_search(pgph_hash, &entry->key, HASH_REMOVE, NULL);
			num_removed++;
		}
	}

	if (num_removed > 0)
		flush_password_history();

	LWLockRelease(pgph->lock);
}

static bool check_password_reuse(const char *username, const char *password)
{
	int count_in_history = 0;
	pgphEntry *entry;
	bool found = false;
	char *encrypted_password;
	HASH_SEQ_STATUS hash_seq;

	Assert(username != NULL);

	if (password == NULL)
		return false;

	if (password_reuse_history == 0 && password_reuse_interval == 0)
		return false;

	if (!pgph || !pgph_hash)
		return false;

	encrypted_password = strdup(str_to_sha256(password, username));

	elog(DEBUG1, "Looking for registered password = '%s' for username = '%s'", encrypted_password, username);

	LWLockAcquire(pgph->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pgph_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (strcmp(entry->key.rolename, username) == 0)
		{
			if (strcmp(encrypted_password, entry->key.password_hash) == 0)
			{
				elog(DEBUG1, "password found in history, username = '%s',"
							 " password: '%s', saved at date: '%s'",
					 username,
					 entry->key.password_hash,
					 timestamptz_to_str(entry->password_date));

				found = true;

				if (password_reuse_interval > 0)
				{
					TimestampTz dt_now = GetCurrentTimestamp();
					float8 result;
					result = ((float8)(dt_now - entry->password_date)) / 1000000.0; /* in seconds */
					result /= 86400;												/* in days */
					elog(DEBUG1, "password_reuse_interval: %d, entry age: %d",
						 password_reuse_interval,
						 (int)result);

					if (password_reuse_interval < (int)result)
					{
						elog(DEBUG1, "this history entry has expired");
						found = false;
						count_in_history--;
					}
				}
			}

			count_in_history++;
		}
	}

	LWLockRelease(pgph->lock);

	free(encrypted_password);

	if (found)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				 errmsg(gettext_noop("Cannot use this credential following the password reuse policy"))));

	remove_password_from_history(username, password, count_in_history);

	return true;
}

static int check_valid_until(char *valid_until_date)
{
	int days = 0;

	elog(DEBUG1, "option VALID UNTIL date: %s", valid_until_date);

	if (valid_until_date)
	{
		Datum validUntil_datum;
		TimestampTz dt_now = GetCurrentTimestamp();
		TimestampTz valid_date;
		float8 result;

		validUntil_datum = DirectFunctionCall3(timestamptz_in,
											   CStringGetDatum(valid_until_date),
											   ObjectIdGetDatum(InvalidOid),
											   Int32GetDatum(-1));
		valid_date = DatumGetTimestampTz(validUntil_datum);

		result = ((float8)(valid_date - dt_now)) / 1000000.0; /* in seconds */
		result /= 86400;									  /* in days */
		days = (int)result;

		elog(DEBUG1, "option VALID UNTIL in days: %d", days);
	}

	return days;
}

static void check_password(const char *username, const char *password,
						   PasswordType password_type, Datum validuntil_time,
						   bool validuntil_null)
{

	switch (password_type)
	{
	case PASSWORD_TYPE_PLAINTEXT:
	{
#ifdef USE_CRACKLIB
		const char *reason;
#endif
		if (is_in_whitelist((char *)username, username_whitelist))
			break;

		statement_has_password = true;
		username_check(username, password);
		if (password != NULL)
		{
			password_check(username, password);
#ifdef USE_CRACKLIB
			if ((reason = FascistCheck(password, CRACKLIB_DICTPATH)))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("password is easily cracked"),
						 errdetail_log("cracklib diagnostic: %s", reason)));
#endif
		}
		break;
	}
	default:
		if (!encrypted_password_allowed)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("password type is not a plain text"))));
		break;
	}
}

void _PG_init(void)
{
	/* Defined GUCs */
	username_guc();
	password_guc();

	if (process_shared_preload_libraries_in_progress)
	{
		DefineCustomIntVariable("yaspgpp.history_max_size",
								gettext_noop("maximum of entries in the password history"), NULL,
								&pgph_max, 65535, 1, (INT_MAX / 1024), PGC_POSTMASTER, 0,
								NULL, NULL, NULL);

		DefineCustomIntVariable("yaspgpp.auth_failure_cache_size",
								gettext_noop("maximum of entries in the auth failure cache"), NULL,
								&pgaf_max, 1024, 1, (INT_MAX / 1024), PGC_POSTMASTER, 0,
								NULL, NULL, NULL);
	}

	DefineCustomBoolVariable("yaspgpp.no_password_logging",
							 gettext_noop("prevent exposing the password in error messages logged"),
							 NULL, &no_password_logging, true, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.max_auth_failure",
							gettext_noop("maximum number of authentication failure before"
										 " the user loggin account be invalidated"),
							NULL,
							&fail_max, 0, 0, 64, PGC_SUSET, 0,
							NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.reset_superuser",
							 gettext_noop("restore superuser acces when he have been banned."),
							 NULL, &reset_superuser, false, PGC_SIGHUP, 0,
							 NULL, NULL, NULL);

	DefineCustomBoolVariable("yaspgpp.encrypted_password_allowed",
							 gettext_noop("allow encrypted password to be used or throw an error"),
							 NULL, &encrypted_password_allowed, false, PGC_SUSET, 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable(
		"yaspgpp.whitelist",
		gettext_noop("comma separated list of username to exclude from password policy check"), NULL,
		&username_whitelist, "", PGC_SUSET, 0, check_whitelist, NULL, NULL);

	DefineCustomIntVariable("yaspgpp.auth_delay_ms",
							"Milliseconds to delay before reporting authentication failure",
							NULL,
							&auth_delay_milliseconds,
							0,
							0, INT_MAX / 1000,
							PGC_SIGHUP,
							GUC_UNIT_MS,
							NULL,
							NULL,
							NULL);

	DefineCustomStringVariable(
		"yaspgpp.whitelist_auth_failure",
		gettext_noop("comma separated list of username to exclude from max authentication failure check"), NULL,
		&max_auth_whitelist, "", PGC_SUSET, 0, check_whitelist, NULL, NULL);

	MarkGUCPrefixReserved("yaspgpp");

	/* Install hooks */
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = cc_ProcessUtility;
	prev_check_password_hook = check_password_hook;
	check_password_hook = check_password;
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = pghist_shmem_request;
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pghist_shmem_startup;

	prev_log_hook = emit_log_hook;
	emit_log_hook = fix_log;

	prev_ClientAuthentication = ClientAuthentication_hook;
	ClientAuthentication_hook = yaspgpp_max_auth_failure;
}

void _PG_fini(void)
{
	/* Uninstall hooks */
	check_password_hook = prev_check_password_hook;
	ProcessUtility_hook = prev_ProcessUtility;
	emit_log_hook = prev_log_hook;
	shmem_request_hook = prev_shmem_request_hook;
	shmem_startup_hook = prev_shmem_startup_hook;
	ClientAuthentication_hook = prev_ClientAuthentication;
}

static void cc_ProcessUtility(PEL_PROCESSUTILITY_PROTO)
{
	Node *parsetree = pstmt->utilityStmt;

	if (prev_ProcessUtility)
		prev_ProcessUtility(PEL_PROCESSUTILITY_ARGS);
	else
		standard_ProcessUtility(PEL_PROCESSUTILITY_ARGS);

	statement_has_password = false;

	switch (nodeTag(parsetree))
	{
	case T_RenameStmt:
	{
		RenameStmt *stmt = (RenameStmt *)parsetree;
		if (stmt->renameType == OBJECT_ROLE && stmt->newname != NULL)
		{
			if (is_in_whitelist(stmt->newname, username_whitelist) || is_in_whitelist(stmt->subname, username_whitelist))
				break;

			username_check(stmt->newname, NULL);
			rename_user_in_history(stmt->subname, stmt->newname);
		}
		break;
	}

	case T_AlterRoleStmt:
	{
		AlterRoleStmt *stmt = (AlterRoleStmt *)parsetree;
		ListCell *option;
		char *password;
		bool save_password = false;
		DefElem *dvalidUntil = NULL;
		DefElem *dpassword = NULL;

		if (is_in_whitelist(stmt->role->rolename, username_whitelist))
			break;

		foreach (option, stmt->options)
		{
			DefElem *defel = (DefElem *)lfirst(option);

			if (strcmp(defel->defname, "password") == 0)
			{
				dpassword = defel;
			}
			else if (strcmp(defel->defname, "validUntil") == 0)
			{
				dvalidUntil = defel;
			}
		}
		if (dpassword && dpassword->arg)
		{
			statement_has_password = true;
			password = strVal(dpassword->arg);
			save_password = check_password_reuse(stmt->role->rolename, password);
		}

		if (dvalidUntil && dvalidUntil->arg && password_valid_until > 0)
		{
			int valid_until = check_valid_until(strVal(dvalidUntil->arg));
			if (valid_until < password_valid_until)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
						 errmsg(gettext_noop("the VALID UNTIL option must have a date older than %d days"), password_valid_until)));
		}
		if (dvalidUntil && dvalidUntil->arg && password_valid_max > 0)
		{
			int valid_max = check_valid_until(strVal(dvalidUntil->arg));
			if (valid_max > password_valid_max)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
						 errmsg(gettext_noop("the VALID UNTIL option must NOT have a date beyond %d days"), password_valid_max)));
		}

		if (save_password)
			save_password_in_history(stmt->role->rolename, password);

		break;
	}

	case T_CreateRoleStmt:
	{
		CreateRoleStmt *stmt = (CreateRoleStmt *)parsetree;
		ListCell *option;
		int valid_until = 0;
		int valid_max = 0;
		bool has_valid_until = false;
		bool save_password = false;
		char *password;
		DefElem *dpassword = NULL;
		DefElem *dvalidUntil = NULL;

		if (is_in_whitelist(stmt->role, username_whitelist))
			break;

		username_check(stmt->role, NULL);
		foreach (option, stmt->options)
		{
			DefElem *defel = (DefElem *)lfirst(option);

			if (strcmp(defel->defname, "password") == 0)
			{
				dpassword = defel;
			}
			else if (strcmp(defel->defname, "validUntil") == 0)
			{
				dvalidUntil = defel;
			}
		}

		if (dpassword && dpassword->arg)
		{
			statement_has_password = true;
			password = strVal(dpassword->arg);
			save_password = check_password_reuse(stmt->role, password);
		}

		if (dvalidUntil && dvalidUntil->arg && password_valid_until > 0)
		{
			valid_until = check_valid_until(strVal(dvalidUntil->arg));
			has_valid_until = true;
		}
		if (dvalidUntil && dvalidUntil->arg && password_valid_max > 0)
		{
			valid_max = check_valid_until(strVal(dvalidUntil->arg));
			has_valid_until = true;
		}

		if (!has_valid_until && (password_valid_until > 0 || password_valid_max > 0))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("require a VALID UNTIL option"))));

		if (password_valid_until > 0 && valid_until < password_valid_until)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("require a VALID UNTIL option with a date older than %d days"), password_valid_until)));

		if (password_valid_max > 0 && valid_max > password_valid_max)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					 errmsg(gettext_noop("require a VALID UNTIL option with a date beyond %d days"), password_valid_max)));

		if (save_password)
			save_password_in_history(stmt->role, password);

		break;
	}

	case T_DropRoleStmt:
	{
		DropRoleStmt *stmt = (DropRoleStmt *)parsetree;
		ListCell *item;

		foreach (item, stmt->roles)
		{
			RoleSpec *rolspec = lfirst(item);

			remove_user_from_history(rolspec->rolename);
		}
		break;
	}

	default:
		break;
	}
}

char *str_to_sha256(const char *password, const char *salt)
{
	int password_len = strlen(password);
	int saltlen = strlen(salt);
	uint8 checksumbuf[PG_SHA256_DIGEST_LENGTH];
	char *result = palloc0(sizeof(char) * PG_SHA256_DIGEST_STRING_LENGTH);
	pg_hmac_ctx *hmac_ctx = pg_hmac_create(PG_SHA256);

	if (hmac_ctx == NULL)
	{
		pfree(result);
		elog(ERROR, gettext_noop("yaspgpp could not initialize checksum context"));
	}

	if (pg_hmac_init(hmac_ctx, (uint8 *)password, password_len) < 0 ||
		pg_hmac_update(hmac_ctx, (uint8 *)salt, saltlen) < 0 ||
		pg_hmac_final(hmac_ctx, checksumbuf, sizeof(checksumbuf)) < 0)
	{
		pfree(result);
		pg_hmac_free(hmac_ctx);
		elog(ERROR, gettext_noop("yaspgpp could not initialize checksum"));
	}
	hex_encode((char *)checksumbuf, sizeof checksumbuf, result);
	result[PG_SHA256_DIGEST_STRING_LENGTH - 1] = '\0';

	pg_hmac_free(hmac_ctx);

	return result;
}

static Size pgph_memsize(void)
{
	Size size;

	size = MAXALIGN(sizeof(pgphSharedState));
	size = add_size(size, hash_estimate_size(pgph_max, sizeof(pgphEntry)));

	return size;
}

static Size pgaf_memsize(void)
{
	Size size;

	size = MAXALIGN(sizeof(pgafSharedState));
	size = add_size(size, hash_estimate_size(pgaf_max, sizeof(pgafEntry)));

	return size;
}

static void pghist_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();

	RequestAddinShmemSpace(pgph_memsize());
	RequestNamedLWLockTranche(PGPH_TRANCHE_NAME, 1);
	RequestAddinShmemSpace(pgaf_memsize());
	RequestNamedLWLockTranche(PGAF_TRANCHE_NAME, 1);
}

static void pghist_shmem_startup(void)
{
	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	pgph_shmem_startup();

	pgaf_shmem_startup();
}

static void pgph_shmem_startup(void)
{
	bool found;
	HASHCTL info;
	FILE *file = NULL;
	uint32 header;
	int32 pgphver;
	int32 num;
	int32 i;

	pgph = NULL;
	pgph_hash = NULL;

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pgph = ShmemInitStruct("pg_password_history",
						   sizeof(pgphSharedState),
						   &found);

	if (!found)
	{
		pgph->lock = &(GetNamedLWLockTranche(PGPH_TRANCHE_NAME))->lock;
	}

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgphHashKey);
	info.entrysize = sizeof(pgphEntry);
	pgph_hash = ShmemInitHash("pg_password_history hash",
							  pgph_max, pgph_max,
							  &info,
							  HASH_ELEM | HASH_BLOBS);

	LWLockRelease(AddinShmemInitLock);

	if (found)
		return;

	file = AllocateFile(PGPH_DUMP_FILE_OLD, PG_BINARY_R);
	if (file != NULL)
	{
		FreeFile(file);
		(void)durable_rename(PGPH_DUMP_FILE_OLD, PGPH_DUMP_FILE, LOG);
	}

	file = AllocateFile(PGPH_DUMP_FILE, PG_BINARY_R);
	if (file == NULL)
	{
		if (errno != ENOENT)
			goto read_error;
		return;
	}

	if (fread(&header, sizeof(uint32), 1, file) != 1 ||
		fread(&pgphver, sizeof(uint32), 1, file) != 1 ||
		fread(&num, sizeof(int32), 1, file) != 1)
		goto read_error;

	if (header != PGPH_FILE_HEADER || pgphver != PGPH_VERSION)
		goto data_error;

	for (i = 0; i < num; i++)
	{
		pgphEntry temp;
		pgphEntry *entry;

		if (fread(&temp, sizeof(pgphEntry), 1, file) != 1)
		{
			ereport(LOG,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("ignoring invalid data in pg_password_history file \"%s\"",
							PGPH_DUMP_FILE)));
			goto fail;
		}

		entry = pgph_entry_alloc(&temp.key, temp.password_date);
		if (!entry)
			goto fail;
	}
	FreeFile(file);

	pgph->num_entries = i + 1;

	return;

read_error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not read pg_password_history file \"%s\": %m",
					PGPH_DUMP_FILE)));
	goto fail;
data_error:
	ereport(LOG,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("ignoring invalid data in file \"%s\"",
					PGPH_DUMP_FILE)));
fail:
	if (file)
		FreeFile(file);
}

static pgphEntry *pgph_entry_alloc(pgphHashKey *key, TimestampTz password_date)
{
	pgphEntry *entry;
	bool found;

	if (hash_get_num_entries(pgph_hash) >= pgph_max)
	{
		ereport(LOG,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("can not allocate enough memory for new entry in password history cache."),
				 errhint("You shoul increase yaspgpp.history_max_size.")));
		return NULL;
	}

	entry = (pgphEntry *)hash_search(pgph_hash, key, HASH_ENTER, &found);

	if (!found)
		entry->password_date = password_date;

	return entry;
}

static pgafEntry *pgaf_entry_alloc(pgafHashKey *key, float failure_count)
{
	pgafEntry *entry;
	bool found;

	if (hash_get_num_entries(pgaf_hash) >= pgph_max)
	{
		ereport(LOG,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("can not allocate enough memory for new entry in auth failure cache."),
				 errhint("You shoul increase yaspgpp.history_max_size.")));
		return NULL;
	}

	entry = (pgafEntry *)hash_search(pgaf_hash, key, HASH_ENTER, &found);

	if (!found)
	{
		entry->failure_count = failure_count;
		if (failure_count >= fail_max)
			entry->banned_date = GetCurrentTimestamp();
	}

	return entry;
}

static void flush_password_history(void)
{
	FILE *file;
	int32 num_entries;
	pgphEntry *entry;
	HASH_SEQ_STATUS hash_seq;

	if (!pgph || !pgph_hash)
		return;

	elog(DEBUG1, "flushing password history to file %s", PGPH_DUMP_FILE);

	file = AllocateFile(PGPH_DUMP_FILE ".tmp", PG_BINARY_W);
	if (file == NULL)
		goto error;

	if (fwrite(&PGPH_FILE_HEADER, sizeof(uint32), 1, file) != 1)
		goto error;
	if (fwrite(&PGPH_VERSION, sizeof(uint32), 1, file) != 1)
		goto error;
	num_entries = hash_get_num_entries(pgph_hash);
	if (fwrite(&num_entries, sizeof(int32), 1, file) != 1)
		goto error;

	hash_seq_init(&hash_seq, pgph_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (fwrite(entry, sizeof(pgphEntry), 1, file) != 1)
		{
			hash_seq_term(&hash_seq);
			goto error;
		}
	}

	fseek(file, 0, SEEK_END);
	while ((ftell(file) % BLCKSZ) != 0)
		putc(0, file);

	if (FreeFile(file))
	{
		file = NULL;
		goto error;
	}

	elog(DEBUG1, "history hash table written to disk");

	(void)durable_rename(PGPH_DUMP_FILE ".tmp", PGPH_DUMP_FILE, LOG);

	return;

error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not write password history file \"%s\": %m",
					PGPH_DUMP_FILE ".tmp")));
	if (file)
		FreeFile(file);

	unlink(PGPH_DUMP_FILE ".tmp");
}

static void pgaf_shmem_startup(void)
{
	bool found;
	HASHCTL info;

	pgaf = NULL;
	pgaf_hash = NULL;

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pgaf = ShmemInitStruct("pg_auth_failure_history",
						   sizeof(pgafSharedState),
						   &found);

	if (!found)
	{
		pgaf->lock = &(GetNamedLWLockTranche(PGAF_TRANCHE_NAME))->lock;
	}

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgafHashKey);
	info.entrysize = sizeof(pgafEntry);
	pgaf_hash = ShmemInitHash("pg_auth_failure_history hash",
							  pgaf_max, pgaf_max,
							  &info,
							  HASH_ELEM | HASH_BLOBS);

	LWLockRelease(AddinShmemInitLock);
}

PG_FUNCTION_INFO_V1(pg_password_history_reset);

Datum pg_password_history_reset(PG_FUNCTION_ARGS)
{
	char *username;
	int num_removed = 0;
	HASH_SEQ_STATUS hash_seq;
	pgphEntry *entry;

	if (!pgph || !pgph_hash)
		return 0;

	if (!superuser())
		ereport(ERROR, (errmsg("only superuser can reset password history")));

	if (PG_NARGS() > 0)
		username = PG_GETARG_CSTRING(0);
	else
		username = NULL;

	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgph_hash);

	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (username == NULL || strcmp(entry->key.rolename, username) == 0)
		{
			hash_search(pgph_hash, &entry->key, HASH_REMOVE, NULL);
			num_removed++;
		}
	}

	if (num_removed > 0)
		flush_password_history();

	LWLockRelease(pgph->lock);

	PG_RETURN_INT32(num_removed);
}

PG_FUNCTION_INFO_V1(pg_password_history);

Datum pg_password_history(PG_FUNCTION_ARGS)
{
	pg_password_history_internal(fcinfo);

	return (Datum)0;
}

static void pg_password_history_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *)fcinfo->resultinfo;
	TupleDesc tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	HASH_SEQ_STATUS hash_seq;
	pgphEntry *entry;

	if (!pgph || !pgph_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("yaspgpp must be loaded via shared_preload_libraries to use password history")));

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not allowed in this context")));

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	LWLockAcquire(pgph->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pgph_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum values[PG_PASSWORD_HISTORY_COLS];
		bool nulls[PG_PASSWORD_HISTORY_COLS];
		int i = 0;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = CStringGetDatum(entry->key.rolename);
		values[i++] = TimestampTzGetDatum(entry->password_date);
		values[i++] = CStringGetTextDatum(entry->key.password_hash);

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	LWLockRelease(pgph->lock);
}

PG_FUNCTION_INFO_V1(pg_password_history_timestamp);

Datum pg_password_history_timestamp(PG_FUNCTION_ARGS)
{
	char *username = PG_GETARG_CSTRING(0);
	TimestampTz new_timestamp = PG_GETARG_TIMESTAMPTZ(1);
	pgphEntry *entry;
	int num_changed = 0;
	HASH_SEQ_STATUS hash_seq;

	if (!pgph || !pgph_hash)
		return 0;

	if (!superuser())
		ereport(ERROR, (errmsg("only superuser can change timestamp in password history")));

	LWLockAcquire(pgph->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgph_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (strcmp(entry->key.rolename, username) == 0)
		{
			entry->password_date = new_timestamp;
			num_changed++;
		}
	}

	if (num_changed > 0)
		flush_password_history();

	LWLockRelease(pgph->lock);

	PG_RETURN_INT32(num_changed);
}

static void fix_log(ErrorData *edata)
{
	if (edata->elevel != ERROR)
	{
		if (prev_log_hook)
			(*prev_log_hook)(edata);
		return;
	}

	if (statement_has_password && no_password_logging)
		edata->hide_stmt = true;

	statement_has_password = false;

	if (prev_log_hook)
		(*prev_log_hook)(edata);
}

static void yaspgpp_max_auth_failure(Port *port, int status)
{
	if (status != STATUS_OK)
		pg_usleep(1000L * auth_delay_milliseconds);

	if (is_in_whitelist(port->user_name, max_auth_whitelist))
	{
		if (prev_ClientAuthentication)
			prev_ClientAuthentication(port, status);
		return;
	}

	if (fail_max > 0 && status != STATUS_EOF)
	{
		Oid userOid = get_role_oid(port->user_name, true);

		if (userOid != InvalidOid)
		{
			float fail_num = get_auth_failure(port->user_name, userOid, status);

			if (status == STATUS_ERROR && fail_num <= fail_max)
				fail_num = save_auth_failure(port, userOid);

			if (fail_num >= fail_max)
			{
				if (reset_superuser && userOid == 10)
					remove_auth_failure(port->user_name, userOid);
				else
					ereport(FATAL, (errmsg("rejecting connection, user '%s' has been banned", port->user_name)));
			}

			if (status == STATUS_OK && fail_num < fail_max)
				remove_auth_failure(port->user_name, userOid);
		}
	}

	if (prev_ClientAuthentication)
		prev_ClientAuthentication(port, status);
}

static float get_auth_failure(const char *username, Oid userid, int status)
{
	pgafHashKey key;
	pgafEntry *entry;
	float fail_cnt = 0;

	Assert(username != NULL);

	if (fail_max == 0)
		return 0;

	if (!pgaf || !pgaf_hash)
		return 0;

	key.roleid = userid;

	LWLockAcquire(pgaf->lock, LW_EXCLUSIVE);
	entry = (pgafEntry *)hash_search(pgaf_hash, &key, HASH_FIND, NULL);
	if (entry)
		fail_cnt = entry->failure_count;

	elog(DEBUG1, "Auth failure count for user %s is %f, fired by status: %d", username, fail_cnt, status);

	LWLockRelease(pgaf->lock);

	return fail_cnt;
}

static float save_auth_failure(Port *port, Oid userid)
{
	pgafHashKey key;
	pgafEntry *entry;
	float fail_cnt = 1;

	Assert(port->user_name != NULL);

	if (fail_max == 0)
		return 0;

	if (!pgaf || !pgaf_hash)
		return 0;

	key.roleid = userid;

	LWLockAcquire(pgaf->lock, LW_EXCLUSIVE);

	entry = (pgafEntry *)hash_search(pgaf_hash, &key, HASH_FIND, NULL);
	if (entry)
	{
		fail_cnt = entry->failure_count + 1;

		elog(DEBUG1, "Remove entry in auth failure hash table for user %s", port->user_name);
		hash_search(pgaf_hash, &entry->key, HASH_REMOVE, NULL);
	}
	elog(DEBUG1, "Add new entry in auth failure hash table for user %s (%d, %f)", port->user_name, userid, fail_cnt);

	entry = pgaf_entry_alloc(&key, fail_cnt);

	LWLockRelease(pgaf->lock);

	return fail_cnt;
}

static void remove_auth_failure(const char *username, Oid userid)
{
	pgafHashKey key;

	Assert(username != NULL);

	if (fail_max == 0)
		return;

	if (!pgaf || !pgaf_hash)
		return;

	key.roleid = userid;

	LWLockAcquire(pgaf->lock, LW_EXCLUSIVE);

	elog(DEBUG1, "Remove entry in auth failure hash table for user %s", username);
	hash_search(pgaf_hash, &key, HASH_REMOVE, NULL);

	LWLockRelease(pgaf->lock);
}

PG_FUNCTION_INFO_V1(pg_banned_role_reset);

Datum pg_banned_role_reset(PG_FUNCTION_ARGS)
{
	char *username;
	int num_removed = 0;
	HASH_SEQ_STATUS hash_seq;
	pgafEntry *entry;

	if (!pgaf || !pgaf_hash)
		return 0;

	if (!superuser())
		ereport(ERROR, (errmsg("only superuser can reset banned roles cache")));

	if (PG_NARGS() > 0)
		username = PG_GETARG_CSTRING(0);
	else
		username = NULL;

	LWLockAcquire(pgaf->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgaf_hash);

	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		if (username == NULL || (entry->key.roleid == get_role_oid(username, true)))
		{
			hash_search(pgaf_hash, &entry->key, HASH_REMOVE, NULL);
			num_removed++;
		}
	}

	LWLockRelease(pgaf->lock);

	PG_RETURN_INT32(num_removed);
}

PG_FUNCTION_INFO_V1(pg_banned_role);

Datum pg_banned_role(PG_FUNCTION_ARGS)
{
	pg_banned_role_internal(fcinfo);

	return (Datum)0;
}

static void pg_banned_role_internal(FunctionCallInfo fcinfo)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *)fcinfo->resultinfo;
	TupleDesc tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	HASH_SEQ_STATUS hash_seq;
	pgafEntry *entry;

	if (!pgaf || !pgaf_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("yaspgpp must be loaded via shared_preload_libraries to use auth failure feature")));

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not allowed in this context")));

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	LWLockAcquire(pgaf->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pgaf_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum values[PG_BANNED_ROLE_COLS];
		bool nulls[PG_BANNED_ROLE_COLS];
		int i = 0;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = ObjectIdGetDatum(entry->key.roleid);
		values[i++] = Int8GetDatum(entry->failure_count);
		if (entry->banned_date)
			values[i++] = TimestampTzGetDatum(entry->banned_date);
		else
			nulls[i++] = true;

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	LWLockRelease(pgaf->lock);
}
