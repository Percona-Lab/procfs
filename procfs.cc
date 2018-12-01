#include <m_ctype.h>                    /* my_charset_bin */
#include <mysql_version.h>
#if MYSQL_VERSION_ID >= 80002
#include <sql/sql_class.h>                  /* THD, Security context */
#include <sql/item_cmpfunc.h>
#include <mf_wcomp.h>
#else
#include <sql_class.h>                  /* THD, Security context */
#include <item_cmpfunc.h>
#endif
#include <mysql/psi/mysql_thread.h>

#include <stdlib.h>
#include <glob.h>
#include <time.h>
#include <ctype.h>
#include <mysql/plugin.h>

#include <fstream>
#define IS_PROCFS_CONTENTS_SIZE 60000
#define IS_PROCFS_REFRESH_IN_SECONDS 60

bool schema_table_store_record(THD *thd, TABLE *table);
extern struct st_mysql_information_schema procfs_view;


struct st_mysql_information_schema
procfs_view={MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION};
MYSQL_PLUGIN procfs_plugin_info= 0;

static ST_FIELD_INFO procfs_view_fields[]=
{
  {"file", 1024,  MYSQL_TYPE_STRING, 0, MY_I_S_UNSIGNED, 0, 0},
  {"contents", IS_PROCFS_CONTENTS_SIZE , MYSQL_TYPE_STRING, 0, MY_I_S_UNSIGNED, 0, 0},
  {0, 0, MYSQL_TYPE_NULL, 0, 0, 0, 0}
};

static mysql_rwlock_t LOCK_procfs_files;

#ifdef HAVE_PSI_INTERFACE
PSI_rwlock_key key_rwlock_LOCK_procfs_files;

static PSI_rwlock_info all_procfs_rwlocks[]=
{
  { &key_rwlock_LOCK_procfs_files, "LOCK_plugin_procfs", 0 }
};

static void init_procfs_psi_keys()
{
  const char* category= "procfs";
  int count;

  count= array_elements(all_procfs_rwlocks);
  mysql_rwlock_register(category, all_procfs_rwlocks, count);
}
#endif

namespace procfs_plugin {
  std::vector<std::string> files;
  time_t files_last_updated_at;
}


  static
bool get_equal_condition_argument(Item *cond, std::string *eq_arg,
    const std::string &field_name)
{
  if (cond != 0 && cond->type() == Item::FUNC_ITEM)
  {
    Item_func *func= static_cast<Item_func *>(cond);
    if (func != NULL && func->functype() == Item_func::EQ_FUNC)
    {
      Item_func_eq* eq_func= static_cast<Item_func_eq*>(func);
      if (eq_func->arguments()[0]->type() == Item::FIELD_ITEM &&
          my_strcasecmp(system_charset_info,
            eq_func->arguments()[0]->full_name(),
            field_name.c_str()) == 0)
      {
        char buff[1024];
        String *res;
        String filter(buff, sizeof(buff), system_charset_info);
        if (eq_func->arguments()[1] != NULL &&
            (res= eq_func->arguments()[1]->val_str(&filter)))
        {
          eq_arg->append(res->c_ptr_safe(), res->length());
          return false;
        }
      }
    }
  }
  return true;
}

  static
bool get_like_condition_argument(Item *cond, std::string *like_arg,
    const std::string &field_name)
{
  if (cond != 0 && cond->type() == Item::FUNC_ITEM)
  {
    Item_func *func= static_cast<Item_func *>(cond);
    if (func != NULL && func->functype() == Item_func::LIKE_FUNC)
    {
      Item_func_like* like_func= static_cast<Item_func_like*>(func);
      if (like_func->arguments()[0]->type() == Item::FIELD_ITEM &&
          my_strcasecmp(system_charset_info,
            like_func->arguments()[0]->full_name(),
            field_name.c_str()) == 0)
      {
        char buff[1024];
        String *res;
        String filter(buff, sizeof(buff), system_charset_info);
        if (like_func->arguments()[1] != NULL &&
            (res= like_func->arguments()[1]->val_str(&filter)))
        {
          like_arg->append(res->c_ptr_safe(), res->length());
          return false;
        }
      }
    }
  }
  return true;
}


static bool get_in_condition_argument(Item *cond, std::map<std::string, bool> &in_args,
    const std::string &field_name)
{
  if (cond != 0 && cond->type() == Item::FUNC_ITEM)
  {
    Item_func *func= static_cast<Item_func *>(cond);
    if (func != NULL && func->functype() == Item_func::IN_FUNC)
    {
      Item_func_in* in_func= static_cast<Item_func_in*>(func);
      if (in_func->arguments()[0]->type() == Item::FIELD_ITEM &&
          my_strcasecmp(system_charset_info,
            in_func->arguments()[0]->full_name(),
            field_name.c_str()) == 0)
      {
        char buff[1024];
        String *res;
        String filter(buff, sizeof(buff), system_charset_info);
        for (uint i = 1; i < in_func->arg_count; ++i) {
          if (in_func->arguments()[i] != NULL &&
              (res= in_func->arguments()[i]->val_str(&filter))
              && res->length() > 0)
          {
            in_args[std::string(res->c_ptr_safe(), res->length())] = true;
          }
        }
        return false;
      }
    }
  }
  return true;
}

static size_t read_file_to_buf(const char* fname, char* buf)
{
  std::ifstream f(fname);
  if (!f || !f.is_open())
    return 0;
  f.read(buf, IS_PROCFS_CONTENTS_SIZE);
  size_t sz = f.gcount();
  f.close();
  return sz;
}

static void fill_procfs_view_row(THD *thd, TABLE *table, const char* fname, char* buf, size_t sz)
{
  if (sz == 0)
    return;

  table->field[0]->store(fname, strlen(fname), system_charset_info);
  table->field[1]->store(buf, sz, system_charset_info);
  schema_table_store_record(thd, table);
}

static void fill_files_list()
{
  time_t ts = time(NULL);


  mysql_rwlock_rdlock(&LOCK_procfs_files);
  if (ts < procfs_plugin::files_last_updated_at + IS_PROCFS_REFRESH_IN_SECONDS)
  {
    mysql_rwlock_unlock(&LOCK_procfs_files);
    return;
  }
  mysql_rwlock_unlock(&LOCK_procfs_files);

  mysql_rwlock_wrlock(&LOCK_procfs_files);
  if (ts < procfs_plugin::files_last_updated_at + IS_PROCFS_REFRESH_IN_SECONDS)
  {
    mysql_rwlock_unlock(&LOCK_procfs_files);
    return;
  }

  procfs_plugin::files_last_updated_at = ts;

  std::ifstream procfs_cnf("procfs.cnf");

  procfs_plugin::files.clear();
  while(procfs_cnf)
  {
    std::string path;
    std::getline(procfs_cnf, path);
    if (path.rfind("/proc", 0) != 0 && path.rfind("/sys", 0) != 0)
      continue;

    if (path.find('*') == std::string::npos && path.find('{') == std::string::npos)
    {
      procfs_plugin::files.push_back(path);
      continue;
    }

    glob_t globbuf;
    globbuf.gl_offs = 0;
    int res = glob(path.c_str(), GLOB_DOOFFS | GLOB_BRACE | GLOB_MARK, NULL, &globbuf);
    if (res == GLOB_NOMATCH || res == GLOB_ABORTED || res == GLOB_NOSPACE) {
      globfree(&globbuf);
      continue;
    }
    for (size_t i = 0; i < globbuf.gl_pathc; ++i)
    {
      if (globbuf.gl_pathv[i] == NULL)
        continue;
      int len = strlen(globbuf.gl_pathv[i]);
      if (len == 0 || globbuf.gl_pathv[i][len-1] == '/')
        continue;
      procfs_plugin::files.push_back(std::string(globbuf.gl_pathv[i]));
    }
    globfree(&globbuf);
    continue;
  }
  mysql_rwlock_unlock(&LOCK_procfs_files);

  procfs_cnf.close();
}

static int fill_procfs_view(THD *thd,
    TABLE_LIST *tables,
    Item *cond)
{
  TABLE *table= tables->table;
  char* buf = static_cast<char*>(my_malloc(PSI_NOT_INSTRUMENTED,
        IS_PROCFS_CONTENTS_SIZE, MY_ZEROFILL));

  std::string I_S_PROCFS_FILE ("information_schema.procfs.file");
  std::string like_arg;

  std::map<std::string, bool> in_args;

  fill_files_list();

  if (cond != 0)
  {
    std::string eq_arg;
    if (!get_equal_condition_argument(cond, &eq_arg, I_S_PROCFS_FILE) && !eq_arg.empty())
    {
      in_args[eq_arg] = true;
    }
    else if (!get_like_condition_argument(cond, &like_arg, I_S_PROCFS_FILE) && !like_arg.empty()) {
    }
    else
    {
      get_in_condition_argument(cond, in_args, I_S_PROCFS_FILE);
    }
  }

  mysql_rwlock_rdlock(&LOCK_procfs_files);
  for(std::vector<std::string>::const_iterator fname
      = procfs_plugin::files.begin(); fname != procfs_plugin::files.end(); ++fname) {
    if (cond != 0 && in_args.size() > 0 && in_args.find(*fname) == in_args.end())
      continue;
#if MYSQL_VERSION_ID >= 80002
    if (cond != 0 && like_arg.size() > 0 &&
        wild_compare(fname->c_str(), fname->size(), like_arg.c_str(), like_arg.size(), 0) )
      continue;
#else
    if (cond != 0 && like_arg.size() > 0 &&
        wild_compare(fname->c_str(), like_arg.c_str(), 0) )
      continue;
#endif
    size_t sz = read_file_to_buf(fname->c_str(), buf);
    fill_procfs_view_row(thd, table, fname->c_str(), buf, sz);
  }
  mysql_rwlock_unlock(&LOCK_procfs_files);

  my_free(buf);

  return false;
}

static int procfs_view_init(void *ptr)
{
#ifdef HAVE_PSI_INTERFACE
  init_procfs_psi_keys();
#endif
  mysql_rwlock_init(key_rwlock_LOCK_procfs_files, &LOCK_procfs_files);

  ST_SCHEMA_TABLE *schema_table= (ST_SCHEMA_TABLE *)ptr;

  schema_table->fields_info= procfs_view_fields;
  schema_table->fill_table= fill_procfs_view;
  schema_table->idx_field1= 0;
  schema_table->idx_field2= 1;

  procfs_plugin::files_last_updated_at = 0;

  return 0;
}

static int procfs_view_deinit(void*) {
  procfs_plugin::files.clear();
  procfs_plugin::files_last_updated_at = 0;
  mysql_rwlock_destroy(&LOCK_procfs_files);
  return 0;
}

mysql_declare_plugin(procfs)
{
  MYSQL_INFORMATION_SCHEMA_PLUGIN,                  /* type                            */
    &procfs_view,                                    /* descriptor                      */
    "procfs",                                        /* name                            */
    "Percona Inc",                                   /* author                          */
    "I_S table providing a view /proc/ statistics",  /* description                     */
    PLUGIN_LICENSE_GPL,                              /* plugin license                  */
    procfs_view_init,                                /* init function (when loaded)     */
#if MYSQL_VERSION_ID >= 80002
    NULL,                                            /* check uninstall function        */
#endif
    procfs_view_deinit,                              /* deinit function (when unloaded) */
    0x0100,                                          /* version                         */
    NULL,                                            /* status variables                */
    NULL,                                            /* system variables                */
    NULL,
    0
}
mysql_declare_plugin_end;
