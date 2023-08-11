#include "includes.h"
#include "system/filesys.h"
#include "winbindd.h"
#include "tdb_validate.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_winbind.h"
#include "ads.h"
#include "nss_info.h"
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"
#include "util_tdb.h"
#include "libsmb/samlogon_cache.h"
#include "lib/namemap_cache.h"

static bool (*s_winbindd_state_offline)(void);
/* source3/winbindd/winbindd_cache.c */
void set_winbindd_state_offline(bool (*f)(void)) {
	s_winbindd_state_offline = f;
}
bool call_winbindd_state_offline(void) {
	return (*s_winbindd_state_offline)();
}

static struct winbindd_domain* (*s_find_domain_from_name)(const char *domain_name);
/* source3/winbindd/winbindd_util.c */
void set_find_domain_from_name(struct winbindd_domain* (*f)(const char *domain_name)) {
	s_find_domain_from_name = f;
}
struct winbindd_domain* call_find_domain_from_name(const char *domain_name) {
	return (*s_find_domain_from_name)(domain_name);
}

static bool (*s_wcache_tdc_fetch_list)( struct winbindd_tdc_domain **domains, size_t *num_domains );
/* source3/winbindd/winbindd_cache.c */
void set_wcache_tdc_fetch_list(bool (*f)( struct winbindd_tdc_domain **domains, size_t *num_domains )) {
	s_wcache_tdc_fetch_list = f;
}
bool call_wcache_tdc_fetch_list( struct winbindd_tdc_domain **domains, size_t *num_domains ) {
	return (*s_wcache_tdc_fetch_list)(domains, num_domains);
}

static NTSTATUS (*s_smb_register_idmap_nss)(int version, const char *name, struct nss_info_methods *methods);
/* source3/winbindd/nss_info.c */
void set_smb_register_idmap_nss (NTSTATUS (*f)(int version, const char *name, struct nss_info_methods *methods)) {
	s_smb_register_idmap_nss = f;
}
NTSTATUS call_smb_register_idmap_nss(int version, const char *name, struct nss_info_methods *methods) {
	return (*s_smb_register_idmap_nss)(version, name, methods);
}

static struct winbindd_domain* (*s_find_our_domain)(void);
/* source3/winbindd/winbindd_util.c */
void set_find_our_domain(struct winbindd_domain* (*f)(void)){
	s_find_our_domain = f;
}
struct winbindd_domain* call_find_our_domain(void) {
	return (*s_find_our_domain)();
}

bool (*s_domain_has_idmap_config)(const char *domname);
/* source3/winbindd/idmap.c */
void set_domain_has_idmap_config( bool (*f)(const char *domname)){
	s_domain_has_idmap_config = f;
}
bool call_domain_has_idmap_config(const char *domname){
	return (*s_domain_has_idmap_config)(domname);
}

NTSTATUS (*s_smb_register_idmap)(int version, const char *name, struct idmap_methods *methods);
/* source3/winbindd/nss_info.c */
void set_smb_register_idmap (NTSTATUS (*f)(int version, const char *name,
			    struct idmap_methods *methods)){
	s_smb_register_idmap = f;
}
NTSTATUS call_smb_register_idmap(int version, const char *name, struct idmap_methods *methods) {
	return (*s_smb_register_idmap)(version, name, methods);
}
				
static bool (*s_netsamlogon_cache_have)(const struct dom_sid *sid);
/* source3/winbindd/winbindd_cache.c */
void set_netsamlogon_cache_have(bool (*f)(const struct dom_sid *sid)){
	s_netsamlogon_cache_have = f;
}
bool call_netsamlogon_cache_have(const struct dom_sid *sid){
	return (*s_netsamlogon_cache_have)(sid);
}
