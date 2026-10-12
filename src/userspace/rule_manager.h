#ifndef __RULE_MANAGER_H__
#define __RULE_MANAGER_H__

#include <stdint.h>
#include "../../include/aegis_types.h"

/* CIDR parsing */
int parse_cidr(const char *cidr_str, struct lpm_ip4_key *key);

/* IP Blacklist & Whitelist Management */
int rule_ip_add(const char *pin_path, const char *cidr_str, enum aegis_action action);
int rule_ip_del(const char *pin_path, const char *cidr_str);
int rule_ip_list(const char *pin_path, const char *table_name);

/* L4 Protocol / Port Rule Management */
int rule_l4_add(const char *proto_str, uint16_t port, enum aegis_action action);
int rule_l4_del(const char *proto_str, uint16_t port);
int rule_l4_list(void);

/* Listening Service Ports Management (For Methods 6 & 7) */
int port_allow(const char *proto_str, uint16_t port);
int port_disallow(const char *proto_str, uint16_t port);
int port_list(const char *proto_str);

/* Dynamic Ban Management (Method 10) */
int dynamic_ban_list(void);
int dynamic_ban_clear(const char *ip_str);

/* Feature Toggles (Enable/Disable individual defense methods) */
int feature_toggle(const char *feat_name, int enable);
int feature_list(void);

/* Default Policy Management */
int policy_set(enum aegis_action default_action);
int policy_get(void);

#endif /* __RULE_MANAGER_H__ */
