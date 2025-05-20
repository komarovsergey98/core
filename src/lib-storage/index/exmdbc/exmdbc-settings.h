#ifndef EXMDBC_SETTINGS_H
#define EXMDBC_SETTINGS_H


/* IMAP RFC defines this to be at least 30 minutes. */
#define IMAPC_DEFAULT_MAX_IDLE_TIME (60*29)
/* </settings checks> */

/*
 * NOTE: Any additions here should be reflected in imapc_storage_create's
 * serialization of settings.
 */

extern const struct setting_parser_info exmdbc_setting_parser_info;

#endif
