/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NABU_LOG_WATCH_H
#define NABU_LOG_WATCH_H
#ifdef __cplusplus
extern "C" {
#endif
/* Called only from the ordinary writer, outside its transport lock. */
void nabu_boot_watch_poll(void);
void nabu_data_mount_progress(unsigned stage, int status);
#ifdef __cplusplus
}
#endif
#endif
