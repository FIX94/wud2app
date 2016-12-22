
#ifndef _WUDPARTS_H_
#define _WUDPARTS_H_

bool wudparts_open(const char *path);
size_t wudparts_read(void *buf, size_t len);
uint64_t wudparts_tell();
void wudparts_seek(uint64_t offset);
void wudparts_close();

#endif
