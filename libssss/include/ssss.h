#ifndef LIBSSSS_H
#define LIBSSSS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  void *data;
  int (*read)(void *data, uint8_t *buf, size_t len);
} ssss_cprng;

ssss_cprng* ssss_cprng_alloc();
void ssss_cprng_free(ssss_cprng*);

int ssss_split(ssss_cprng* rand, int n, int t, size_t len, uint8_t *secret, uint8_t *share);
int ssss_combine(int t, size_t len, uint8_t *secret, uint8_t *share);

#endif
