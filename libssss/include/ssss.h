#ifndef LIBSSSS_H
#define LIBSSSS_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t ssss_index_t;

typedef struct {
  void *data;
  int (*read)(void *data, uint8_t *buf, size_t len);
} ssss_cprng;

ssss_cprng* ssss_cprng_alloc();
void ssss_cprng_free(ssss_cprng*);

enum encdec {ENCODE, DECODE};

/* a 64 bit pseudo random permutation (based on the XTEA cipher) */
void ssss_encode_mpz(size_t bytes, uint8_t *buf, enum encdec encdecmode);

size_t ssss_size_share(size_t len);
int ssss_combine(const uint8_t *shares, uint8_t *secret, size_t len_secret, ssss_index_t threshold);
int ssss_split(const uint8_t *secret, uint8_t *shares, size_t len_secret, ssss_index_t share, size_t threshold, ssss_cprng *cprng);

#endif
