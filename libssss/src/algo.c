/*
 *  ssss version 0.5                         -  Copyright 2005,2006 B. Poettering
 *  ssss version 0.5.1..0.5.4 (changes only) -  Copyright 2011,2013 Jon D. Frisby
 *  ssss version 0.5.6 (libssss)             -  Copyright 2016,2017 Hiroaki Mizuguchi
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

/*
 * http://point-at-infinity.org/ssss/
 * https://github.com/MrJoy/ssss
 *
 * This is an implementation of Shamir's Secret Sharing Scheme. See
 * the project's homepage http://point-at-infinity.org/ssss/ for more
 * information on this topic.
 *
 * This code links against the GNU multiprecision library "libgmp".
 * Original author compiled the code successfully with gmp 4.1.4.
 * Jon Frisby compiled the code successfully with gmp 5.0.2.
 *
 * You will need a system that has a /dev/random entropy source.
 *
 * Compile with
 * "gcc -O2 -lgmp -o ssss-split ssss.c && ln ssss-split ssss-combine"
 *
 * Compile with -DNOMLOCK to obtain a version without memory locking.
 *
 * If you encounter compile issues, compile with USE_RESTORE_SECRET_WORKAROUND.
 *
 * Report bugs to: ssss AT point-at-infinity.org
 * Also report compilation / usability issues to: jfrisby AT mrjoy.com
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "ssss.h"
#include "field.h"

/* evaluate polynomials efficiently
 * Note that this implementation adds an additional x^k term. This term is
 * subtracted off on recombining. This additional term neither adds nor removes
 * security but is left solely for legacy reasons.
 */

static void horner(field *f, int n, mpz_t y, const mpz_t x, const mpz_t coeff[])
{
  int i;
  mpz_set(y, x);
  for(i = n - 1; i; i--) {
    field_add(y, y, coeff[i]);
    field_mult(f, y, y, x);
  }
  field_add(y, y, coeff[0]);
}

/* calculate the secret from a set of shares solving a linear equation system */

#define MPZ_SWAP(A, B) \
  do { mpz_set(h, A); mpz_set(A, B); mpz_set(B, h); } while(0)

static int restore_secret(const field *f,
                   int n,
#ifdef USE_RESTORE_SECRET_WORKAROUND
                   void *A,
#else
                   mpz_t (*A)[n],
#endif
                   mpz_t b[])
{
  mpz_t (*AA)[n] = (mpz_t (*)[n])A;
  int i, j, k, found;
  mpz_t h;
  mpz_init(h);
  for(i = 0; i < n; i++) {
    if (! mpz_cmp_ui(AA[i][i], 0)) {
      for(found = 0, j = i + 1; j < n; j++)
        if (mpz_cmp_ui(AA[i][j], 0)) {
          found = 1;
          break;
        }
      if (! found)
        return -1;
      for(k = i; k < n; k++)
        MPZ_SWAP(AA[k][i], AA[k][j]);
      MPZ_SWAP(b[i], b[j]);
    }
    for(j = i + 1; j < n; j++) {
      if (mpz_cmp_ui(AA[i][j], 0)) {
        for(k = i + 1; k < n; k++) {
          field_mult(f, h, AA[k][i], AA[i][j]);
          field_mult(f, AA[k][j], AA[k][j], AA[i][i]);
          field_add(AA[k][j], AA[k][j], h);
        }
        field_mult(f, h, b[i], AA[i][j]);
        field_mult(f, b[j], b[j], AA[i][i]);
        field_add(b[j], b[j], h);
      }
    }
  }
  field_invert(f, h, AA[n - 1][n - 1]);
  field_mult(f, b[n - 1], b[n - 1], h);
  mpz_clear(h);
  return 0;
}

size_t ssss_size_share(size_t secret)
{
  return secret + sizeof(ssss_index_t)*2;
}

int ssss_split(const uint8_t *secret, uint8_t *shares, size_t len_secret, ssss_index_t share, size_t threshold, ssss_cprng *cprng)
{
  char is_default_cprng = 0;
  int ret = 0;
  ssss_index_t i;
  // check arguments
  if (secret == NULL) return -1;
  if (shares == NULL) return -2;
  if (len_secret <= 0) return -3;
  if (share <= 0) return -4;
  if (threshold <= 0 || threshold > share) return -5;
  if (cprng == NULL) {
    cprng = ssss_cprng_alloc();
    if (cprng == NULL) return -6;
    is_default_cprng = 1;
  }

  uint8_t *buf = (uint8_t*)malloc(len_secret);
  if (buf == NULL) {
    ret = 1;
    goto err_buf;
  }

  field f;
  field_init(&f, len_secret * 8);
  mpz_t *a, y, x;
  a = (mpz_t*)malloc(sizeof(mpz_t)*threshold);
  if (a == NULL) {
    ret = 2;
    goto err_a;
  }
  for (i = 0; i < threshold; ++i)
    mpz_init(a[i]);

  mpz_init(y);
  mpz_init(x);

  // setup a[]
  mpz_import (a[0], len_secret, 1, 1, 0, 0, secret);
  for (i = 1; i < threshold; ++i) {
    if (cprng->read(cprng->data, buf, len_secret)) {
      ret = 3;
      goto err_read;
    }
    mpz_import(a[i], len_secret, 1, 1, 0, 0, buf);
  }

  uint8_t *ptr;
  size_t len_share = ssss_size_share(len_secret);
  for (i = 0, ptr = shares; i < share; ++i, ptr += len_share) {
    mpz_set_ui(x, i + 1);
    horner(&f, threshold, y, x, (const mpz_t*)a);
    ssss_index_t *meta = (ssss_index_t*)ptr;
    meta[0] = threshold;
    meta[1] = i + 1;
    mpz_export(ptr + sizeof(ssss_index_t)*2, NULL, 1, 1, 0, 0, y);
  }

  mpz_clear(x);
  mpz_clear(y);
  for (i = 0; i < threshold; ++i)
    mpz_clear(a[i]);
err_read:
  free(a);
err_a:
  free(buf);
err_buf:
  if (is_default_cprng) ssss_cprng_free(cprng);
  return ret;
}

int ssss_combine(const uint8_t *shares, uint8_t *secret, size_t len_secret, ssss_index_t threshold)
{
  int ret = 0;
  ssss_index_t i,j;
  // check arguments
  if (shares == NULL) return -1;
  if (secret == NULL) return -2;
  if (len_secret <= 0) return -3;
  if (threshold <= 0) return -4;

  // initialize variables
  mpz_t A[threshold][threshold], y[threshold], x;
  for(i = 0; i < threshold; ++i) {
    for (j = 0; j < threshold; ++j)
      mpz_init(A[i][j]);
    mpz_init(y[i]);
  }
  mpz_init(x);
  field f;
  field_init(&f, len_secret * 8);

  const uint8_t *ptr;
  size_t len_share = ssss_size_share(len_secret);
  for (i = 0, ptr = shares; i < threshold; ++i, ptr += len_share) {
    ssss_index_t *meta = (ssss_index_t*)ptr;
    if (meta[0] > threshold) {
      ret = -1;
      goto clean;
    }
    mpz_set_ui(x, meta[1]);
    mpz_set_ui(A[threshold - 1][i], 1);
    j = threshold - 2;
    do {
      field_mult(&f, A[j][i], A[j+1][i], x);
    }while(j-- > 0);
    mpz_import(y[i], len_secret, 1, 1, 0, 0, ptr + sizeof(ssss_index_t)*2);
    //
    field_mult(&f, x, x, A[0][i]);
    field_add(y[i], y[i], x);
  }

  ret = restore_secret(&f, threshold, A, y);
  if (ret != 0) goto clean;

  mpz_export(secret, NULL, 1, 1, 0, 0, y[threshold - 1]);

clean:
  // release resource
  field_deinit(&f);
  for(i = 0; i < threshold; ++i) {
    for (j = 0; j < threshold; ++j)
      mpz_clear(A[i][j]);
    mpz_clear(y[i]);
  }
  mpz_clear(x);
  return ret;
}

