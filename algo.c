/*
 *  ssss version 0.5                         -  Copyright 2005,2006 B. Poettering
 *  ssss version 0.5.1..0.5.4 (changes only) -  Copyright 2011,2013 Jon D. Frisby
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

#include <gmp.h>
#include "ssss.h"
#include "field.h"

/* evaluate polynomials efficiently
 * Note that this implementation adds an additional x^k term. This term is
 * subtracted off on recombining. This additional term neither adds nor removes
 * security but is left solely for legacy reasons.
 */

void horner(field *f, int n, mpz_t y, const mpz_t x, const mpz_t coeff[])
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

int restore_secret(const field *f,
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
