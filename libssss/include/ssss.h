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
