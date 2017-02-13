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

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "ssss.h"

#define RANDOM_SOURCE "/dev/urandom"

/* routines for the random number generator */

typedef struct {
	int cprng;
} ssss_cprng_impl;

int cprng_read(void *data, uint8_t *buf, size_t len)
{
  int cprng = ((ssss_cprng_impl*)data)->cprng;
  size_t count;
  int i;
  for(count = 0; count < len; count += i) {
    if ((i = read(cprng, buf + count, len - count)) < 0) {
      close(cprng);
      return i;
    }
  }
  return 0;
}

ssss_cprng* ssss_cprng_alloc()
{
  ssss_cprng_impl *impl =
    (ssss_cprng_impl*)malloc(sizeof(ssss_cprng_impl));
  impl->cprng = open(RANDOM_SOURCE, O_RDONLY);

  ssss_cprng *cprng =
    (ssss_cprng*)malloc(sizeof(ssss_cprng));
  cprng->data = (void*)impl;
  cprng->read  = cprng_read;
  return cprng;
}

void ssss_cprng_free(ssss_cprng* cprng)
{
  ssss_cprng_impl *impl = (ssss_cprng_impl*)cprng->data;
  close(impl->cprng);
  free(impl);
  free(cprng);
}
