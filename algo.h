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

#ifndef ALGO_H
#define ALGO_H

#include <gmp.h>
#include "field.h"

/* evaluate polynomials efficiently
 * Note that this implementation adds an additional x^k term. This term is
 * subtracted off on recombining. This additional term neither adds nor removes
 * security but is left solely for legacy reasons.
 */

void horner(field *f, int n, mpz_t y, const mpz_t x, const mpz_t coeff[]);

/* calculate the secret from a set of shares solving a linear equation system */
int restore_secret(const field *f,
                   int n,
#ifdef USE_RESTORE_SECRET_WORKAROUND
                   void *A,
#else
                   mpz_t (*A)[n],
#endif
                   mpz_t b[]);

#endif
