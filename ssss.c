/*
 *  ssss version 0.5                    -  Copyright 2005,2006 B. Poettering
 *  ssss version 0.5.1+ (changes only)  -  Copyright held by respective contributors
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
 * Jon Frisby compiled the code successfully with gmp 5.0.2, and 6.1.2.
 *
 * You will need a system that has a /dev/urandom entropy source.
 *
 * Compile with -DNOMLOCK to obtain a version without memory locking.
 *
 * If you encounter compile issues, compile with USE_RESTORE_SECRET_WORKAROUND.
 *
 * Report bugs to: ssss AT point-at-infinity.org
 * Also report compilation / usability issues to: jfrisby AT mrjoy.com
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <termios.h>
#include <sys/mman.h>

#include <gmp.h>
#include <ssss.h>
#include "ssss.h"

int opt_showversion = 0;
int opt_help = 0;
int opt_quiet = 0;
int opt_QUIET = 0;
int opt_hex = 0;
int opt_diffusion = 1;
int opt_security = 0;
int opt_threshold = -1;
int opt_number = -1;
char *opt_token = NULL;
char *ssss_errmsg = NULL;

struct termios echo_orig, echo_off;

/* emergency abort and warning functions */

void fatal(char *msg)
{
  tcsetattr(0, TCSANOW, &echo_orig);
  fprintf(stderr, "%sFATAL: %s.\n", isatty(2) ? "\a" : "", msg);
  exit(1);
}

void warning(char *msg)
{
  if (! opt_QUIET)
    fprintf(stderr, "%sWARNING: %s.\n", isatty(2) ? "\a" : "", msg);
}

/* I/O routines for GF(2^deg) field elements */

void str_import(uint8_t *bin, size_t len, const char *s, int hexmode)
{
  size_t l = strlen(s);
  if (hexmode) {
    mpz_t x;
    mpz_init(x);
    if (l > len * 2)
      fatal("input string too long");
    if (l < len * 2)
      warning("input string too short, adding null padding on the left");
    if (mpz_set_str(x, s, 16) || (mpz_cmp_ui(x, 0) < 0))
      fatal("invalid syntax");
    if (len < (mpz_sizeinbase(x, 2) + 7)/8 )
      fatal("input number too big");
    mpz_export(bin, NULL, 1, 1, 0, 0, x);
    mpz_clear(x);
  }
  else {
    int i;
    int warn = 0;
    if (l > len)
      fatal("input string too long");
    for(i = l - 1; i >= 0; i--)
      warn = warn || (s[i] < 32) || (s[i] >= 127);
    if (warn)
      warning("binary data detected, use -x mode instead");
    memset(bin, 0, len);
    memcpy(bin, s, l);
  }
}

void str_print(FILE* stream, const uint8_t *buf, size_t len, int hexmode)
{
  int i;
  if (hexmode) {
    mpz_t x;
    mpz_init(x);
    mpz_import(x, len, 1, 1, 0, 0, buf);
    for(i = len * 2 - mpz_sizeinbase(x, 16); i; i--)
      fprintf(stream, "0");
    mpz_out_str(stream, 16, x);
    mpz_clear(x);
    fprintf(stream, "\n");
  }
  else {
    unsigned int i;
    int printable, warn = 0;
    for(i = 0; i < len; i++) {
      printable = (buf[i] >= 32) && (buf[i] < 127);
      warn = warn || ! printable;
      fprintf(stream, "%c", printable ? buf[i] : '.');
    }
    fprintf(stream, "\n");
    if (warn)
      warning("binary data detected, use -x mode instead");
  }
}

/* Prompt for a secret, generate shares for it */

void split(void)
{
  char buf[MAXLINELEN];
  if (! opt_quiet) {
    fprintf(stderr, "Generating shares using a (%d,%d) scheme with ",
            opt_threshold, opt_number);
    if (opt_security)
      fprintf(stderr, "a %d bit", opt_security);
    else
      fprintf(stderr, "dynamic");
    fprintf(stderr, " security level.\n");

    int deg = opt_security ? opt_security : MAXDEGREE;
    fprintf(stderr, "Enter the secret, ");
    if (opt_hex)
      fprintf(stderr, "as most %d hex digits: ", deg / 4);
    else
      fprintf(stderr, "at most %d ASCII characters: ", deg / 8);
  }
  tcsetattr(0, TCSANOW, &echo_off);
  if (! fgets(buf, sizeof(buf), stdin))
    fatal("I/O error while reading secret");
  tcsetattr(0, TCSANOW, &echo_orig);
  fprintf(stderr, "\n");
  buf[strcspn(buf, "\r\n")] = '\0';

  if (! opt_security) {
    opt_security = opt_hex ? 4 * ((strlen(buf) + 1) & ~1): 8 * strlen(buf);
    if (opt_security % 8 != 0 || opt_security < 8)
      fatal("security level invalid (secret too long?)");
    if (! opt_quiet)
      fprintf(stderr, "Using a %d bit security level.\n", opt_security);
  }

  ssss_cprng *cprng = ssss_cprng_alloc();
  if (cprng == NULL)
    fatal("Can't setup cprng");

  size_t len_secret = opt_security / 8;
  if (opt_security % 8 != 0) len_secret++;
  uint8_t *secret = calloc(1, len_secret);
  if (secret == NULL)
    fatal("Can't allocation memory");
  size_t len_share  = ssss_size_share(len_secret);
  uint8_t *shares = calloc(1, len_share*opt_number);
  if (shares == NULL)
    fatal("Can't allocation memory");

  str_import(secret, len_secret, buf, opt_hex);

  if (opt_diffusion) {
    if (len_secret >= 8 )
      ssss_encode_mpz(len_secret, secret, ENCODE);
    else
      warning("security level too small for the diffusion layer");
  }

  int ret ;
  if (ret = ssss_split(secret, shares, len_secret, opt_number, opt_threshold, cprng))
  {
	  printf("%d ", ret);
	fatal("invalid");
  }

  unsigned int fmt_len;
  int i;
  for(fmt_len = 1, i = opt_number; i >= 10; i /= 10, fmt_len++);
  uint8_t *ptr;
  for(i = 0,ptr = shares; i < opt_number; i++, ptr += len_share) {
    if (opt_token)
      fprintf(stdout, "%s-", opt_token);
    ssss_index_t *idx = (ssss_index_t*)ptr;
    fprintf(stdout, "%0*d-", fmt_len, idx[1]);
    str_print(stdout, (uint8_t*)&(idx[2]), len_secret, 1);
  }

  memset(secret, 0, len_secret);
  free(shares);
  free(secret);
  ssss_cprng_free(cprng);
}

/* Prompt for shares, calculate the secret */

void combine(void)
{
	char buf[MAXLINELEN];
	int i;
	size_t len_secret = 0;
	size_t len_share = 0;
	uint8_t *shares = NULL;
	uint8_t *ptr = NULL;

	if (! opt_quiet)
		fprintf(stderr, "Enter %d shares separated by newlines:\n", opt_threshold);
	for (i = 0; i < opt_threshold; i++, ptr += len_share) {
		if (! opt_quiet)
			fprintf(stderr, "Share [%d/%d]: ", i + 1, opt_threshold);

		if (! fgets(buf, sizeof(buf), stdin))
			fatal("I/O error while reading shares");
		buf[strcspn(buf, "\r\n")] = '\0';
		char *a, *b;
		if (! (a = strchr(buf, '-')))
			fatal("invalid syntax");
		*a++ = 0;
		if ((b = strchr(a, '-')))
			*b++ = 0;
		else
			b = a, a = buf;

		// set security bits and malloc *shares
		if (len_secret == 0) {
			// when first loop
			size_t security_bits = 4 * strlen(b);
			if (security_bits % 8 != 0 || security_bits < 8)
				fatal("share has illegal length");

			len_secret = security_bits / 8;
			len_share = ssss_size_share(len_secret);
			ptr = shares = (uint8_t*)calloc(len_share, opt_threshold);
			if (shares == NULL)
				fatal("Can't allocation memory");
		} else {
			// when non first loop
			if (len_secret*2 != strlen(b))
				fatal("shares have different security levels");
		}

		// set x
		ssss_index_t *meta_ptr = (ssss_index_t*)ptr;
		ssss_index_t x = atoi(a);
		if (x == 0)
			fatal("invalid share");
		meta_ptr[0] = opt_threshold;
		meta_ptr[1] = x;
		str_import(ptr + sizeof(ssss_index_t)*2, len_secret, b, 1);
	}

	uint8_t data[MAXDEGREE];
	if (ssss_combine(shares, data, len_secret, opt_threshold))
		fatal("shares inconsistent. Perhaps a single share was used twice");

	if (opt_diffusion) {
		if (len_secret >= 8)
			ssss_encode_mpz(len_secret, data, DECODE);
	else
		warning("security level too small for the diffusion layer");
	}

	if (! opt_quiet)
		fprintf(stderr, "Resulting secret: ");
	str_print(stdout, data, len_secret, opt_hex);

	free(shares);
}

int main(int argc, char *argv[])
{
  char *name;
  int i;

#if ! NOMLOCK
  int failedMemoryLock = 0;
  if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
  {
    failedMemoryLock = 1;
    switch(errno) {
    case ENOMEM:
      warning("couldn't get memory lock (ENOMEM, try to adjust RLIMIT_MEMLOCK!)");
      break;
    case EPERM:
      warning("couldn't get memory lock (EPERM, try UID 0!)");
      break;
    case ENOSYS:
      warning("couldn't get memory lock (ENOSYS, kernel doesn't allow page locking)");
      break;
    default:
      warning("couldn't get memory lock");
      break;
    }
  }
#endif

  if (getuid() != geteuid())
    seteuid(getuid());

  tcgetattr(0, &echo_orig);
  echo_off = echo_orig;
  echo_off.c_lflag &= ~ECHO;

  opt_help = argc == 1;
  const char* flags =
#if ! NOMLOCK
    "MvDhqQxs:t:n:w:";
#else
    "vDhqQxs:t:n:w:";
#endif

  while((i = getopt(argc, argv, flags)) != -1)
    switch(i) {
    case 'v': opt_showversion = 1; break;
    case 'h': opt_help = 1; break;
    case 'q': opt_quiet = 1; break;
    case 'Q': opt_QUIET = opt_quiet = 1; break;
    case 'x': opt_hex = 1; break;
    case 's': opt_security = atoi(optarg); break;
    case 't': opt_threshold = atoi(optarg); break;
    case 'n': opt_number = atoi(optarg); break;
    case 'w': opt_token = optarg; break;
    case 'D': opt_diffusion = 0; break;
#if ! NOMLOCK
    case 'M':
      if(failedMemoryLock != 0)
        fatal("memory lock is required to proceed");
      break;
#endif
    default:
      exit(1);
    }
  if (! opt_help && (argc != optind))
    fatal("invalid argument");

  if ((name = strrchr(argv[0], '/')) == NULL)
    name = argv[0];

  if (strstr(name, "split")) {
    if (opt_help || opt_showversion) {
      fputs("Split secrets using Shamir's Secret Sharing Scheme.\n"
            "\n"
            "ssss-split -t threshold -n shares [-w token] [-s level]"
#if ! NOMLOCK
            " [-M]"
#endif
            " [-x] [-q] [-Q] [-D] [-v]\n",
            stderr);
      if (opt_showversion)
        fputs("\nVersion: " VERSION, stderr);
      exit(0);
    }

    if (opt_threshold < 2)
      fatal("invalid parameters: invalid threshold value");

    if (opt_number < opt_threshold)
      fatal("invalid parameters: number of shares smaller than threshold");

    if (opt_security && (opt_security % 8 != 0 || opt_security < 8))
      fatal("invalid parameters: invalid security level");

    if (opt_token && (strlen(opt_token) > MAXTOKENLEN))
      fatal("invalid parameters: token too long");

    split();
  }
  else {
    if (opt_help || opt_showversion) {
      fputs("Combine shares using Shamir's Secret Sharing Scheme.\n"
            "\n"
            "ssss-combine -t threshold"
#if ! NOMLOCK
            " [-M]"
#endif
            " [-x] [-q] [-Q] [-D] [-v]\n",
            stderr);
      if (opt_showversion)
        fputs("\nVersion: " VERSION, stderr);
      exit(0);
    }

    if (opt_threshold < 2)
      fatal("invalid parameters: invalid threshold value");

    combine();
  }
  return 0;
}
