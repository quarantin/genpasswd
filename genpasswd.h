/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GENPASSWD_H
#define GENPASSWD_H

#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
 
#define PROG_NAME "passwdgen"
 
#define DEFAULT_PASSWD_LEN 16
#define DEFAULT_PASSWD_SIZE (DEFAULT_PASSWD_LEN + 1)
#define DEFAULT_PASSWD_COUNT 32

#define LENGTH(x) ((sizeof(x) - sizeof(wchar_t)) / sizeof(wchar_t))
#define MIN(x, y, t) (t)((t)(x) > (t)(y) ? (y) : (x))
#define MAX(x, y, t) (t)((t)(x) < (t)(y) ? (y) : (x))
 
#define DIGIT_CHARS L"0123456789"
#define DIGIT_CHARS_LEN LENGTH(DIGIT_CHARS)
 
#define LOWER_CHARS L"abcdefghijklmnopqrstuvwxyz"
#define LOWER_CHARS_LEN LENGTH(LOWER_CHARS)
 
#define UPPER_CHARS L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define UPPER_CHARS_LEN LENGTH(UPPER_CHARS)
 
#define SPECIAL_CHARS L" !#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\""
#define SPECIAL_CHARS_LEN LENGTH(SPECIAL_CHARS)

#define UTF8_CHARS L"áàâäÁÀÂÄéèêëÉÈÊËíìîïÍÌÎÏóòôöÓÒÔÖúùûüÚÙÛÜýŷÿÝŶŸçÇ€œŒ"
#define UTF8_CHARS_LEN LENGTH(UTF8_CHARS)

struct range {
	size_t min;
	size_t max;
};

struct pwd_stat {
	size_t d;
	size_t a;
	size_t A;
	size_t s;
	size_t u;
	double entropy;
};

struct pwd_policy {
	struct range d;
	struct range a;
	struct range A;
	struct range s;
	struct range u;
	double min_entropy;
	double best_entropy;
	size_t pwdlen;
};

struct config {
	int urandom_fd;
	wchar_t *alphabet;
	size_t alphabet_size;
	struct pwd_policy policy;
	int opt_check_entropy;
	int opt_check_policy;
	int opt_min_entropy;
	int opt_passwd_count;
	int opt_table;
	int opt_verbose;
};

#endif /* GENPASSWD_H */

