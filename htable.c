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
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <search.h>

int wc_to_key (wchar_t wc, char *key, size_t keysz)
{
	wchar_t wcs[2];
	size_t written;

	if (!key || keysz != sizeof(wchar_t) + 1)
		return -1;

	wcs[0] = wc;
	wcs[1] = L'\0';

	written = wcstombs(key, wcs, keysz);
	if (!written || written > sizeof(wchar_t) || written == (size_t)-1) {
		perror("wcstombs failed");
		return -1;
	}

	return 0;
}

void update_frequencies (wchar_t wc)
{
	char *key;
	size_t keysz;
	int err, data;
	ENTRY entry, *pentry;

	keysz = sizeof(wchar_t) + 1;
	key = malloc(keysz);
	if (!key) {
		perror("malloc failed");
		// TODO better error handling
		exit(EXIT_FAILURE);
	}

	err = wc_to_key(wc, key, keysz);
	if (err) {
		fprintf(stderr, "FATAL: wc_to_key failed\n");
		// TODO better error handling
		exit(EXIT_FAILURE);
	}

	entry.key = key;
	entry.data = NULL;

	pentry = hsearch(entry, FIND);
	if (!pentry)
		pentry = &entry;
	else
		free(entry.key);

	data = (int)(long)pentry->data + 1;
	pentry->data = (void *)(long)data;

	hsearch(*pentry, ENTER);
}

int ht_get (wchar_t wc)
{
	int err;
	ENTRY entry, *pentry;
	char key[sizeof(wchar_t) + 1];

	err = wc_to_key(wc, key, sizeof(key));
	if (err) {
		fprintf(stderr, "FATAL: wc_to_key failed\n");
		// TODO better error handling
		exit(EXIT_FAILURE);
	}

	entry.key = key;
	entry.data = NULL;

	pentry = hsearch(entry, FIND);
	if (!pentry)
		return 0;

	return (int)(long)pentry->data;
}

void ht_del (wchar_t *keys, size_t keyssz)
{
	int err;
	size_t i;
	ENTRY entry, *pentry;
	char key[sizeof(wchar_t) + 1];

	for (i = 0; i < keyssz; i++) {

		err = wc_to_key(keys[i], key, sizeof(key));
		if (err) {
			fprintf(stderr, "FATAL: wc_to_key failed\n");
			// TODO better error handling
			exit(EXIT_FAILURE);
		}

		entry.key = key;
		entry.data = NULL;

		pentry = hsearch(entry, FIND);
		if (pentry)
			free(pentry->key);
	}
}

