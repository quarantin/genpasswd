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
#ifndef HTABLE_H
#define HTABLE_H

#include <wchar.h>

int wc_to_key (wchar_t wc, char *key, size_t keysz);

void update_frequencies (wchar_t wc);

int ht_get (wchar_t wc);

void ht_del (wchar_t *keys, size_t keyssz);

#endif /* HTABLE_H */
