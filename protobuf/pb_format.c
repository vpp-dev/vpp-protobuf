/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pb_format.h"

/* Parse an IP4 address %d.%d.%d.%d. */
uword unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 * result = va_arg (*args, u8 *);
  unsigned a[4];

  if (! unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

/* Parse an IP6 address. */
uword unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t * result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
	hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
	hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
	n_colon++;
      else
	{
	  unformat_put_input (input);
	  break;
	}

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
	return 0;

      if (hex_digit < 16)
	{
	  hex_quad = (hex_quad << 4) | hex_digit;

	  /* Hex quad must fit in 16 bits. */
	  if (n_hex_digits >= 4)
	    return 0;

	  n_colon = 0;
	  n_hex_digits++;
	}

      /* Save position of :: */
      if (n_colon == 2)
	{
	  /* More than one :: ? */
	  if (double_colon_index < ARRAY_LEN (hex_quads))
	    return 0;
	  double_colon_index = n_hex_quads;
	}

      if (n_colon > 0 && n_hex_digits > 0)
	{
	  hex_quads[n_hex_quads++] = hex_quad;
	  hex_quad = 0;
	  n_hex_digits = 0;
	}
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;

  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
	word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

	for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
	  hex_quads[n_zero + i] = hex_quads[i];

	for (i = 0; i < n_zero; i++)
	  hex_quads[double_colon_index + i] = 0;

	n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

u8 * format_ip4_address (u8 * s, va_list * args)
{
  u8 * a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 * format_ip6_address (u8 * s, va_list * args)
{
    ip6_address_t * a = va_arg (*args, ip6_address_t *);
    u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

    i_max_n_zero = ARRAY_LEN (a->as_u16);
    max_n_zeros = 0;
    i_first_zero = i_max_n_zero;
    n_zeros = 0;
    for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
      {
        u32 is_zero = a->as_u16[i] == 0;
        if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
          {
            i_first_zero = i;
            n_zeros = 0;
          }
        n_zeros += is_zero;
        if ((! is_zero && n_zeros > max_n_zeros)
            || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
          {
            i_max_n_zero = i_first_zero;
            max_n_zeros = n_zeros;
            i_first_zero = ARRAY_LEN (a->as_u16);
            n_zeros = 0;
          }
      }

    last_double_colon = 0;
    for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
      {
        if (i == i_max_n_zero && max_n_zeros > 1)
          {
            s = format (s, "::");
            i += max_n_zeros - 1;
            last_double_colon = 1;
          }
        else
          {
            s = format (s, "%s%x",
                        (last_double_colon || i == 0) ? "" : ":",
                        clib_net_to_host_u16 (a->as_u16[i]));
            last_double_colon = 0;
          }
      }

    return s;
}
