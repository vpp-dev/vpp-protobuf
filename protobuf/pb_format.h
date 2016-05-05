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

#ifndef __VPPPROTOBUF_PB_FORMAT_H__
#define __VPPPROTOBUF_PB_FORMAT_H__

#include <vppinfra/format.h>

typedef union {
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  uword as_uword[16 / sizeof (uword)];
} ip6_address_t;

uword unformat_ip4_address (unformat_input_t * input, va_list * args);
uword unformat_ip6_address (unformat_input_t * input, va_list * args);
u8 * format_ip4_address (u8 * s, va_list * args);
u8 * format_ip6_address (u8 * s, va_list * args);

#endif
