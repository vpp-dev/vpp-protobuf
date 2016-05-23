# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall

bin_PROGRAMS = vpp_protobuf

vpp_protobuf_SOURCES = protobuf/main.c protobuf/vpp.pb-c.c protobuf/tcpclient.c protobuf/msghandler.c
vpp_protobuf_LDADD = -lvlibmemoryclient -lvlibapi -lvlib_unix -lvlib \
					-lsvm -lsvmdb -lrt -ldl -lvppinfra -lpthread -lev -lprotobuf-c

BUILT_SOURCES = protobuf/vpp.pb-c.c protobuf/vpp.pb-c.h

SUFFIXES = .pb-c.c .pb-c.h

%.pb-c.c %.pb-c.h: %.proto
	protoc-c --c_out=. $<

nobase_include_HEADERS =

