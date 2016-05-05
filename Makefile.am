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

AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@

lib_LTLIBRARIES = protobuf.la protobuf_test.la
protobuf_la_SOURCES = protobuf/main.c protobuf/vpp.pb-c.c protobuf/tcpclient.c protobuf/msghandler.c protobuf/pb_format.c protobuf/protobuf_api.c
protobuf_la_LDFLAGS = -module -lev -lprotobuf-c

BUILT_SOURCES = protobuf/vpp.pb-c.c protobuf/vpp.pb-c.h protobuf/protobuf.api.h

SUFFIXES = .pb-c.c .pb-c.h .api.h .api

%.pb-c.c %.pb-c.h: %.proto
	protoc-c --c_out=. $<
	
%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@	

nobase_include_HEADERS =

protobuf_test_la_SOURCES = protobuf/protobuf_test.c protobuf/protobuf_plugin.api.h protobuf/pb_format.c
protobuf_test_la_LDFLAGS = -module

if WITH_PLUGIN_TOOLKIT
install-data-hook:
	mkdir /usr/lib/vpp_plugins || true
	mkdir /usr/lib/vpp_api_test_plugins || true
 	cp $(prefix)/lib/protobuf.so.*.*.* /usr/lib/vpp_plugins
	cp $(prefix)/lib/protobuf_test.so.*.*.* /usr/lib/vpp_api_test_plugins
endif
