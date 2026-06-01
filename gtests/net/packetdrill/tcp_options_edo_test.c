/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Hermetic unit tests for TCP EDO (Extended Data Offset) support.
 *
 * These tests run without a kernel (via `make tests`) and guard the
 * packetdrill-side EDO logic. The test catalogue and rationale live in
 * data/tests/01-unit-tests-hermetisch.md. Test IDs (R0, U1.., N1.., S1)
 * referenced here map to that document and to the data/tasks files.
 *
 * STATUS: framework + R0 regression baseline are active and green today.
 * The EDO-specific tests are added incrementally by the tasks that
 * implement the corresponding feature (see "EDO TEST ROADMAP" below), so
 * that each test lands together with the code it verifies.
 */

#include "assert.h"
#include "ethernet.h"
#include "packet_parser.h"

#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "tcp.h"
#include "tcp_options.h"
#include "tcp_options_iterator.h"

bool debug_logging = false;

/* Parse a raw IP packet (helper mirroring packet_parser_test.c). */
static struct packet *parse_ipv4(const u8 *data, int len)
{
	struct packet *packet = packet_new(len);
	char *error = NULL;
	enum packet_parse_result_t result;

	memcpy(packet->buffer, data, len);
	result = parse_packet(packet, len, ETHERTYPE_IP, 0, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);
	return packet;
}

/*
 * R0 (regression baseline): a NON-EDO TCP/IPv4 segment carrying
 * <sack ...,TS val .. ecr ..> (doff = 10 => 40-byte header, 20 option bytes).
 *
 * This locks in the relationship "header length / payload boundary == doff*4"
 * that EDO decouples. Once EDO lands (Tasks 04/05), a packet WITHOUT EDO must
 * still behave byte-identically (tcp_header_len_override == 0). This test must
 * keep passing unchanged — it is the primary guard against collateral damage.
 */
static void test_r0_non_edo_baseline(void)
{
	u8 data[] = {
		/* 192.0.2.1:53055 > 192.168.0.1:8080
		 * . 1:1(0) ack 2202903899 win 257
		 * <sack 2202905347:2202906795,TS val 300 ecr 1623332896>
		 */
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x39, 0x11, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0xcf, 0x3f, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x83, 0x4d, 0xa5, 0x5b,
		0xa0, 0x10, 0x01, 0x01, 0xdb, 0x2d, 0x00, 0x00,
		0x05, 0x0a, 0x83, 0x4d, 0xab, 0x03, 0x83, 0x4d,
		0xb0, 0xab, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x2c,
		0x60, 0xc2, 0x18, 0x20
	};
	struct packet *packet = parse_ipv4(data, sizeof(data));

	/* doff == 10 => 40-byte TCP header, 20 option bytes, no payload. */
	assert(packet->tcp != NULL);
	assert(packet->tcp->doff == 10);
	assert(packet_tcp_header_len(packet) == 40);
	assert(packet_tcp_options_len(packet) == 20);
	assert(packet_payload_len(packet) == 0);

	packet_free(packet);
}

/*
 * R1 (iterator baseline): the option iterator visits exactly the options
 * within doff (SACK then TIMESTAMP) and then stops. EDO (Task 06) must extend
 * this iteration past doff WITHOUT breaking the non-EDO case asserted here.
 */
static void test_r1_iterator_baseline(void)
{
	u8 data[] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x39, 0x11, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0xcf, 0x3f, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x83, 0x4d, 0xa5, 0x5b,
		0xa0, 0x10, 0x01, 0x01, 0xdb, 0x2d, 0x00, 0x00,
		0x05, 0x0a, 0x83, 0x4d, 0xab, 0x03, 0x83, 0x4d,
		0xb0, 0xab, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x2c,
		0x60, 0xc2, 0x18, 0x20
	};
	struct packet *packet = parse_ipv4(data, sizeof(data));
	struct tcp_options_iterator iter;
	char *error = NULL;
	struct tcp_option *opt;

	opt = tcp_options_begin(packet, &iter);
	assert(opt != NULL);
	assert(opt->kind == TCPOPT_SACK);

	opt = tcp_options_next(&iter, &error);
	assert(opt != NULL);
	assert(opt->kind == TCPOPT_TIMESTAMP);

	opt = tcp_options_next(&iter, &error);
	assert(opt == NULL);
	assert(error == NULL);

	packet_free(packet);
}

/*
 * ============================ EDO TEST ROADMAP ============================
 * Add each test as a `static void test_xxx(void)` and call it from main()
 * together with the task that implements the feature. Keep -Werror happy:
 * only define a test function once it is actually called (no unused static
 * functions). Details/asserts: data/tests/01-unit-tests-hermetisch.md.
 *
 *   Task 03  --  No dedicated test: the EDO constants + struct field are
 *                verified at compile time and exercised transitively by U1
 *                (which references TCPOPT_EDO and the edo union branch).
 *   Task 04  U1  Build EDO Supported: wire bytes (kind, len==2), doff covers it.
 *   Task 04  U2  Build EDO Extension (4B) with options > 60B: doff covers only
 *                up to EDO ext; packet_tcp_header_len()==Header_Length*4;
 *                TCP checksum covers the full header.
 *   Task 04  U3  Build EDO Extension (6B): Segment_Length == pseudoheader len.
 *   Task 06  U4  Parse hand-built EDO segment: tcp_header_len_override set from
 *                Header_Length; payload offset correct; iterator sees options
 *                beyond doff.
 *   Task 06  U5  Round-trip build -> parse -> iterate equals input option list.
 *   Task 06  N1  Extension length != 4/6 -> parse_tcp() returns PACKET_BAD.
 *   Task 06  N2  Header_Length < doff*4 -> PACKET_BAD.
 *   Task 06  N3  Header_Length > segment size -> PACKET_BAD.
 *   Task 06  N4  EDO extension positioned outside the doff region -> rejected.
 *   Task 06  N5  Truncated option (length runs past segment) -> PACKET_BAD.
 *   Task 08  S1  packet_to_string renders EDO Supported / Extension readably.
 * =========================================================================
 */

int main(void)
{
	/* Active today (no EDO code required): */
	test_r0_non_edo_baseline();
	test_r1_iterator_baseline();

	/* EDO tests are wired in here by Tasks 03/04/06/08 (see roadmap above). */
	return 0;
}
