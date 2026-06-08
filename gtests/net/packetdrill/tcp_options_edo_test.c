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
#include "tcp_packet.h"

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

/* Build an outbound TCP/IPv4 packet carrying the given options. */
static struct packet *build_tcp(const struct tcp_options *opts, char **error)
{
	return new_tcp_packet(AF_INET, DIRECTION_OUTBOUND, ip_info_new(),
			      /* src_port */ 1234, /* dst_port */ 80,
			      /* flags */ ".", /* start_sequence */ 0,
			      /* tcp_payload_bytes */ 0, /* ack_sequence */ 0,
			      /* window */ 100, /* urg_ptr */ 0, opts,
			      /* ignore_ts_val */ false, /* abs_ts_ecr */ false,
			      /* abs_seq */ false, /* ignore_seq */ false,
			      /* trr_code */ 0, /* trr_pen */ 0,
			      /* udp_src_port */ 0, /* udp_dst_port */ 0, error);
}

/*
 * U1 (Task 04, build side): an EDO Supported option (kind 77, len 2), padded
 * to a 32-bit word, lands on the wire verbatim and is fully covered by doff
 * (no EDO Extension present, so doff behaves exactly as before).
 */
static void test_u1_build_edo_supported(void)
{
	struct tcp_options *opts = tcp_options_new();
	char *error = NULL;
	struct packet *packet;
	const u8 *o;

	/* EDO Supported (2B) + 2 NOPs -> 4 option bytes (word aligned). */
	assert(tcp_options_append(opts,
		tcp_option_new(TCPOPT_EDO_SUPPORTED, TCPOLEN_EDO_SUPPORTED))
		== STATUS_OK);
	assert(tcp_options_append(opts, tcp_option_new(TCPOPT_NOP, 1)) == STATUS_OK);
	assert(tcp_options_append(opts, tcp_option_new(TCPOPT_NOP, 1)) == STATUS_OK);

	packet = build_tcp(opts, &error);
	assert(packet != NULL);
	assert(error == NULL);

	/* doff = (20 + 4) / 4 = 6, covering the whole option region. */
	assert(packet->tcp->doff == 6);

	o = (const u8 *)(packet->tcp + 1);
	assert(o[0] == TCPOPT_EDO_SUPPORTED);
	assert(o[1] == TCPOLEN_EDO_SUPPORTED);

	packet_free(packet);
	free(opts);
}

/*
 * U2 (Task 04, build side): an EDO Extension (kind 78, len 4) followed by
 * options that push the REAL header past 60 bytes. doff must cover only up to
 * and including the EDO Extension, while the real header (and thus ip_bytes)
 * accounts for the full, oversized option region.
 *
 * The receive-side assertions (packet_tcp_header_len()==Header_Length*4 and
 * "checksum covers the full header") need the parse-time override and live in
 * U4 (Task 06); on a freshly built packet packet_tcp_header_len() is still
 * doff-based, so they are intentionally not asserted here.
 */
static void test_u2_build_edo_extension_over_60(void)
{
	struct tcp_options *opts = tcp_options_new();
	char *error = NULL;
	struct packet *packet;
	const u8 *o;

	/* MSS (4B) + EDO Extension (4B) within doff, then a 40-byte option
	 * after the EDO Extension -> real header = 20 + 48 = 68 (> 60). */
	assert(tcp_options_append(opts, tcp_option_new(TCPOPT_MAXSEG, TCPOLEN_MAXSEG))
		== STATUS_OK);
	assert(tcp_options_append(opts,
		tcp_option_new(TCPOPT_EDO_EXTENSION, TCPOLEN_EDO_EXTENSION))
		== STATUS_OK);
	assert(tcp_options_append(opts, tcp_option_new(TCPOPT_EXP, 40)) == STATUS_OK);

	packet = build_tcp(opts, &error);
	assert(packet != NULL);
	assert(error == NULL);

	/* doff = (20 + 4 + 4) / 4 = 7: only MSS + EDO Extension. */
	assert(packet->tcp->doff == 7);
	assert(packet->tcp->doff * 4 == 28);

	/* The real header (68B) is larger than the doff region and is reflected
	 * in ip_bytes = 20 (IP) + 68 (TCP) + 0 (payload). */
	assert(packet->ip_bytes == 20 + 68);

	o = (const u8 *)(packet->tcp + 1);
	assert(o[0] == TCPOPT_MAXSEG);
	assert(o[TCPOLEN_MAXSEG] == TCPOPT_EDO_EXTENSION);
	assert(o[TCPOLEN_MAXSEG + 1] == TCPOLEN_EDO_EXTENSION);

	packet_free(packet);
	free(opts);
}

/*
 * Build a raw IPv4 + TCP packet into 'buf' from the given option bytes, with an
 * EXPLICIT doff (in bytes) so negative tests can craft headers where doff and
 * the real option layout disagree. Returns the total IP length. The TCP
 * checksum is left zero (the parser does not verify it).
 */
static int make_ipv4_tcp(u8 *buf, const u8 *opts, int opts_len,
			 int doff_bytes, int payload_len)
{
	const int ihl = 20;
	const int tcp_fixed = 20;
	const int tcp_len = tcp_fixed + opts_len + payload_len;
	const int ip_len = ihl + tcp_len;
	u8 *tcp;

	memset(buf, 0, ip_len);
	/* IPv4 header */
	buf[0] = 0x45;			/* version 4, IHL 5 (20 bytes) */
	buf[2] = (ip_len >> 8) & 0xff;
	buf[3] = ip_len & 0xff;
	buf[8] = 64;			/* TTL */
	buf[9] = IPPROTO_TCP;
	buf[12] = 192; buf[13] = 0; buf[14] = 2; buf[15] = 1;	/* src */
	buf[16] = 192; buf[17] = 0; buf[18] = 2; buf[19] = 2;	/* dst */
	/* TCP header */
	tcp = buf + ihl;
	tcp[0] = 0x04; tcp[1] = 0xd2;	/* src port 1234 */
	tcp[2] = 0x00; tcp[3] = 0x50;	/* dst port 80 */
	tcp[12] = ((doff_bytes / 4) << 4) & 0xf0;	/* data offset nibble */
	tcp[13] = 0x10;			/* ACK */
	if (opts_len)
		memcpy(tcp + tcp_fixed, opts, opts_len);

	/* IPv4 header checksum (the parser verifies it). */
	{
		u32 sum = 0;
		int i;

		for (i = 0; i < ihl; i += 2)
			sum += (buf[i] << 8) | buf[i + 1];
		while (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
		sum = ~sum & 0xffff;
		buf[10] = (sum >> 8) & 0xff;
		buf[11] = sum & 0xff;
	}
	return ip_len;
}

/* Parse a raw IP packet, returning the result (caller frees *out). */
static enum packet_parse_result_t try_parse_ipv4(const u8 *data, int len,
						 struct packet **out)
{
	struct packet *packet = packet_new(len);
	char *error = NULL;
	enum packet_parse_result_t result;

	memcpy(packet->buffer, data, len);
	result = parse_packet(packet, len, ETHERTYPE_IP, 0, &error);
	free(error);
	*out = packet;
	return result;
}

/* Append helpers that write a single TCP option in wire format. */
static int put_mss(u8 *p)        { p[0] = TCPOPT_MAXSEG; p[1] = TCPOLEN_MAXSEG;
				   p[2] = 0x05; p[3] = 0xb4; return 4; }
static int put_edo_ext(u8 *p, u16 hlen_words) {
	p[0] = TCPOPT_EDO_EXTENSION; p[1] = TCPOLEN_EDO_EXTENSION;
	p[2] = (hlen_words >> 8) & 0xff; p[3] = hlen_words & 0xff; return 4; }
static int put_filler(u8 *p, u8 len) { p[0] = TCPOPT_EXP; p[1] = len;
				   memset(p + 2, 0, len - 2); return len; }

/*
 * U4 (Task 06, parse side): a hand-built EDO segment whose options extend past
 * the doff region. parse_tcp() must set tcp_header_len_override from
 * Header_Length, place the payload boundary at the real header end, and the
 * option iterator must visit options BEYOND doff.
 *
 * Layout: MSS(4) + EDO Extension(4, Header_Length=17 words=68B) within doff
 * (doff=7 => 28B), then a 40-byte option after doff. Real header = 68 bytes.
 */
static void test_u4_parse_edo(void)
{
	u8 opts[48], pkt[256];
	struct packet *packet;
	struct tcp_options_iterator iter;
	struct tcp_option *opt;
	char *error = NULL;
	int n = 0, len;

	n += put_mss(opts + n);
	n += put_edo_ext(opts + n, 17);		/* 17 words = 68 bytes */
	n += put_filler(opts + n, 40);
	assert(n == 48);
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 28, /* payload */ 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	assert(packet->tcp->doff == 7);			/* doff region only */
	assert(packet->tcp_header_len_override == 68);	/* real header */
	assert(packet_tcp_header_len(packet) == 68);
	assert(packet_payload_len(packet) == 0);	/* boundary at 68 */

	/* Iterator must walk all three options, including the one past doff. */
	opt = tcp_options_begin(packet, &iter);
	assert(opt != NULL && opt->kind == TCPOPT_MAXSEG);
	opt = tcp_options_next(&iter, &error);
	assert(opt != NULL && opt->kind == TCPOPT_EDO_EXTENSION);
	opt = tcp_options_next(&iter, &error);
	assert(opt != NULL && opt->kind == TCPOPT_EXP);	/* beyond doff */
	opt = tcp_options_next(&iter, &error);
	assert(opt == NULL && error == NULL);

	packet_free(packet);
}

/*
 * U5 (Task 06): round-trip. The parsed+iterated option list equals the input
 * option list, including the extended region beyond doff.
 */
static void test_u5_roundtrip(void)
{
	const u8 expect_kinds[] = { TCPOPT_MAXSEG, TCPOPT_EDO_EXTENSION,
				    TCPOPT_EXP };
	u8 opts[48], pkt[256];
	struct packet *packet;
	struct tcp_options_iterator iter;
	struct tcp_option *opt;
	char *error = NULL;
	int n = 0, len, i = 0;

	n += put_mss(opts + n);
	n += put_edo_ext(opts + n, 17);
	n += put_filler(opts + n, 40);
	len = make_ipv4_tcp(pkt, opts, n, 28, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	for (opt = tcp_options_begin(packet, &iter); opt != NULL;
	     opt = tcp_options_next(&iter, &error)) {
		assert(i < (int)ARRAY_SIZE(expect_kinds));
		assert(opt->kind == expect_kinds[i]);
		i++;
	}
	assert(error == NULL);
	assert(i == (int)ARRAY_SIZE(expect_kinds));

	packet_free(packet);
}

/*
 * Negative tests. The FreeBSD test kernel does NOT reject malformed EDO (no
 * drop/RST): an EDO Extension with an unexpected length is ignored, and
 * Header_Length is not range-checked. packetdrill mirrors this — it only
 * APPLIES the override when fully valid/usable, otherwise treats the segment
 * as non-EDO (override stays 0, parse succeeds). The sole hard failure is a
 * truncated option that would overrun the buffer (memory safety).
 * See data/freebsd-kernel-edo-referenz.md.
 */

/* N1: EDO Extension length != 4 -> ignored (override 0), parse OK. */
static void test_n1_bad_extension_length(void)
{
	u8 opts[12], pkt[256];
	struct packet *packet;
	int n = 0, len;

	n += put_mss(opts + n);				/* 0..3 */
	opts[n++] = TCPOPT_EDO_EXTENSION;		/* kind */
	opts[n++] = 5;					/* bad length 5 */
	opts[n++] = 0; opts[n++] = 0; opts[n++] = 0;	/* 3 payload bytes */
	opts[n++] = TCPOPT_NOP; opts[n++] = TCPOPT_NOP;
	opts[n++] = TCPOPT_NOP;				/* pad to 12 */
	assert(n == 12);
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 32, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	assert(packet->tcp_header_len_override == 0);	/* ignored */
	packet_free(packet);
}

/* N2: Header_Length < doff*4 -> not applied (override 0), parse OK. */
static void test_n2_header_length_too_small(void)
{
	u8 opts[8], pkt[256];
	struct packet *packet;
	int n = 0, len;

	n += put_mss(opts + n);
	n += put_edo_ext(opts + n, 5);		/* 5 words = 20B < doff(28) */
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 28, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	assert(packet->tcp_header_len_override == 0);
	packet_free(packet);
}

/* N3: Header_Length > segment size -> not applied (override 0), parse OK. */
static void test_n3_header_length_too_big(void)
{
	u8 opts[8], pkt[256];
	struct packet *packet;
	int n = 0, len;

	n += put_mss(opts + n);
	n += put_edo_ext(opts + n, 100);	/* 400B >> segment */
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 28, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	assert(packet->tcp_header_len_override == 0);
	packet_free(packet);
}

/* N4: EDO Extension positioned entirely beyond doff -> not seen (override 0). */
static void test_n4_extension_outside_doff(void)
{
	u8 opts[8], pkt[256];
	struct packet *packet;
	int n = 0, len;

	n += put_mss(opts + n);			/* within doff (region=4) */
	n += put_edo_ext(opts + n, 12);		/* sits at offset 24, past doff */
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 24, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_OK);
	assert(packet->tcp_header_len_override == 0);	/* not recognised */
	packet_free(packet);
}

/* N5: option length overruns the doff region -> PACKET_BAD, no OOB read. */
static void test_n5_truncated_option(void)
{
	u8 opts[8], pkt[256];
	struct packet *packet;
	int n = 0, len;

	n += put_mss(opts + n);				/* 0..3 */
	opts[n++] = TCPOPT_EDO_EXTENSION;		/* kind at offset 4 */
	opts[n++] = 10;					/* length overruns region */
	opts[n++] = 0; opts[n++] = 0;
	len = make_ipv4_tcp(pkt, opts, n, /* doff */ 28, 0);

	assert(try_parse_ipv4(pkt, len, &packet) == PACKET_BAD);
	packet_free(packet);
}

/*
 * U6 (Task 09, build side): a packet built via new_tcp_packet() with options
 * extending past the doff region must expose the effective header length so the
 * option iterator walks the EXTENDED region too. This is what makes the
 * outbound options comparison (run_packet.c) see the script's full option list
 * rather than stopping at doff.
 */
static void test_u6_built_edo_iterates_extended(void)
{
	struct tcp_options *opts = tcp_options_new();
	struct tcp_options_iterator iter;
	struct tcp_option *opt, *ext;
	struct packet *packet;
	char *error = NULL;

	assert(tcp_options_append(opts,
		tcp_option_new(TCPOPT_MAXSEG, TCPOLEN_MAXSEG)) == STATUS_OK);
	ext = tcp_option_new(TCPOPT_EDO_EXTENSION, TCPOLEN_EDO_EXTENSION);
	ext->edo.header_length = htons(17);	/* 17 words = 68-byte header */
	assert(tcp_options_append(opts, ext) == STATUS_OK);
	assert(tcp_options_append(opts, tcp_option_new(TCPOPT_EXP, 40)) == STATUS_OK);

	packet = build_tcp(opts, &error);
	assert(packet != NULL && error == NULL);

	/* Built packet exposes the real header length, not just doff*4. */
	assert(packet->tcp_header_len_override == 68);
	assert(packet_tcp_header_len(packet) == 68);

	/* Iterator walks all three options, including the one beyond doff. */
	opt = tcp_options_begin(packet, &iter);
	assert(opt != NULL && opt->kind == TCPOPT_MAXSEG);
	opt = tcp_options_next(&iter, &error);
	assert(opt != NULL && opt->kind == TCPOPT_EDO_EXTENSION);
	opt = tcp_options_next(&iter, &error);
	assert(opt != NULL && opt->kind == TCPOPT_EXP);		/* beyond doff */
	opt = tcp_options_next(&iter, &error);
	assert(opt == NULL && error == NULL);

	packet_free(packet);
	free(opts);
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
 *   Task 04  U3  N/A: the FreeBSD test kernel implements only the 4-byte EDO
 *                Extension; there is no 6-byte/Segment_Length variant. See
 *                data/freebsd-kernel-edo-referenz.md.
 *   Task 06  U4  Parse hand-built EDO segment: tcp_header_len_override set from
 *                Header_Length; payload offset correct; iterator sees options
 *                beyond doff.
 *   Task 06  U5  Round-trip build -> parse -> iterate equals input option list.
 *   Task 06  N1  Extension length != 4 -> ignored (override 0), parse OK
 *                (kernel-consistent: the FreeBSD kernel ignores, never RSTs).
 *   Task 06  N2  Header_Length < doff*4 -> not applied (override 0), parse OK.
 *   Task 06  N3  Header_Length > segment size -> not applied (override 0), OK.
 *   Task 06  N4  EDO extension positioned outside the doff region -> not seen
 *                (override 0), parse OK.
 *   Task 06  N5  Truncated option (length overruns doff region) -> PACKET_BAD
 *                (the one hard failure: memory safety, no OOB read).
 *   Task 08  S1  packet_to_string renders EDO Supported / Extension readably.
 *                (lives in packet_to_string_test.c)
 *   Task 09  U6  Built EDO packet exposes the effective header length so the
 *                option iterator (and thus the outbound comparison) covers the
 *                extended region beyond doff.
 * =========================================================================
 */

int main(void)
{
	/* Active today (no EDO code required): */
	test_r0_non_edo_baseline();
	test_r1_iterator_baseline();

	/* Task 04 (build side): */
	test_u1_build_edo_supported();
	test_u2_build_edo_extension_over_60();

	/* Task 06 (parse side + negative/bounds): */
	test_u4_parse_edo();
	test_u5_roundtrip();
	test_n1_bad_extension_length();
	test_n2_header_length_too_small();
	test_n3_header_length_too_big();
	test_n4_extension_outside_doff();
	test_n5_truncated_option();

	/* Task 09 (comparison relies on the built packet exposing the
	 * extended option region): */
	test_u6_built_edo_iterates_extended();

	return 0;
}
