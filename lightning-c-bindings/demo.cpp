extern "C" {
#include <lightning.h>

#ifdef REAL_NET
#include <ldk_net.h>
#endif
}
#include "include/lightningpp.hpp"

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <mutex>
#include <vector>

const uint8_t valid_node_announcement[] = {
	0x94, 0xe4, 0xf5, 0x61, 0x41, 0x24, 0x7d, 0x90, 0x23, 0xa0, 0xc8, 0x34, 0x8c, 0xc4, 0xca, 0x51,
	0xd8, 0x17, 0x59, 0xff, 0x7d, 0xac, 0x8c, 0x9b, 0x63, 0x29, 0x1c, 0xe6, 0x12, 0x12, 0x93, 0xbd,
	0x66, 0x4d, 0x6b, 0x9c, 0xfb, 0x35, 0xda, 0x16, 0x06, 0x3d, 0xf0, 0x8f, 0x8a, 0x39, 0x99, 0xa2,
	0xf2, 0x5d, 0x12, 0x0f, 0x2b, 0x42, 0x1b, 0x8b, 0x9a, 0xfe, 0x33, 0x0c, 0xeb, 0x33, 0x5e, 0x52,
	0xee, 0x99, 0xa1, 0x07, 0x06, 0xed, 0xf8, 0x48, 0x7a, 0xc6, 0xe5, 0xf5, 0x5e, 0x01, 0x3a, 0x41,
	0x2f, 0x18, 0x94, 0x8a, 0x3b, 0x0a, 0x52, 0x3f, 0xbf, 0x61, 0xa9, 0xc5, 0x4f, 0x70, 0xee, 0xb8,
	0x79, 0x23, 0xbb, 0x1a, 0x44, 0x7d, 0x91, 0xe6, 0x2a, 0xbc, 0xa1, 0x07, 0xbc, 0x65, 0x3b, 0x02,
	0xd9, 0x1d, 0xb2, 0xf2, 0x3a, 0xcb, 0x75, 0x79, 0xc6, 0x66, 0xd8, 0xc1, 0x71, 0x29, 0xdf, 0x04,
	0x60, 0xf4, 0xbf, 0x07, 0x7b, 0xb9, 0xc2, 0x11, 0x94, 0x6a, 0x28, 0xc2, 0xdd, 0xd8, 0x7b, 0x44,
	0x8f, 0x08, 0xe3, 0xc8, 0xd8, 0xf4, 0x81, 0xb0, 0x9f, 0x94, 0xcb, 0xc8, 0xc1, 0x3c, 0xc2, 0x6e,
	0x31, 0x26, 0xfc, 0x33, 0x16, 0x3b, 0xe0, 0xde, 0xa1, 0x16, 0x21, 0x9f, 0x89, 0xdd, 0x97, 0xa4,
	0x41, 0xf2, 0x9f, 0x19, 0xb1, 0xae, 0x82, 0xf7, 0x85, 0x9a, 0xb7, 0x8f, 0xb7, 0x52, 0x7a, 0x72,
	0xf1, 0x5e, 0x89, 0xe1, 0x8a, 0xcd, 0x40, 0xb5, 0x8e, 0xc3, 0xca, 0x42, 0x76, 0xa3, 0x6e, 0x1b,
	0xf4, 0x87, 0x35, 0x30, 0x58, 0x43, 0x04, 0xd9, 0x2c, 0x50, 0x54, 0x55, 0x47, 0x6f, 0x70, 0x9b,
	0x42, 0x1f, 0x91, 0xfc, 0xa1, 0xdb, 0x72, 0x53, 0x96, 0xc8, 0xe5, 0xcd, 0x0e, 0xcb, 0xa0, 0xfe,
	0x6b, 0x08, 0x77, 0x48, 0xb7, 0xad, 0x4a, 0x69, 0x7c, 0xdc, 0xd8, 0x04, 0x28, 0x35, 0x9b, 0x73,
	0x00, 0x00, 0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce,
	0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5b, 0xe5, 0xe9, 0x47, 0x82,
	0x09, 0x67, 0x4a, 0x96, 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61, 0x76, 0x54, 0x0f, 0xd0, 0x01, 0xfa,
	0x1d, 0x64, 0x69, 0x47, 0x70, 0xc5, 0x6a, 0x77, 0x09, 0xc4, 0x2c, 0x03, 0x5c, 0x4e, 0x0d, 0xec,
	0x72, 0x15, 0xe2, 0x68, 0x33, 0x93, 0x87, 0x30, 0xe5, 0xe5, 0x05, 0xaa, 0x62, 0x50, 0x4d, 0xa8,
	0x5b, 0xa5, 0x71, 0x06, 0xa4, 0x6b, 0x5a, 0x24, 0x04, 0xfc, 0x9d, 0x8e, 0x02, 0xba, 0x72, 0xa6,
	0xe8, 0xba, 0x53, 0xe8, 0xb9, 0x71, 0xad, 0x0c, 0x98, 0x23, 0x96, 0x8a, 0xef, 0x4d, 0x78, 0xce,
	0x8a, 0xf2, 0x55, 0xab, 0x43, 0xdf, 0xf8, 0x30, 0x03, 0xc9, 0x02, 0xfb, 0x8d, 0x02, 0x16, 0x34,
	0x5b, 0xf8, 0x31, 0x16, 0x4a, 0x03, 0x75, 0x8e, 0xae, 0xa5, 0xe8, 0xb6, 0x6f, 0xee, 0x2b, 0xe7,
	0x71, 0x0b, 0x8f, 0x19, 0x0e, 0xe8, 0x80, 0x24, 0x90, 0x32, 0xa2, 0x9e, 0xd6, 0x6e
};

// A simple block containing only one transaction (which is the channel-open transaction for the
// channel we'll create). This was originally created by printing additional data in a simple
// rust-lightning unit test.
const uint8_t channel_open_block[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xa2, 0x47, 0xd2, 0xf8, 0xd4, 0xe0, 0x6a, 0x3f, 0xf9, 0x7a, 0x9a, 0x34,
	0xbb, 0xa9, 0x96, 0xde, 0x63, 0x84, 0x5a, 0xce, 0xcf, 0x98, 0xb8, 0xbb, 0x75, 0x4c, 0x4f, 0x7d,
	0xee, 0x4c, 0xa9, 0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, // transaction count
	0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x40, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x20, 0xd1, 0xd9, 0x13, 0xa9,
	0x76, 0x09, 0x05, 0xa3, 0x4d, 0x13, 0x5b, 0x69, 0xaa, 0xe7, 0x79, 0x71, 0xb9, 0x75, 0xa1, 0xd0,
	0x77, 0xcb, 0xa2, 0xf6, 0x6a, 0x25, 0x37, 0x3a, 0xaf, 0xdc, 0x11, 0x09, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00
};

// The first transaction in the block is header (80 bytes) + transaction count (1 byte) into the block data.
const uint8_t channel_open_txid[] = {
	0x02, 0xe0, 0x50, 0x05, 0x33, 0xd3, 0x29, 0x66, 0x0c, 0xb2, 0xcb, 0x1e, 0x7a, 0x4a, 0xc7, 0xc7,
	0x8b, 0x02, 0x46, 0x7e, 0x30, 0x2c, 0xe6, 0x19, 0xce, 0x43, 0x3e, 0xdf, 0x43, 0x65, 0xae, 0xf9,
};

// Two blocks built on top of channel_open_block:
const uint8_t block_1[81] = {
	0x01, 0x00, 0x00, 0x00, 0x0c, 0x7a, 0xc2, 0xdc, 0x08, 0xaf, 0x40, 0x7d, 0x58, 0x81, 0x9b, 0x44,
	0xc7, 0xe0, 0x0f, 0x78, 0xc0, 0xd1, 0x01, 0xa2, 0x03, 0x16, 0x4a, 0x8d, 0x92, 0x66, 0x4e, 0xaf,
	0x7f, 0xfc, 0x6e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, // transaction count
};
const uint8_t block_2[81] = {
	0x01, 0x00, 0x00, 0x00, 0x36, 0x0b, 0xf5, 0x46, 0x4a, 0xc7, 0x26, 0x4c, 0x4b, 0x36, 0xa6, 0x9d,
	0x0e, 0xf0, 0x14, 0xfb, 0x8a, 0xcb, 0x20, 0x84, 0x18, 0xf3, 0xaa, 0x77, 0x32, 0x2d, 0xf7, 0x48,
	0x62, 0x92, 0xb1, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, // transaction count
};

const LDKThirtyTwoBytes genesis_hash = { // We don't care particularly if this is "right"
	.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1 }
};

void print_log(const void *this_arg, const char *record) {
	printf("%p - %s\n", this_arg, record);
}

uint32_t get_fee(const void *this_arg, LDKConfirmationTarget target) {
	if (target == LDKConfirmationTarget_Background) {
		return 253;
	} else {
		return 507;
	}
	// Note that we don't call _free() on target, but that's OK, its unitary
}
// We use the same fee estimator globally:
const LDKFeeEstimator fee_est {
	.this_arg = NULL,
	.get_est_sat_per_1000_weight = get_fee,
	.free = NULL,
};

static std::atomic_int num_txs_broadcasted(0);
void broadcast_tx(const void *this_arg, LDKTransaction tx) {
	num_txs_broadcasted += 1;
	//TODO
	Transaction_free(tx);
}

struct NodeMonitors {
	std::mutex mut;
	std::vector<std::pair<LDK::OutPoint, LDK::ChannelMonitor>> mons;
	LDKLogger* logger;

	void ConnectBlock(const uint8_t (*header)[80], uint32_t height, LDKCVec_C2Tuple_usizeTransactionZZ tx_data, LDKBroadcasterInterface broadcast, LDKFeeEstimator fee_est) {
		std::unique_lock<std::mutex> l(mut);
		for (auto& mon : mons) {
			LDK::CVec_TransactionOutputsZ res = ChannelMonitor_block_connected(&mon.second, header, tx_data, height, broadcast, fee_est, *logger);
		}
	}
};

LDKCResult_NoneChannelMonitorUpdateErrZ add_channel_monitor(const void *this_arg, LDKOutPoint funding_txo_arg, LDKChannelMonitor monitor_arg) {
	// First bind the args to C++ objects so they auto-free
	LDK::ChannelMonitor mon(std::move(monitor_arg));
	LDK::OutPoint funding_txo(std::move(funding_txo_arg));

	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	arg->mons.push_back(std::make_pair(std::move(funding_txo), std::move(mon)));
	return CResult_NoneChannelMonitorUpdateErrZ_ok();
}
static std::atomic_int mons_updated(0);
LDKCResult_NoneChannelMonitorUpdateErrZ update_channel_monitor(const void *this_arg, LDKOutPoint funding_txo_arg, LDKChannelMonitorUpdate monitor_arg) {
	// First bind the args to C++ objects so they auto-free
	LDK::ChannelMonitorUpdate update(std::move(monitor_arg));
	LDK::OutPoint funding_txo(std::move(funding_txo_arg));

	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	bool updated = false;
	for (auto& mon : arg->mons) {
		if (OutPoint_get_index(&mon.first) == OutPoint_get_index(&funding_txo) &&
				!memcmp(OutPoint_get_txid(&mon.first), OutPoint_get_txid(&funding_txo), 32)) {
			updated = true;
			LDKBroadcasterInterface broadcaster = {
				.broadcast_transaction = broadcast_tx,
			};
			LDK::CResult_NoneMonitorUpdateErrorZ res = ChannelMonitor_update_monitor(&mon.second, &update, &broadcaster, &fee_est, arg->logger);
			assert(res->result_ok);
		}
	}
	assert(updated);

	mons_updated += 1;
	return CResult_NoneChannelMonitorUpdateErrZ_ok();
}
LDKCVec_MonitorEventZ monitors_pending_monitor_events(const void *this_arg) {
	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	if (arg->mons.size() == 0) {
		return LDKCVec_MonitorEventZ {
			.data = NULL,
			.datalen = 0,
		};
	} else {
		// We only ever actually have one channel per node, plus concatenating two
		// Rust Vecs to each other from C++ will require a bit of effort.
		assert(arg->mons.size() == 1);
		return ChannelMonitor_get_and_clear_pending_monitor_events(&arg->mons[0].second);
	}
}

struct EventQueue {
	std::vector<LDK::Event> events;
};
void handle_event(const void *this_arg, const LDKEvent *event) {
	EventQueue* arg = (EventQueue*) this_arg;
	arg->events.push_back(Event_clone(event));
}

#ifdef REAL_NET
class PeersConnection {
	void* node1_handler;
	void* node2_handler;

public:
	PeersConnection(LDK::ChannelManager& cm1, LDK::ChannelManager& cm2, LDK::PeerManager& net1, LDK::PeerManager& net2) {
		node1_handler = init_socket_handling(&net1);
		node2_handler = init_socket_handling(&net2);

		struct sockaddr_in listen_addr;
		listen_addr.sin_family = AF_INET;
		listen_addr.sin_addr.s_addr = htonl((127 << 8*3) | 1);
		listen_addr.sin_port = htons(10042);
		assert(!socket_bind(node2_handler, (sockaddr*)&listen_addr, sizeof(listen_addr)));

		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PublicKeyZ peers_1 = PeerManager_get_peer_node_ids(&net1);
			LDK::CVec_PublicKeyZ peers_2 = PeerManager_get_peer_node_ids(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen == 1) { break; }
			std::this_thread::yield();
		}

		// Connect twice, which should auto-disconnect, and is a good test of our disconnect pipeline
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		// Then disconnect the "main" connection, while another connection is being made.
		PeerManager_disconnect_by_node_id(&net1, ChannelManager_get_our_node_id(&cm2), false);
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		// Wait for all our sockets to disconnect (making sure we disconnect any new connections)...
		while (true) {
			PeerManager_disconnect_by_node_id(&net1, ChannelManager_get_our_node_id(&cm2), false);
			// Wait for the peers to disconnect...
			LDK::CVec_PublicKeyZ peers_1 = PeerManager_get_peer_node_ids(&net1);
			LDK::CVec_PublicKeyZ peers_2 = PeerManager_get_peer_node_ids(&net2);
			if (peers_1->datalen == 0 && peers_2->datalen == 0) { break; }
			std::this_thread::yield();
		}

		// Finally make an actual connection and keep it this time
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PublicKeyZ peers_1 = PeerManager_get_peer_node_ids(&net1);
			LDK::CVec_PublicKeyZ peers_2 = PeerManager_get_peer_node_ids(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen == 1) { break; }
			std::this_thread::yield();
		}
	}
	void stop() {
		interrupt_socket_handling(node1_handler);
		interrupt_socket_handling(node2_handler);
	}
};

#else // REAL_NET

uintptr_t sock_send_data(void *this_arg, LDKu8slice data, bool resume_read) {
	return write((int)((long)this_arg), data.data, data.datalen);
}
void sock_disconnect_socket(void *this_arg) {
	close((int)((long)this_arg));
}
bool sock_eq(const void *this_arg, const LDKSocketDescriptor *other_arg) {
	return this_arg == other_arg->this_arg;
}
uint64_t sock_hash(const void *this_arg) {
	return (uint64_t)this_arg;
}
void sock_read_data_thread(int rdfd, LDKSocketDescriptor *peer_descriptor, LDKPeerManager *pm) {
	unsigned char buf[1024];
	LDKu8slice data;
	data.data = buf;
	ssize_t readlen = 0;
	while ((readlen = read(rdfd, buf, 1024)) > 0) {
		data.datalen = readlen;
		LDK::CResult_boolPeerHandleErrorZ res = PeerManager_read_event(&*pm, peer_descriptor, data);
		if (!res->result_ok) {
			peer_descriptor->disconnect_socket(peer_descriptor->this_arg);
			return;
		}
		PeerManager_process_events(pm);
	}
	PeerManager_socket_disconnected(&*pm, peer_descriptor);
}

class PeersConnection {
	int pipefds_1_to_2[2];
	int pipefds_2_to_1[2];
	std::thread t1, t2;
	LDKSocketDescriptor sock1, sock2;

public:
	PeersConnection(LDK::ChannelManager& cm1, LDK::ChannelManager& cm2, LDK::PeerManager& net1, LDK::PeerManager& net2) {
		assert(!pipe(pipefds_1_to_2));
		assert(!pipe(pipefds_2_to_1));

		sock1 = LDKSocketDescriptor {
			.this_arg = (void*)(long)pipefds_1_to_2[1],
			.send_data = sock_send_data,
			.disconnect_socket = sock_disconnect_socket,
			.eq = sock_eq,
			.hash = sock_hash,
			.cloned = NULL,
			.free = NULL,
		};

		sock2 = LDKSocketDescriptor {
			.this_arg = (void*)(long)pipefds_2_to_1[1],
			.send_data = sock_send_data,
			.disconnect_socket = sock_disconnect_socket,
			.eq = sock_eq,
			.hash = sock_hash,
			.cloned = NULL,
			.free = NULL,
		};

		t1 = std::thread(&sock_read_data_thread, pipefds_2_to_1[0], &sock1, &net1);
		t2 = std::thread(&sock_read_data_thread, pipefds_1_to_2[0], &sock2, &net2);

		// Note that we have to bind the result to a C++ class to make sure it gets free'd
		LDK::CResult_CVec_u8ZPeerHandleErrorZ con_res = PeerManager_new_outbound_connection(&net1, ChannelManager_get_our_node_id(&cm2), sock1);
		assert(con_res->result_ok);
		LDK::CResult_NonePeerHandleErrorZ con_res2 = PeerManager_new_inbound_connection(&net2, sock2);
		assert(con_res2->result_ok);

		auto writelen = write(pipefds_1_to_2[1], con_res->contents.result->data, con_res->contents.result->datalen);
		assert(writelen > 0 && uint64_t(writelen) == con_res->contents.result->datalen);

		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PublicKeyZ peers_1 = PeerManager_get_peer_node_ids(&net1);
			LDK::CVec_PublicKeyZ peers_2 = PeerManager_get_peer_node_ids(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen ==1) { break; }
			std::this_thread::yield();
		}
	}

	void stop() {
		close(pipefds_1_to_2[0]);
		close(pipefds_2_to_1[0]);
		close(pipefds_1_to_2[1]);
		close(pipefds_2_to_1[1]);
		t1.join();
		t2.join();
	}
};
#endif // !REAL_NET

struct CustomMsgQueue {
	std::vector<LDK::Type> msgs;
};

uint16_t custom_msg_type_id(const void *this_arg) {
	return 8888;
}
LDKCVec_u8Z custom_msg_bytes(const void *this_arg) {
	uint8_t *bytes = (uint8_t *) malloc(1024);
	memset(bytes, 42, 1024);
	return LDKCVec_u8Z {
		.data = bytes, .datalen = 1024
	};
}
LDKStr custom_msg_debug(const void *this_arg) {
	return LDKStr {
		.chars = NULL, .len = 0, .chars_is_owned = false
	};
}

LDKCResult_COption_TypeZDecodeErrorZ read_custom_message(const void* this_arg, uint16_t type_id, LDKu8slice buf) {
	assert(type_id == 8888);
	assert(buf.datalen == 1024);
	uint8_t cmp[1024];
	memset(cmp, 42, 1024);
	assert(!memcmp(cmp, buf.data, 1024));
	return CResult_COption_TypeZDecodeErrorZ_ok(COption_TypeZ_some(LDKType {
		.this_arg = NULL,
		.type_id = custom_msg_type_id,
		.debug_str = custom_msg_debug,
		.free = NULL,
	}));
}

LDKCResult_NoneLightningErrorZ handle_custom_message(const void* this_arg, struct LDKType msg, struct LDKPublicKey _sender_node_id) {
	CustomMsgQueue* arg = (CustomMsgQueue*) this_arg;
	arg->msgs.push_back(std::move(msg));
	return CResult_NoneLightningErrorZ_ok();
}
LDKCVec_C2Tuple_PublicKeyTypeZZ never_send_custom_msgs(const void* this_arg) {
	return LDKCVec_C2Tuple_PublicKeyTypeZZ {
		.data = NULL, .datalen = 0
	};
}

LDKCVec_C2Tuple_PublicKeyTypeZZ create_custom_msg(const void* this_arg) {
	const LDKPublicKey *counterparty_node_id = (const LDKPublicKey *)this_arg;
	LDKCVec_C2Tuple_PublicKeyTypeZZ ret = {
		.data = ((LDKC2Tuple_PublicKeyTypeZ*)malloc(sizeof(LDKC2Tuple_PublicKeyTypeZ))),
		.datalen = 1
	};
	ret.data[0].a = *counterparty_node_id;
	ret.data[0].b = LDKType {
		.this_arg = NULL,
		.type_id = custom_msg_type_id,
		.debug_str = custom_msg_debug,
		.write = custom_msg_bytes,
		.free = NULL,
	};
	return ret;
}

int main() {
	uint8_t channel_open_header[80];
	uint8_t header_1[80];
	uint8_t header_2[80];
	memcpy(channel_open_header, channel_open_block, 80);
	memcpy(header_1, block_1, 80);
	memcpy(header_2, block_2, 80);

	LDKPublicKey null_pk;
	memset(&null_pk, 0, sizeof(null_pk));

	LDKThirtyTwoBytes random_bytes;
	LDKThirtyTwoBytes chain_tip;
	memset(&chain_tip, 0, sizeof(chain_tip)); // channel_open_header's prev_blockhash is all-0s

	LDKNetwork network = LDKNetwork_Testnet;

	// Trait implementations:
	LDKBroadcasterInterface broadcast {
		.this_arg = NULL,
		.broadcast_transaction = broadcast_tx,
		.free = NULL,
	};

	// Instantiate classes for the nodes that don't get reloaded on a ser-des reload
	LDKLogger logger1 {
		.this_arg = (void*)1,
		.log = print_log,
		.free = NULL,
	};

	NodeMonitors mons1;
	mons1.logger = &logger1;
	LDKWatch mon1 {
		.this_arg = &mons1,
		.watch_channel = add_channel_monitor,
		.update_channel = update_channel_monitor,
		.release_pending_monitor_events = monitors_pending_monitor_events,
		.free = NULL,
	};

	LDK::NetGraphMsgHandler net_graph1 = NetGraphMsgHandler_new(NetworkGraph_new(genesis_hash), COption_AccessZ_none(), logger1);
	LDKSecretKey node_secret1;

	LDKLogger logger2 {
		.this_arg = (void*)2,
		.log = print_log,
		.free = NULL,
	};

	NodeMonitors mons2;
	mons2.logger = &logger2;
	LDKWatch mon2 {
		.this_arg = &mons2,
		.watch_channel = add_channel_monitor,
		.update_channel = update_channel_monitor,
		.release_pending_monitor_events = monitors_pending_monitor_events,
		.free = NULL,
	};

	LDK::NetGraphMsgHandler net_graph2 = NetGraphMsgHandler_new(NetworkGraph_new(genesis_hash), COption_AccessZ_none(), logger2);
	LDKSecretKey node_secret2;

	LDK::CVec_u8Z cm1_ser = LDKCVec_u8Z {}; // ChannelManager 1 serialization at the end of the ser-des scope
	LDK::CVec_u8Z cm2_ser = LDKCVec_u8Z {}; // ChannelManager 2 serialization at the end of the ser-des scope

	{ // Scope for the ser-des reload
		// Instantiate classes for node 1:
		uint8_t node_seed[32];
		memset(&node_seed, 0, 32);
		LDK::KeysManager keys1 = KeysManager_new(&node_seed, 0, 0);
		LDK::KeysInterface keys_source1 = KeysManager_as_KeysInterface(&keys1);
		node_secret1 = keys_source1->get_node_secret(keys_source1->this_arg);

		LDK::ChannelManager cm1 = ChannelManager_new(fee_est, mon1, broadcast, logger1, KeysManager_as_KeysInterface(&keys1), UserConfig_default(), ChainParameters_new(network, BestBlock_new(chain_tip, 0)));

		LDK::CVec_ChannelDetailsZ channels = ChannelManager_list_channels(&cm1);
		assert(channels->datalen == 0);

		LDK::MessageHandler msg_handler1 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm1), NetGraphMsgHandler_as_RoutingMessageHandler(&net_graph1));

		LDK::IgnoringMessageHandler ignoring_handler1 = IgnoringMessageHandler_new();
		LDK::CustomMessageHandler custom_msg_handler1 = IgnoringMessageHandler_as_CustomMessageHandler(&ignoring_handler1);

		random_bytes = keys_source1->get_secure_random_bytes(keys_source1->this_arg);
		LDK::PeerManager net1 = PeerManager_new(std::move(msg_handler1), node_secret1, &random_bytes.data, logger1, std::move(custom_msg_handler1));

		// Demo getting a channel key and check that its returning real pubkeys:
		LDK::Sign chan_signer1 = keys_source1->get_channel_signer(keys_source1->this_arg, false, 42);
		chan_signer1->BaseSign.set_pubkeys(&chan_signer1->BaseSign); // Make sure pubkeys is defined
		LDKPublicKey payment_point = ChannelPublicKeys_get_payment_point(&chan_signer1->BaseSign.pubkeys);
		assert(memcmp(&payment_point, &null_pk, sizeof(null_pk)));

		// Instantiate classes for node 2:
		memset(&node_seed, 1, 32);
		LDK::KeysManager keys2 = KeysManager_new(&node_seed, 0, 0);
		LDK::KeysInterface keys_source2 = KeysManager_as_KeysInterface(&keys2);
		node_secret2 = keys_source2->get_node_secret(keys_source2->this_arg);

		LDK::ChannelHandshakeConfig handshake_config2 = ChannelHandshakeConfig_default();
		ChannelHandshakeConfig_set_minimum_depth(&handshake_config2, 2);
		LDK::UserConfig config2 = UserConfig_default();
		UserConfig_set_own_channel_config(&config2, std::move(handshake_config2));

		LDK::ChannelManager cm2 = ChannelManager_new(fee_est, mon2, broadcast, logger2, KeysManager_as_KeysInterface(&keys2), std::move(config2), ChainParameters_new(network, BestBlock_new(chain_tip, 0)));

		LDK::CVec_ChannelDetailsZ channels2 = ChannelManager_list_channels(&cm2);
		assert(channels2->datalen == 0);

		LDK::RoutingMessageHandler net_msgs2 = NetGraphMsgHandler_as_RoutingMessageHandler(&net_graph2);
		LDK::CResult_ChannelAnnouncementDecodeErrorZ chan_ann = ChannelAnnouncement_read(LDKu8slice { .data = valid_node_announcement, .datalen = sizeof(valid_node_announcement) });
		assert(chan_ann->result_ok);
		LDK::CResult_boolLightningErrorZ ann_res = net_msgs2->handle_channel_announcement(net_msgs2->this_arg, chan_ann->contents.result);
		assert(ann_res->result_ok);

		LDK::MessageHandler msg_handler2 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm2), std::move(net_msgs2));

		LDK::IgnoringMessageHandler ignoring_handler2 = IgnoringMessageHandler_new();
		LDK::CustomMessageHandler custom_msg_handler2 = IgnoringMessageHandler_as_CustomMessageHandler(&ignoring_handler2);

		random_bytes = keys_source2->get_secure_random_bytes(keys_source2->this_arg);
		LDK::PeerManager net2 = PeerManager_new(std::move(msg_handler2), node_secret2, &random_bytes.data, logger2, std::move(custom_msg_handler2));

		// Open a connection!
		PeersConnection conn(cm1, cm2, net1, net2);

		// Note that we have to bind the result to a C++ class to make sure it gets free'd
		LDK::CResult_NoneAPIErrorZ res = ChannelManager_create_channel(&cm1, ChannelManager_get_our_node_id(&cm2), 40000, 1000, 42, UserConfig_default());
		assert(res->result_ok);
		PeerManager_process_events(&net1);

		LDK::CVec_ChannelDetailsZ new_channels = ChannelManager_list_channels(&cm1);
		assert(new_channels->datalen == 1);
		LDK::ChannelCounterparty new_channels_counterparty = ChannelDetails_get_counterparty(&new_channels->data[0]);
		LDKPublicKey chan_open_pk = ChannelCounterparty_get_node_id(&new_channels_counterparty);
		assert(!memcmp(chan_open_pk.compressed_form, ChannelManager_get_our_node_id(&cm2).compressed_form, 33));

		while (true) {
			LDK::CVec_ChannelDetailsZ new_channels_2 = ChannelManager_list_channels(&cm2);
			if (new_channels_2->datalen == 1) {
				// Sample getting our counterparty's init features (which used to be hard to do without a memory leak):
				LDK::ChannelCounterparty new_channels_2_counterparty = ChannelDetails_get_counterparty(&new_channels_2->data[0]);
				const LDK::InitFeatures init_feats = ChannelCounterparty_get_features(&new_channels_2_counterparty);
				assert(init_feats->inner != NULL);
				break;
			}
			std::this_thread::yield();
		}

		LDKEventsProvider ev1 = ChannelManager_as_EventsProvider(&cm1);
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev1.process_pending_events(ev1.this_arg, handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_FundingGenerationReady);
				assert(queue.events[0]->funding_generation_ready.user_channel_id == 42);
				assert(queue.events[0]->funding_generation_ready.channel_value_satoshis == 40000);
				assert(queue.events[0]->funding_generation_ready.output_script.datalen == 34);
				assert(!memcmp(queue.events[0]->funding_generation_ready.output_script.data, channel_open_block + 58 + 81, 34));
				LDKTransaction funding_transaction { .data = const_cast<uint8_t*>(channel_open_block + 81), .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false };

				LDK::CResult_NoneAPIErrorZ fund_res = ChannelManager_funding_transaction_generated(&cm1, &queue.events[0]->funding_generation_ready.temporary_channel_id.data, funding_transaction);
				assert(fund_res->result_ok);
				break;
			}
			std::this_thread::yield();
		}

		// We observe when the funding signed messages have been exchanged by
		// waiting for two monitors to be registered.
		assert(num_txs_broadcasted == 0);
		PeerManager_process_events(&net1);
		while (num_txs_broadcasted != 1) {
			std::this_thread::yield();
		}

		LDK::Listen listener1 = ChannelManager_as_Listen(&cm1);
		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = channel_open_block, .datalen = sizeof(channel_open_block) }, 1);

		LDK::Listen listener2 = ChannelManager_as_Listen(&cm2);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = channel_open_block, .datalen = sizeof(channel_open_block) }, 1);

		LDKCVec_C2Tuple_usizeTransactionZZ txdata { .data = (LDKC2Tuple_usizeTransactionZ*)malloc(sizeof(LDKC2Tuple_usizeTransactionZ)), .datalen = 1 };
		*txdata.data = C2Tuple_usizeTransactionZ_new(0, LDKTransaction { .data = (uint8_t*)channel_open_block + 81, .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false });
		mons1.ConnectBlock(&channel_open_header, 1, txdata, broadcast, fee_est);

		txdata = LDKCVec_C2Tuple_usizeTransactionZZ { .data = (LDKC2Tuple_usizeTransactionZ*)malloc(sizeof(LDKC2Tuple_usizeTransactionZ)), .datalen = 1 };
		*txdata.data = C2Tuple_usizeTransactionZ_new(0, LDKTransaction { .data = (uint8_t*)channel_open_block + 81, .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false });
		mons2.ConnectBlock(&channel_open_header, 1, txdata, broadcast, fee_est);

		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = block_1, .datalen = sizeof(block_1) }, 2);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = block_1, .datalen = sizeof(block_1) }, 2);
		mons1.ConnectBlock(&header_1, 2, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);
		mons2.ConnectBlock(&header_1, 2, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);

		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = block_2, .datalen = sizeof(block_1) }, 3);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = block_2, .datalen = sizeof(block_1) }, 3);
		mons1.ConnectBlock(&header_2, 3, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);
		mons2.ConnectBlock(&header_2, 3, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);

		PeerManager_process_events(&net1);
		PeerManager_process_events(&net2);

		// Now send funds from 1 to 2!
		uint64_t channel_scid;
		while (true) {
			LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
			if (outbound_channels->datalen == 1) {
				const LDKChannelDetails *channel = &outbound_channels->data[0];
				LDK::ChannelCounterparty counterparty = ChannelDetails_get_counterparty(channel);
				// Note that the channel ID is the same as the channel txid reversed as the output index is 0
				uint8_t expected_chan_id[32];
				for (int i = 0; i < 32; i++) { expected_chan_id[i] = channel_open_txid[31-i]; }
				assert(!memcmp(ChannelDetails_get_channel_id(channel), expected_chan_id, 32));
				assert(!memcmp(
					ChannelCounterparty_get_node_id(&counterparty).compressed_form,
					ChannelManager_get_our_node_id(&cm2).compressed_form, 33));
				assert(ChannelDetails_get_channel_value_satoshis(channel) == 40000);
				// We opened the channel with 1000 push_msat:
				assert(ChannelDetails_get_outbound_capacity_msat(channel) ==
					40000*1000 - 1000 - 1000 * ChannelCounterparty_get_unspendable_punishment_reserve(&counterparty));
				int64_t inbound_capacity = ((int64_t)1000) - ChannelCounterparty_get_unspendable_punishment_reserve(&counterparty);
				if (inbound_capacity < 0) inbound_capacity = 0;
				assert(ChannelDetails_get_inbound_capacity_msat(channel) == (uint64_t)inbound_capacity);
				assert(ChannelDetails_get_is_usable(channel));
				LDK::COption_u64Z scid_opt = ChannelDetails_get_short_channel_id(channel);
				assert(scid_opt->some);
				channel_scid = scid_opt->some;
				break;
			}
			std::this_thread::yield();
		}

		LDKCOption_u64Z min_value = {
			.tag = LDKCOption_u64Z_Some,
			.some = 5000,
		};
		LDK::CResult_InvoiceSignOrCreationErrorZ invoice = create_invoice_from_channelmanager(&cm2,
			KeysManager_as_KeysInterface(&keys2),
			LDKCurrency_Bitcoin, min_value,
			LDKStr {
				.chars = (const uint8_t *)"Invoice Description",
				.len =             strlen("Invoice Description"),
				.chars_is_owned = false
			});
		assert(invoice->result_ok);
		LDKThirtyTwoBytes payment_hash;
		memcpy(payment_hash.data, Invoice_payment_hash(invoice->contents.result), 32);

		{
			LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
			LDK::NetworkGraph graph_2_ref = NetGraphMsgHandler_get_network_graph(&net_graph2);
			LDK::CResult_RouteLightningErrorZ route = get_route(ChannelManager_get_our_node_id(&cm1), &graph_2_ref, ChannelManager_get_our_node_id(&cm2), LDKInvoiceFeatures {
					.inner = NULL, .is_owned = false
				}, &outbound_channels, Invoice_route_hints(invoice->contents.result),
				5000, Invoice_min_final_cltv_expiry(invoice->contents.result), logger1);
			assert(route->result_ok);
			LDK::CVec_CVec_RouteHopZZ paths = Route_get_paths(route->contents.result);
			assert(paths->datalen == 1);
			assert(paths->data[0].datalen == 1);
			assert(!memcmp(RouteHop_get_pubkey(&paths->data[0].data[0]).compressed_form,
				ChannelManager_get_our_node_id(&cm2).compressed_form, 33));
			assert(RouteHop_get_short_channel_id(&paths->data[0].data[0]) == channel_scid);
			LDK::CResult_NonePaymentSendFailureZ send_res = ChannelManager_send_payment(&cm1, route->contents.result, payment_hash, Invoice_payment_secret(invoice->contents.result));
			assert(send_res->result_ok);
		}

		mons_updated = 0;
		PeerManager_process_events(&net1);
		while (mons_updated != 4) {
			std::this_thread::yield();
		}

		// Check that we received the payment!
		LDKEventsProvider ev2 = ChannelManager_as_EventsProvider(&cm2);
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(ev2.this_arg, handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_PendingHTLCsForwardable);
				break;
			}
			std::this_thread::yield();
		}
		ChannelManager_process_pending_htlc_forwards(&cm2);
		PeerManager_process_events(&net2);

		mons_updated = 0;
		LDKThirtyTwoBytes payment_preimage;
		{
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(ev2.this_arg, handler);
			assert(queue.events.size() == 1);
			assert(queue.events[0]->tag == LDKEvent_PaymentReceived);
			assert(!memcmp(queue.events[0]->payment_received.payment_hash.data, payment_hash.data, 32));
			assert(queue.events[0]->payment_received.purpose.tag == LDKPaymentPurpose_InvoicePayment);
			assert(!memcmp(queue.events[0]->payment_received.purpose.invoice_payment.payment_secret.data,
					Invoice_payment_secret(invoice->contents.result).data, 32));
			assert(queue.events[0]->payment_received.amt == 5000);
			memcpy(payment_preimage.data, queue.events[0]->payment_received.purpose.invoice_payment.payment_preimage.data, 32);
			assert(ChannelManager_claim_funds(&cm2, payment_preimage));
		}
		PeerManager_process_events(&net2);
		// Wait until we've passed through a full set of monitor updates (ie new preimage + CS/RAA messages)
		while (mons_updated != 5) {
			std::this_thread::yield();
		}
		{
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev1.process_pending_events(ev1.this_arg, handler);
			assert(queue.events.size() == 1);
			assert(queue.events[0]->tag == LDKEvent_PaymentSent);
			assert(!memcmp(queue.events[0]->payment_sent.payment_preimage.data, payment_preimage.data, 32));
		}

		conn.stop();

		cm1_ser = ChannelManager_write(&cm1);
		cm2_ser = ChannelManager_write(&cm2);
	}

	LDK::CVec_ChannelMonitorZ mons_list1 = LDKCVec_ChannelMonitorZ { .data = (LDKChannelMonitor*)malloc(sizeof(LDKChannelMonitor)), .datalen = 1 };
	assert(mons1.mons.size() == 1);
	mons_list1->data[0] = *& std::get<1>(mons1.mons[0]); // Note that we need a reference, thus need a raw clone here, which *& does.
	mons_list1->data[0].is_owned = false; // XXX: God this sucks
	uint8_t node_seed[32];
	memset(&node_seed, 0, 32);
	LDK::KeysManager keys1 = KeysManager_new(&node_seed, 1, 0);
	LDK::KeysInterface keys_source1 = KeysManager_as_KeysInterface(&keys1);

	LDK::ChannelManagerReadArgs cm1_args = ChannelManagerReadArgs_new(KeysManager_as_KeysInterface(&keys1), fee_est, mon1, broadcast, logger1, UserConfig_default(), std::move(mons_list1));
	LDK::CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ cm1_read =
		C2Tuple_BlockHashChannelManagerZ_read(LDKu8slice { .data = cm1_ser->data, .datalen = cm1_ser -> datalen}, std::move(cm1_args));
	assert(cm1_read->result_ok);
	LDK::ChannelManager cm1(std::move(cm1_read->contents.result->b));

	LDK::CVec_ChannelMonitorZ mons_list2 = LDKCVec_ChannelMonitorZ { .data = (LDKChannelMonitor*)malloc(sizeof(LDKChannelMonitor)), .datalen = 1 };
	assert(mons2.mons.size() == 1);
	mons_list2->data[0] = *& std::get<1>(mons2.mons[0]); // Note that we need a reference, thus need a raw clone here, which *& does.
	mons_list2->data[0].is_owned = false; // XXX: God this sucks
	memset(&node_seed, 1, 32);
	LDK::KeysManager keys2 = KeysManager_new(&node_seed, 1, 0);

	LDK::ChannelManagerReadArgs cm2_args = ChannelManagerReadArgs_new(KeysManager_as_KeysInterface(&keys2), fee_est, mon2, broadcast, logger2, UserConfig_default(), std::move(mons_list2));
	LDK::CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ cm2_read =
		C2Tuple_BlockHashChannelManagerZ_read(LDKu8slice { .data = cm2_ser->data, .datalen = cm2_ser -> datalen}, std::move(cm2_args));
	assert(cm2_read->result_ok);
	LDK::ChannelManager cm2(std::move(cm2_read->contents.result->b));

	// Attempt to close the channel...
	uint8_t chan_id[32];
	for (int i = 0; i < 32; i++) { chan_id[i] = channel_open_txid[31-i]; }
	LDK::CResult_NoneAPIErrorZ close_res = ChannelManager_close_channel(&cm1, &chan_id);
	assert(!close_res->result_ok); // Note that we can't close while disconnected!

	// Open a connection!
	LDK::MessageHandler msg_handler1 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm1), NetGraphMsgHandler_as_RoutingMessageHandler(&net_graph1));
	random_bytes = keys_source1->get_secure_random_bytes(keys_source1->this_arg);

	LDKPublicKey chan_2_node_id = ChannelManager_get_our_node_id(&cm2);
	LDKCustomMessageHandler custom_msg_handler1 = {
		.this_arg = &chan_2_node_id,
		.handle_custom_message = NULL, // We only create custom messages, not handle them
		.get_and_clear_pending_msg = create_custom_msg,
		.CustomMessageReader = LDKCustomMessageReader {
			.this_arg = NULL,
			.read = read_custom_message,
			.free = NULL,
		},
		.free = NULL,
	};
	LDK::PeerManager net1 = PeerManager_new(std::move(msg_handler1), node_secret1, &random_bytes.data, logger1, std::move(custom_msg_handler1));

	LDK::MessageHandler msg_handler2 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm2), NetGraphMsgHandler_as_RoutingMessageHandler(&net_graph2));
	CustomMsgQueue peer_2_custom_messages;
	LDKCustomMessageHandler custom_msg_handler2 = {
		.this_arg = &peer_2_custom_messages,
		.handle_custom_message = handle_custom_message,
		.get_and_clear_pending_msg = never_send_custom_msgs,
		.CustomMessageReader = LDKCustomMessageReader {
			.this_arg = NULL,
			.read = read_custom_message,
			.free = NULL,
		},
		.free = NULL,
	};
	random_bytes = keys_source1->get_secure_random_bytes(keys_source1->this_arg);
	LDK::PeerManager net2 = PeerManager_new(std::move(msg_handler2), node_secret2, &random_bytes.data, logger2, std::move(custom_msg_handler2));

	PeersConnection conn(cm1, cm2, net1, net2);

	while (true) {
		// Wait for the channels to be considered up once the reestablish messages are processed
		LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
		if (outbound_channels->datalen == 1) {
			break;
		}
	}

	// Actually close the channel
	num_txs_broadcasted = 0;
	close_res = ChannelManager_close_channel(&cm1, &chan_id);
	assert(close_res->result_ok);
	PeerManager_process_events(&net1);
	while (num_txs_broadcasted != 2) {
		std::this_thread::yield();
	}
	LDK::CVec_ChannelDetailsZ chans_after_close1 = ChannelManager_list_channels(&cm1);
	assert(chans_after_close1->datalen == 0);
	LDK::CVec_ChannelDetailsZ chans_after_close2 = ChannelManager_list_channels(&cm2);
	assert(chans_after_close2->datalen == 0);

	conn.stop();

	assert(peer_2_custom_messages.msgs.size() != 0);

	// Few extra random tests:
	LDKSecretKey sk;
	memset(&sk, 42, 32);
	LDKThirtyTwoBytes kdiv_params;
	memset(&kdiv_params, 43, 32);
	LDK::InMemorySigner signer = InMemorySigner_new(sk, sk, sk, sk, sk, random_bytes, 42, kdiv_params);
}
