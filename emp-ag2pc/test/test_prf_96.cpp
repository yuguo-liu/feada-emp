#include <emp-tool/emp-tool.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "test/single_execution.h"
#include "test/plaintext_sha256.h"
#include <time.h>
using namespace std;
using namespace emp;

#define IPAD "36"
#define OPAD "5c"
#define DEBUG false

string sha256_padding(const string &hex_str);
string zero_padding(const string &hex_str, size_t target_length);
int get_padding_length(const string &hex_str);
string utf8_to_hex(const std::string &utf8_str);

string iv_0 = "e6679056a175e6dd4ecf763c5caff2a5fe4a708a3116a0d9d59bc1f898b307da";

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
    // io->set_nodelay();
    // string alice_mask = generate_random_hex_string(64);
    // string bob_mask = generate_random_hex_string(64);
    string alice_mask = "0000000000000000000000000000000000000000000000000000000000000000";
    string bob_mask = "0000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(64);
    } else {
        bob_mask = generate_random_hex_string(64);
    }

	string msg = "client finished";
	msg = utf8_to_hex(msg);
    string seed = "c4b4ebe8578f4ca02a8d833d2cde604ba8896ab61ae7fdd274a8df438c903f56";

    string share_1 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    string share_2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        share_1 = "bce43e9894393a897121bab60d3581b4bf36738dde8fa202554bbb16931d7897cec17bb36c3519dd827f7fb4f0962af0";
    } else {
        share_2 = "29260e341e76c7c05fe77ab4a607fc54359fb953f7db9299e5b3746a5351b232685cfae47cc361351b4d19a547537b16";
    }

    string V = msg + seed;
    string V_zeros = "";

    for (int i = 0; i < V.length(); i++) {
        V_zeros += "0";
    }

    int len_share_1 = share_1.length();
    for (int i = 0; i < 128 - len_share_1; i++) {
        share_1 += "0";
        share_2 += "0";
    }

    string ipad = "";
    string opad = "";
    for (int i = 0; i < 64; i++) {
        ipad += IPAD;
        opad += OPAD;
    }

    string share_1_ipad = xorHexStrings(share_1, ipad);
    string share_1_opad = xorHexStrings(share_1, opad);

    string share_2_ipad = share_2;
    string share_2_opad = share_2;

    V = sha256_padding(share_1_ipad + V).substr(share_1_ipad.length());

    if (DEBUG) cout << "cal f_H(IV_0, k xor opad)" << endl;
    // string f_H_opad = ag2pc_exec(party, io, circuit_file_location+"sha256_i_2_share_msg_2_mask_1_state_o_2_share.txt",
    //     alice_mask + share_1_opad + iv_0 + bob_mask + share_2_opad
    // ).substr(64, 64);
    string f_H_opad = ag2pc_exec(party, io, circuit_file_location+"KDF/sha256_i_2_share_msg_2_mask_1_state_o_2_share.txt",
        bob_mask + share_2_opad + iv_0 + alice_mask + share_1_opad
    ).substr(64, 64);

    string f_H_opad_alice = xorHexStrings(f_H_opad, alice_mask);
    string f_H_opad_bob = bob_mask;

    if (DEBUG) cout << "cal f_H(IV_0, k xor ipad)" << endl;
	// string f_H_ipad = ag2pc_exec(party, io, circuit_file_location+"sha256_i_2_share_msg_1_state_o_hash_state.txt",
	// 	share_1_ipad + iv_0 + share_2_ipad
	// ).substr(64, 64);
    string f_H_ipad = ag2pc_exec(party, io, circuit_file_location+"KDF/sha256_i_2_share_msg_1_state_o_hash_state.txt",
		share_2_ipad + iv_0 + share_1_ipad
	).substr(64, 64);

    if (DEBUG) cout << "cal rest of f_H(f_H(f_H(IV_0, k xor ipad), m_1), m_2)" << endl;
	string f_H_ipad_V = plaintext_sha256(
		V,
		f_H_ipad
	);

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_V)" << endl;
    f_H_ipad_V = sha256_padding(share_1_opad + f_H_ipad_V).substr(share_1_opad.length());
	// string M_1 = ag2pc_exec(party, io, circuit_file_location+"sha256_i_2_share_state_1_msg_o_hash.txt",
    //     f_H_opad_alice + f_H_opad_bob + f_H_ipad_V
    // ).substr(0, 64);
    string M_1 = ag2pc_exec(party, io, circuit_file_location+"KDF/sha256_i_2_share_state_1_msg_o_hash.txt",
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_V
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M reuse the component" << endl;
    string M_1_padded = sha256_padding(share_1_ipad + M_1).substr(share_1_ipad.length());
    string f_H_ipad_M = plaintext_sha256(
        M_1_padded,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_M)" << endl;
    f_H_ipad_M = sha256_padding(share_1_opad + f_H_ipad_M).substr(share_1_opad.length());
    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M: " << f_H_ipad_M.length() * 4 << endl;
    } 
    // string M_2 = ag2pc_exec(party, io, circuit_file_location+"sha256_i_2_share_state_1_msg_o_hash.txt",
    //     f_H_opad_alice + f_H_opad_bob + f_H_ipad_M
    // ).substr(0, 64);
    string M_2 = ag2pc_exec(party, io, circuit_file_location+"KDF/sha256_i_2_share_state_1_msg_o_hash.txt",
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_M
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M_1_V reuse the component" << endl;
    string M_1_V = sha256_padding(share_1_ipad + M_1 + msg + seed).substr(share_1_ipad.length());
    string f_H_ipad_M_1_V = plaintext_sha256(
        M_1_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H_ipad_M_2_V reuse the component" << endl;
    string M_2_V = sha256_padding(share_1_ipad + M_2 + msg + seed).substr(share_1_ipad.length());
    string f_H_ipad_M_2_V = plaintext_sha256(
        M_2_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal ms & h(server key)" << endl;
    // alice_mask = generate_random_hex_string(96);
    // bob_mask = generate_random_hex_string(96);
    alice_mask = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bob_mask = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(112);
    } 
    
    f_H_ipad_M_1_V = sha256_padding(share_1_opad + f_H_ipad_M_1_V).substr(share_1_opad.length());
    f_H_ipad_M_2_V = sha256_padding(share_1_opad + f_H_ipad_M_2_V).substr(share_1_opad.length());

    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_ipad_M_1_V: " << f_H_ipad_M_1_V.length() * 4 << endl;
        cout << "length of alice_mask: " << alice_mask.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M_2_V: " << f_H_ipad_M_2_V.length() * 4 << endl;
        cout << "length of bob_mask: " << bob_mask.length() * 4 << endl;
    } 
    // string ms_str = ag2pc_exec(party, io, circuit_file_location+"o_sha256_i_2_share_state_2_full_msg_o_2_share_hash_1_key_hash copy.txt",
    //     f_H_opad_alice + f_H_ipad_M_1_V + alice_mask + f_H_opad_bob + f_H_ipad_M_2_V + bob_mask
    // );
    string ms_str = ag2pc_exec(party, io, circuit_file_location+"KDF/sha256_i_2_share_state_2_full_msg_o_2_share_hash_1_key_hash.txt",
        f_H_opad_bob + f_H_ipad_M_1_V + bob_mask + f_H_opad_alice + f_H_ipad_M_2_V + alice_mask
    );

    string ms = ms_str.substr(0, 112);
    string hash_server_key = ms_str.substr(112, 64);
    string ms_share = (party == ALICE) ? xorHexStrings(ms, alice_mask) : bob_mask;

    if (party == ALICE) {
        cout << "Alice gets ms_share: 0x" << ms_share << endl;
        cout << "Alice gets key hash: 0x" << hash_server_key << endl;
    } else {
        cout << "Bob gets ms_share: 0x" << ms_share << endl;
        cout << "Bob gets key hash: 0x" << hash_server_key << endl;
    }

	delete io;
	return 0;
}

string sha256_padding(const string &hex_str) {
    int original_length = hex_str.length();
    int additional_length = 112 - (original_length % 128);
    if (additional_length <= 0) additional_length += 128;

    size_t padded_length = original_length + additional_length + 16;

    // Add the '1' bit (0x80 in hex, i.e., 8 bits) to the end of the hex string
    string padded_str = hex_str + "80";

    // Add '0's to make the string length 64-byte aligned minus the 64-bit length
    while (padded_str.length() < padded_length - 16) {
        padded_str += "00";
    }

    // Append the length of the original string (in bits) in hex (64-bit length)
    stringstream length_stream;
    length_stream << setfill('0') << setw(16) << hex << original_length * 4;
    padded_str += length_stream.str();

    return padded_str;
}

string zero_padding(const string &hex_str, size_t target_length) {
    string filled_str = hex_str;
    while (filled_str.length() < target_length) {
        filled_str += "00";
    }
    return filled_str;
}

int get_padding_length(const string &hex_str) {
	int original_length = hex_str.length();
    int additional_length = 112 - (original_length % 128);
    if (additional_length <= 0) additional_length += 128;
	return original_length + additional_length;
}

string utf8_to_hex(const std::string &utf8_str) {
    stringstream hex_stream;

    for (unsigned char c : utf8_str) {
        hex_stream << std::setw(2) << std::setfill('0') << std::hex << (int)c;
    }

    return hex_stream.str();
}