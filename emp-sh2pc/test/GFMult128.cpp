#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstring>

using namespace emp;
using namespace std;

// const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
// string file = circuit_file_location+"/bristol_format/sha-256-multiblock.txt";

void GFMult128(Integer &res, const Integer &mult1_o, const Integer &mult2_o) {
    Integer p {128, 0x87, PUBLIC};
    res = Integer {128, 0, PUBLIC};
    Integer mult1 = mult1_o;
    Integer mult2 = mult2_o;
    Integer one {128, 1, PUBLIC};
    Integer msb {128, 1, PUBLIC};
    Integer lsb_mult1;
    Integer xor_val;
    Integer is_mod;

    msb = msb << 127;

    for (int i = 0; i < 128; i++) {
        lsb_mult1 = mult1 & one;
        xor_val = mult2 * lsb_mult1;
        res = res ^ xor_val;

        is_mod = mult2 & msb;
        is_mod = is_mod / msb;
        xor_val = p * is_mod;

        mult2 = mult2 << 1;
        mult1 = mult1 >> 1;
        mult2 = mult2 ^ xor_val;
    }
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "GFMult128_.txt");

    unsigned char key_alice[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
    };

    bool key_alice_plaintext[16 * 8];
	for (int i = 0; i < 16; i++) {
		int w = key_alice[i];
		for (int j = 0; j < 8; j++) {
			key_alice_plaintext[i * 8 + 7 - j] = w & 1;
			w >>= 1;
		}
	}

    unsigned char key_bob[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
    };

    bool key_bob_plaintext[16 * 8];
	for (int i = 0; i < 16; i++) {
		int w = key_bob[i];
		for (int j = 0; j < 8; j++) {
			key_bob_plaintext[i * 8 + 7 - j] = w & 1;
			w >>= 1;
		}
	}

    block alice_input_o[128];
    block alice_input[128];
    ProtocolExecution::prot_exec->feed(alice_input_o, ALICE, key_alice_plaintext, 128);

    block bob_input_o[128];
    block bob_input[128];
    ProtocolExecution::prot_exec->feed(bob_input_o, BOB, key_bob_plaintext, 128);
 
    for (int i = 0; i < 128; i++) {
        // alice_input[i] = alice_input_o[127 - i];
        // bob_input[i] = bob_input_o[127 - i];
        alice_input[i] = alice_input_o[i];
        bob_input[i] = bob_input_o[i];
    }

    block zero = CircuitExecution::circ_exec->public_label(false);

    block middle_results[128][128];
	memset(middle_results, 0, sizeof(block) * 128 * 128);

	for(int i = 0; i < 128; i++) {
		middle_results[0][i] = alice_input[i];
	}

	for(int i = 1; i < 128; i++) {
		middle_results[i][0] = middle_results[i - 1][127];

		for (int j = 1; j < 128; j++) {
			middle_results[i][j] = middle_results[i - 1][j - 1];
		}

		middle_results[i][7] = CircuitExecution::circ_exec->xor_gate(middle_results[i - 1][6], middle_results[i - 1][127]);
		middle_results[i][2] = CircuitExecution::circ_exec->xor_gate(middle_results[i - 1][1], middle_results[i - 1][127]);
		middle_results[i][1] = CircuitExecution::circ_exec->xor_gate(middle_results[i - 1][0], middle_results[i - 1][127]);
	}

	block result[256];
	for(int i = 0; i < 256; i++) {
		result[i] = zero;
	}
	for(int i = 0; i < 128; i++) {
		result[i] = bob_input[i];
	}
    for (int i = 0; i < 128; i++) {
        for (int j = 0; j < 128; j++) {
            block tmp = CircuitExecution::circ_exec->and_gate(middle_results[i][j], result[i]);
            result[128 + j] = CircuitExecution::circ_exec->xor_gate(result[128 + j], tmp);
        }
    }

    bool output[128];

    block reverse_res[128];
    // reverse the bits
    for (int i = 0; i < 128; i++) {
        // reverse_res[i] = result[255 - i];
        reverse_res[i] = result[i + 128];
    }

    ProtocolExecution::prot_exec->reveal(output, PUBLIC, reverse_res, 128);

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}
