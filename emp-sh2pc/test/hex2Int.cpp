#include <vector>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

typedef unsigned int word32;

char binary_2_hex_digit(const string &bin) {
    if (bin.length() != 4) {
        throw invalid_argument("Binary string length must be 4");
    }

    bitset<4> bits(bin);
    unsigned long decimalValue = bits.to_ulong();

    if (decimalValue < 10) {
        return '0' + decimalValue;
    } else {
        return 'A' + (decimalValue - 10);
    }
}

string emp_binary_2_hex(string binary) {
    if (binary.length() % 4 != 0) {
        throw invalid_argument("Binary string length must be a multiple of 4");
    }

    reverse(binary.begin(), binary.end());

    stringstream hexStream;
    for (size_t i = 0; i < binary.length(); i += 4) {
        string binGroup = binary.substr(i, 4);
        hexStream << binary_2_hex_digit(binGroup);
    }

    return hexStream.str();
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	// setup_semi_honest(io, party);
    setup_plain_prot(true, "hex2int.txt");

    word32 digest[8];
    digest[0] = 0xffffffedL;
    digest[1] = 0xffffffffL;
    digest[2] = 0xffffffffL;
    digest[3] = 0xffffffffL;
    digest[4] = 0xffffffffL;
    digest[5] = 0xffffffffL;
    digest[6] = 0xffffffffL;
    digest[7] = 0x7fffffffL;

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    vector<Bit> digest_bits;
    for (int i = 0; i < 8; i++) {
        word32 tmp = digest[i];
        for (int j = 0; j < 32; j++) {
            digest_bits.push_back((tmp & 1) != 0 ? one : zero);
            tmp >>= 1;
        }
    }

    Integer digest_i (digest_bits);
    // Integer digest_i (256, 0, ALICE);

    digest[0] = 0xfffffffcL;
    digest[1] = 0xffffffffL;
    digest[2] = 0xffffffffL;
    digest[3] = 0xffffffffL;
    digest[4] = 0xffffffffL;
    digest[5] = 0xffffffffL;
    digest[6] = 0xffffffffL;
    digest[7] = 0x97ffffffL;

    digest_bits.clear();
    for (int i = 0; i < 8; i++) {
        word32 tmp = digest[i];
        for (int j = 0; j < 32; j++) {
            digest_bits.push_back((tmp & 1) != 0 ? one : zero);
            tmp >>= 1;
        }
    }

    Integer digest_i_2 (digest_bits);
    // Integer digest_i_2 (256, 0, BOB);

    cout << emp_binary_2_hex(digest_i.reveal<string>()) << endl;
    cout << emp_binary_2_hex(digest_i_2.reveal<string>()) << endl;

    Bit to_mod = (digest_i_2 < Integer(1, 0, PUBLIC)) | (digest_i_2 > digest_i);
    vector<Bit> to_mod_v;
    for (int i = 0; i < 260; i++)
        to_mod_v.push_back(to_mod);

    Integer to_mod_i (to_mod_v);

    Integer mod = digest_i_2 - (digest_i & to_mod_i);

    cout << emp_binary_2_hex(mod.reveal<string>()) << endl;

	// finalize_semi_honest();
    finalize_plain_prot();
	delete io;
}
