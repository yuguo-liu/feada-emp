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

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);

//	io->set_nodelay();
	string a = "0000000000000000000000000000000000000000000000000000000000000000";
	string b = "0000000000000000000000000000000000000000000000000000000000000000";

	string a_mask = "0000000000000000000000000000000000000000000000000000000000000000";
	string b_mask = "0000000000000000000000000000000000000000000000000000000000000000";

	if (party == ALICE) {
		a = "409c3d5327d593bad40c625bb5fc293e2b2f569a21f881b3b18d34c9f4106b78";
        a = hex_string_reverse_bits(a);
		a_mask = hex_string_reverse_bits(generate_random_hex_string(64));
	} else {
		b = "c7c8f148c6d32278cbd099147f9342859313c5b46761211c7e1b0a6c37e1441a";
        b = hex_string_reverse_bits(b);
		b_mask = hex_string_reverse_bits(generate_random_hex_string(64));
	}

    string res = ag2pc_exec(party, io, circuit_file_location+"ECtF/add_2_xor_p256.txt",
        b + b_mask + a + a_mask
    );

    res = hex_string_reverse_bits(res);

	cout << party << " gets 0x" << res << endl;

	string out = (party == ALICE) ? a_mask : xorHexStrings(res, b_mask);

    out = hex_string_reverse_bits(out);

	cout << party << " gets 0x" << out << endl;

	delete io;
	return 0;
}