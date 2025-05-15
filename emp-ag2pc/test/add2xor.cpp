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
	string a = "000000000000000000000000000000000000000000000000000000000000000000";
	string b = "000000000000000000000000000000000000000000000000000000000000000000";
	string p = "00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

	string a_mask = "000000000000000000000000000000000000000000000000000000000000000000";
	string b_mask = "000000000000000000000000000000000000000000000000000000000000000000";

	if (party == ALICE) {
		a = "16A8036C3E8961FCBA5B8DB08162616DA0E37B83E0A406796915614A0FA28F11";
		a = "00" + a;
        a = hex_string_reverse_bits(a);
		a_mask = hex_string_reverse_bits(generate_random_hex_string(64));
		a_mask = a_mask + "00";
	} else {
		b = "225EF5B4ACE046557BA937FE63F0D521A0DC577FEA8FD7590E61E64C957D3C06";
		b = "00" + b;
        b = hex_string_reverse_bits(b);
		b_mask = hex_string_reverse_bits(generate_random_hex_string(64));
		b_mask = b_mask + "00";
	}

	p = hex_string_reverse_bits(p);

    string res = ag2pc_exec(party, io, circuit_file_location+"ECtF/add_2_xor_p256.txt",
        b + b_mask + p + a + a_mask + p
    );

    // res = hex_string_reverse_bits(res);

	cout << party << " gets 0x" << res << endl;

	string out = (party == ALICE) ? a_mask : xorHexStrings(res, b_mask);

    out = hex_string_reverse_bits(out);

	cout << out << endl;

	delete io;
	return 0;
}