#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
	
    string a_1 = "000000a1";
    string a_2 = "00a2";
    string a_3 = "000000a3";
    string a_4 = "000000a4";
    string a_5 = "000000a5";
    string b_1 = "000000b1";
    string b_2 = "00b2";
    string b_3 = "000000b3";

    if (party == ALICE) {
        b_1 = "00000000";
        b_2 = "0000";
        b_3 = "00000000";
    } else if (party == BOB) {
        a_1 = "00000000";
        a_2 = "0000";
        a_3 = "00000000";
        a_4 = "00000000";
        a_5 = "00000000";
    }

    cout << party << ": 0x" << a_1 << endl;
    cout << party << ": 0x" << a_2 << endl;
    cout << party << ": 0x" << a_3 << endl;
    cout << party << ": 0x" << a_4 << endl;
    cout << party << ": 0x" << a_5 << endl;
    cout << party << ": 0x" << b_1 << endl;
    cout << party << ": 0x" << b_2 << endl;
    cout << party << ": 0x" << b_3 << endl;

    string res = ag2pc_exec(party, io, circuit_file_location+"input_test_3.txt", 
        b_1 + b_2 + b_3 + a_1 + a_2 + a_3 + a_4 + a_5
    );

    cout << party << ": res: 0x" << res << endl;
	delete io;
	return 0;
}
