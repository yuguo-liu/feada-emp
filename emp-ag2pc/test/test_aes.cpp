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
	string key = "00000000000000000000000000000000";
	string m   = "40000000000000000000000000000000";
    string m_1 = key + m;
    string m_2 = "0000000000000000000000000000000000000000000000000000000000000000";

    string c = ag2pc_exec(party, io, circuit_file_location+"AES/aes_2pc.txt",
        m_1 + m_2
    );

    cout << party << ": c: " << c << endl;

	delete io;
	return 0;
}