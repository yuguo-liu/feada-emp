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
	string a_1 = "20";
	string a_2 = "30";
	string b_1 = "40";
	string b_2 = "50";

    string hash = ag2pc_exec(party, io, circuit_file_location+"innerproduct.txt",
        a_1 + a_2 + b_1 + b_2
    );

    cout << hash << endl;

	delete io;
	return 0;
}