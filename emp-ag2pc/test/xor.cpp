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
	string a = "b5a44712e6f0964539c7adf326b631be5c38fc0b9552be48a190841ce6c3049c6d4259ccfbe2316a0143cd2f08147d84";
	string b = "68564b8edd0bf7919c292dcde4c31a48269c350afb5190a98718d40f19dccbc89ce7c1ed0e2eae2c35963c96d345adb7";

    string hash = ag2pc_exec(party, io, circuit_file_location+"xor_384.txt",
        a + b
    );

	cout << party << ": a: " << a << endl;
	cout << party << ": b: " << b << endl;
	cout << party << ": c: " << xorHexStrings(a, b) << endl;
    cout << party << ": d: " << hash << endl;

	delete io;
	return 0;
}