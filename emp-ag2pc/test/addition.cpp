#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
	string in = party == ALICE ? "0001100002345671" : "0765432100002200";

    string res = ag2pc_exec(party, io, circuit_file_location+"xor_32.txt", in);

    cout << party << ": res: 0x" << res << endl;
	delete io;
	return 0;
}
