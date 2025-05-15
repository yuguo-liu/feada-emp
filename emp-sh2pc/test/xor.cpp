#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstring>

using namespace emp;
using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string file = circuit_file_location+"/bristol_format/sha-256-multiblock.txt";

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "xor_32.txt");

    Integer a {32, 0, ALICE};
    Integer b {32, 0, BOB};

    Integer c = a ^ b;

    for (int i = 0; i < 32; i++) {
        c.bits[i].reveal();
    }

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}
