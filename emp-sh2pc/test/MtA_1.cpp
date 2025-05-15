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
    setup_plain_prot(true, "mta_1.txt");

    Integer b {256, 0, BOB};
    Integer b_mask {256, 0, BOB};

    Integer a {256, 0, ALICE};
    Integer a_mask {256, 0, ALICE};

    Integer result {256, 0};

    result = a * b + b_mask;

    (result ^ a_mask).reveal<string>();

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}
