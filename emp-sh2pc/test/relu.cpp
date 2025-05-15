#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

using namespace emp;
using namespace std;


int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    setup_plain_prot(true, "relu.txt");

    Float x (0.0f, ALICE);
    Float o (0.0f, PUBLIC);

    

    finalize_plain_prot();
    delete io;

    return 0;
}