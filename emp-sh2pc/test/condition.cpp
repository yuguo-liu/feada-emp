#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "condition.txt");

    Integer alice {32, 0, ALICE};
    Integer bob {32, 0, BOB};

    if ((alice.geq(bob)).reveal<bool>()) {
        alice.reveal<int>();
    } else {
        bob.reveal<int>();
    }

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}