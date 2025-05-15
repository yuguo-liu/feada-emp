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
    setup_plain_prot(true, "innerproduct.txt");

    Integer alice_1 {8, 0, ALICE};
    Integer alice_2 {8, 0, ALICE};
    Integer bob_1 {8, 0, BOB};
    Integer bob_2 {8, 0, BOB};

    Integer product_1 = alice_1 * bob_1 + alice_2 * bob_2;
    Integer product_2 = alice_1 * bob_2 + alice_2 * bob_1;

    product_1.reveal<int>();
    product_2.reveal<int>();

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}