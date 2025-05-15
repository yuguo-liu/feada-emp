#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstring>

using namespace emp;
using namespace std;

typedef unsigned int word32;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string file = circuit_file_location+"/bristol_format/sha-256-multiblock.txt";

void change_endian(block *input, block *output, int input_len);
void print_hash(block *output);
int get_padded_len(int L);
void padding(block *input, block *output, int input_len);
void sha256(block *input, block *output, int input_len);
void sha256_test();


int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    setup_semi_honest(io, party);

    sha256_test();

    finalize_semi_honest();
    delete io;

    return 0;
}

void change_endian(block *input, block *output, int input_len) {
    if (input_len % 8 != 0) {
        error("The circuit synthesizer can only convert the endianness for bytes.");
    }

    int num_bytes = input_len / 8;
    for (int i = 0; i < num_bytes; i++) {
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = input[i * 8 + j];
        }
    }
}

void print_hash(block *output) {
    unsigned char digest_char[32];
    memset(digest_char, 0, 32);

    bool output_bool[256];
    ProtocolExecution::prot_exec->reveal(output_bool, PUBLIC, (block *) output, 256);

//    cout << "print hash: ";
//    for (int i = 0; i < 256; i++) {
//        output_bool[i] ? cout << "1" : cout << "0";
//    }
//    cout << endl;

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            int w = 1;
            for (int k = 0; k < 8; k++) {
                digest_char[i * 4 + j] += output_bool[i * 32 + 8 * j + k] * w;
                w <<= 1;
            }
        }
    }

    printf("Output: 0x");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest_char[i]);
    }
    printf("\n");
}

int get_padded_len(int L) {
    // find K such that L + 1 + K + 64 is a multiple of 512
    int K = 512 - ((L + 1 + 64) % 512);
    K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

    return L + 1 + K + 64;
}

void padding(block *input, block *output, int input_len) {
    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    for (int i = 0; i < input_len; i++) {
        output[i] = input[i];
    }

    int offset = input_len;

    // add one bit "1"
    output[offset++] = one;

    // find K such that L + 1 + K + 64 is a multiple of 512
    int K = 512 - ((input_len + 1 + 64) % 512);
    K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

    // add K bits "0"
    for (int i = 0; i < K; i++) {
        output[offset++] = zero;
    }

    if (input_len > 8191) {
        error("The circuit synthesizer assumes that input_len is small (< 8192 bits).");
    }

    // add the length of L
    // for simplicity, assume that the higher 48 bits are zero---since our input is going to be small anyway
    // the remaining 16 bits give you 2^15-1 bits to spend, about 8KB
    for (int i = 0; i < 48; i++) {
        output[offset++] = zero;
    }

    for (int i = 0; i < 16; i++) {
        int bool_test = (input_len & (1 << (16 - 1 - i))) != 0;
        output[offset++] = bool_test ? one : zero;
    }
}

void sha256(block *input, block *output, int input_len) {
    // new input
    auto input_new = new block[input_len];

    // reverse the bits
    change_endian(input, input_new, input_len);

    // first, do the padding
    int padded_len = get_padded_len(input_len);

    // allocate the padding
    block *padded_input = new block[padded_len];

    // pad
    padding(input_new, padded_input, input_len);

    delete[] input_new;

    // number of blocks
    int num_blocks = padded_len / 512;

    // start the hashing
    // first block
    word32 digest[8];
    digest[0] = 0x6A09E667L;
    digest[1] = 0xBB67AE85L;
    digest[2] = 0x3C6EF372L;
    digest[3] = 0xA54FF53AL;
    digest[4] = 0x510E527FL;
    digest[5] = 0x9B05688CL;
    digest[6] = 0x1F83D9ABL;
    digest[7] = 0x5BE0CD19L;

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    auto input_to_sha256_circuit = new block[768];
    block output_from_sha256_circuit[256];

//    cout << "digest bits: ";
    block digest_bits[256];
    for (int i = 0; i < 8; i++) {
        word32 tmp = digest[i];
        for (int j = 0; j < 32; j++) {
            digest_bits[i * 32 + j] = (tmp & 1) != 0 ? one : zero;
//            (tmp & 1) != 0 ? cout << "1" : cout << "0";
            tmp >>= 1;
        }
    }
//    cout << endl;

    for (int b = 0; b < num_blocks; b++) {
        printf("-- sha256\n");
        // the first 512 bits -> the padded data
        // the rest of the 256 bits -> the 8 * 32 bits of the digest values

        for (int i = 0; i < 512; i++) {
            input_to_sha256_circuit[i] = padded_input[b * 512 + i];
        }

        for (int i = 0; i < 256; i++) {
            input_to_sha256_circuit[512 + i] = digest_bits[i];
        }

        BristolFormat bf(file.c_str());
        bf.compute(output_from_sha256_circuit, input_to_sha256_circuit, input_to_sha256_circuit);

        for (int i = 0; i < 256; i++) {
            digest_bits[i] = output_from_sha256_circuit[i];
        }
    }

//    cout << "111" << endl;
   print_hash(digest_bits);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 8; k++) {
                output[i * 32 + j * 8 + k] = output_from_sha256_circuit[i * 32 + 8 * (3 - j) + k];
            }
        }
    }

    delete[] padded_input;
    delete[] input_to_sha256_circuit;
}

void sha256_test() {
    printf("SHA256 test:\n");
    block output[256];
    block input[2048];

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    for (int i = 0; i < 2048; i++) {
        input[i] = zero;
    }

//    // empty sha256
//    cout << "empty" << endl;
//    sha256(input, output, 0);
//    print_hash(output);

    // hash of 8 bits "1"
    // needs three blocks
//    cout << "16 bits \"1\": 0xFAFA" << endl;
//    for (int i = 0; i < 16; i++) {
//        input[i] = one;
//    }
//    input[5] = zero;
//    input[7] = zero;
//    input[13] = zero;
//    input[15] = zero;
//    sha256(input, output, 16);
//    print_hash(output);

    // hash of 8 bits "1"
    // needs three blocks
    cout << "512 bits \"1\"" << endl;
    for (int i = 0; i < 512; i++) {
        input[i] = one;
    }
    sha256(input, output, 512);
    print_hash(output);

    // hash of 256 bits "1"
//    cout << "256 bits \"1\"" << endl;
//    for (int i = 0; i < 256; i++) {
//        input[i] = one;
//    }
//    sha256(input, output, 256);
//    print_hash(output);

    // hash of 512 bits "1"
    // needs another block
//    cout << "512 bits \"1\"" << endl;
//    for (int i = 0; i < 512; i++) {
//        input[i] = one;
//    }
//    sha256(input, output, 512);
//    print_hash(output);

    // hash of 1024 bits "1"
    // needs three blocks
//    cout << "1024 bits \"1\"" << endl;
//    for (int i = 0; i < 1024; i++) {
//        input[i] = one;
//    }
//    sha256(input, output, 1024);
//    print_hash(output);
}
