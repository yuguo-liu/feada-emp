#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <iostream>
#include <random>
using namespace emp;
using namespace std;

#define DEBUG false
#define LOG false

void random_bool_sequence(bool* seq, const int len) {
    random_device rd;
    for (int i = 0; i < len; i++) {
        seq[i] = rd() % 2 == 0;
    }
}

void bignum_to_blocks(BIGNUM *bn, block *block1, block *block2) {
    int len = BN_num_bytes(bn);
    
    if (len > 32) {
        fprintf(stderr, "BIGNUM should be within 256bits\n");
        return;
    }

    unsigned char *bn_bytes = (unsigned char*) OPENSSL_malloc(len);
    if (bn_bytes == NULL) {
        fprintf(stderr, "memory allocation failed\n");
        return;
    }

    BN_bn2bin(bn, bn_bytes);

    *block1 = _mm_setzero_si128();
    *block2 = _mm_setzero_si128();

    // Copy bytes into the blocks
    if (len <= 16) {
        for (int i = 0; i < len; i++) {
            ((unsigned char*)&(*block2))[15 - i] = bn_bytes[i];
        }
    } else {
        for (int i = (32 - len); i < 16; i++) {
            ((unsigned char*)&(*block1))[15 - i] = bn_bytes[i - (32 - len)];
        }
        for (int i = 16; i < 32; i++) {
            ((unsigned char*)&(*block2))[31 - i] = bn_bytes[i - (32 - len)];
        }
    }

    OPENSSL_free(bn_bytes);
}

void blocks_to_bignum(block block1, block block2, BIGNUM **bn) {
    unsigned char bn_bytes[32] = {0};  // Initialize to zero to handle padding

    unsigned char *block1_bytes = (unsigned char*)&block1;
    for (int i = 0; i < 16; i++) {
        bn_bytes[i] = block1_bytes[15 - i];
    }

    unsigned char *block2_bytes = (unsigned char*)&block2;
    for (int i = 0; i < 16; i++) {
        bn_bytes[16 + i] = block2_bytes[15 - i];
    }

    *bn = BN_bin2bn(bn_bytes, 32, NULL);  // Create BIGNUM from stripped bytes
}

template<typename T>
void mta(BIGNUM **share, T *ot, int party, NetIO *io, BIGNUM **data, const int len_data, BIGNUM *P, BN_CTX *ctx) {
    const int security_param = 128;
    int param = 256 + security_param;

    clock_t t_s, t_e;

    BIGNUM *_res = BN_new();
    BN_zero(_res);
    for (int i = 0; i < len_data; i++) {
        BIGNUM *datum = data[i];
        if (party == ALICE) {
            // step 1: random sample vector delta
            t_s = clock();
            BIGNUM *Delta[param];
            for (int i = 0; i < param; i++) {
                Delta[i] = BN_new();
                BN_rand_range(Delta[i], P);
                // cout << BN_bn2hex(Delta[i]) << endl;
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 1: random sample vector delta [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 2: generate Z_0 & Z_1
            t_s = clock();
            BIGNUM *Z_0[param];
            BIGNUM *Z_1[param];

            for (int i = 0; i < param; i++) {
                Z_0[i] = BN_new();
                Z_1[i] = BN_new();
                BN_mod_sub(Z_0[i], Delta[i], datum, P, ctx);
                BN_mod_add(Z_1[i], Delta[i], datum, P, ctx);
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 2: generate Z_0 & Z_1 [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 3: raise OTs and send the msgs
            t_s = clock();
            block Z_0_blocks[param * 2];
            block Z_1_blocks[param * 2];

            for (int i = 0; i < param; i++) {
                bignum_to_blocks(Z_0[i], &Z_0_blocks[i * 2], &Z_0_blocks[i * 2 + 1]);
                bignum_to_blocks(Z_1[i], &Z_1_blocks[i * 2], &Z_1_blocks[i * 2 + 1]);
            }

            t_e = clock();
            if (DEBUG) cout << party << ": step 3.1: pre-phase raise OTs and send the msgs [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // ot->send_rot(Z_0_blocks, Z_1_blocks, param * 2);
            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << Z_0_blocks[i * 2] << " " << Z_0_blocks[i * 2 + 1] << endl;
                cout << "alice: " << Z_1_blocks[i * 2] << " " << Z_1_blocks[i * 2 + 1] << endl;
            }
            
            t_s = clock();
            ot->send(Z_0_blocks, Z_1_blocks, param * 2);
        	t_e = clock();

            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << BN_bn2hex(Z_0[i]) << " / " << BN_bn2hex(Z_1[i]) << endl;
            }

            if (DEBUG) cout << party << ": step 3.2: OT-phase raise OTs and send the msgs [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 4: recv V
            t_s = clock();
            block V_blocks[param * 2];
            io->recv_block(V_blocks, param * 2);

            BIGNUM *V[param];
            for (int i = 0; i < param; i++) {
                V[i] = BN_new();
                blocks_to_bignum(V_blocks[i * 2], V_blocks[i * 2 + 1], &V[i]);
            }
            t_e = clock();

            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << BN_bn2hex(V[i]) << endl;
            }

            if (DEBUG) cout << party << ": step 4: recv V [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 5: calculate the share
            t_s = clock();
            BIGNUM *res = BN_new();
            BIGNUM *tmp = BN_new();
            BN_zero(res);
            for (int i = 0; i < param; i++) {
                BN_mod_mul(tmp, Delta[i], V[i], P, ctx);
                BN_mod_add(res, res, tmp, P, ctx);
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 5: calculate the share [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            BN_mod_sub(_res, _res, res, P, ctx);
        } else {
            // step 1: randomly sample B and V[:param-1]
            if (DEBUG) cout << party << ": step 1: randomly sample B" << endl;
            bool B[param];
            random_bool_sequence(B, param);

            BIGNUM *V[param];
            BIGNUM *previous_V = BN_new();
            BN_zero(previous_V);
            
            for (int i = 0; i < param - 1; i++) {
                V[i] = BN_new();
                BN_rand_range(V[i], P);
            }

            // step 2: raise OTs and receive the msgs
            if (DEBUG) cout << party << ": step 2: raise OTs and receive the msgs" << endl;
            block Z_blocks[param * 2];
            bool B_ot[param * 2];

            for (int i = 0; i < param; i++) {
                B_ot[i * 2] = B[i];
                B_ot[i * 2 + 1] = B[i];
            }

            // ot->recv_rot(Z_blocks, B_ot, param * 2);
            t_s = clock();
            ot->recv(Z_blocks, B_ot, param * 2);
            t_e = clock();
            // cout << "ot time: " << (double) (t_e - t_s) / CLOCKS_PER_SEC << "s" << endl;

            // for (int i = 0; i < param; i++) {
            //     ot->recv(&Z_blocks[i*2], &B_ot[i*2], 2);
            // }

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob: " << Z_blocks[i * 2] << " " << Z_blocks[i * 2 + 1] << endl;
            }

            BIGNUM *Z[param];
            for (int i = 0; i < param; i++) {
                Z[i] = BN_new();
                blocks_to_bignum(Z_blocks[i * 2], Z_blocks[i * 2 + 1], &Z[i]);
            }

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob:   " << BN_bn2hex(Z[i]) << " / " << B[i] << endl;
            }

            // step 3: randomly sample V s.t. <V, t> = datum
            if (DEBUG) cout << party << ": step 3: randomly sample V s.t. <V, t> = datum" << endl;
            for (int i = 0; i < param - 1; i++) {
                if (!B[i]) {
                    BN_mod_sub(previous_V, previous_V, V[i], P, ctx);
                } else {
                    BN_mod_add(previous_V, previous_V, V[i], P, ctx);
                }
            }

            V[param - 1] = BN_new();
            if (!B[param - 1]) {
                BN_mod_sub(V[param - 1], previous_V, datum, P, ctx);
            } else {
                BN_mod_sub(V[param - 1], datum, previous_V, P, ctx);
            }

            // step 4: send V
            if (DEBUG) cout << party << ": step 4: send V" << endl;
            block V_blocks[param * 2];
            for (int i = 0; i < param; i++) {
                bignum_to_blocks(V[i], &V_blocks[i * 2], &V_blocks[i * 2 + 1]);
            }

            io->send_block(V_blocks, param * 2);

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob:   " << BN_bn2hex(V[i]) << endl;
            }

            // step 5: calculate the share
            if (DEBUG) cout << party << ": step 5: calculate the share" << endl;
            BIGNUM *res = BN_new();
            BIGNUM *tmp = BN_new();
            BN_zero(res);
            for (int i = 0; i < param; i++) {
                BN_mod_mul(tmp, Z[i], V[i], P, ctx);
                BN_mod_add(res, res, tmp, P, ctx);
            }

            BN_mod_add(_res, _res, res, P, ctx);
        }
    }

    *share = _res;
}

void hex_string_to_unsigned_char_array(const std::string& hexStr, unsigned char* byteArray) {
    if (hexStr.length() != 64) {
        std::cerr << "Error: The input hex string must be 64 characters long!" << std::endl;
        return;
    }

    for (size_t i = 0; i < 32; ++i) {
        std::stringstream ss;
        ss << std::hex << hexStr.substr(i * 2, 2);
        int byte;
        ss >> byte;
        byteArray[i] = static_cast<unsigned char>(byte);
    }
}

/**
 * ====== p1 ======
 * x_1 = 0x2cd56ef48c6719d88aac6d2d6a7218b5f7f60ecd6432ff0b7097bf43e92a21ff
 * y_1 = 0x27949458e80a77b593873da0459dd617d0327c818443c42d21f84c31bc04bc8f
 * ====== p2 ======
 * x_2 = 0x5eb31ae72a5831692dee5618b7d821ef3c48174ae1ddb5da2a548a690c7012fa
 * y_2 = 0x1ef573db80aea4e254c0f8913539a732a4ce55370a63cac8835ed84f9acb85c9
 * [bob::processing time: 72.64232635498047ms][alice::processing time: 147.63975143432617ms]
 * 
 * [main::] i am here!
 * [main::] get result 0x5958a11e7d6ae46c558ff73a15c1e9d2f5f0fa7e91ad011152482dddfcf21fb6 from alice
 * [main::] get result 0x3dff22db8b95d39ee059e6014caa05db256cdaec681a8af0333678da1debf60d from bob
 * ====== p3 = p1 + p2 ======
 * y         =  0x39a6d33495877db0596c4499048e5f5753774484e06ad70536700708a43e16b9
 * x         =  0x1757c3fa0900b80b35e9dd3b626befae1b5dd56af9c78c01857ea6b81ade15d6
 * s_1       =  0x5958a11e7d6ae46c558ff73a15c1e9d2f5f0fa7e91ad011152482dddfcf21fb6
 * s_2       =  0x3dff22db8b95d39ee059e6014caa05db256cdaec681a8af0333678da1debf60d
 * s_1 + s_2 =  0x1757c3fa0900b80b35e9dd3b626befae1b5dd56af9c78c01857ea6b81ade15d6
 * [Format]  =  \x17\x57\xc3\xfa\x09\x00\xb8\x0b\x35\xe9\xdd\x3b\x62\x6b\xef\xae\x1b\x5d\xd5\x6a\xf9\xc7\x8c\x01\x85\x7e\xa6\xb8\x1a\xde\x15\xd6
 * ECtF is correct.
 */

int main(int argc, char** argv) {
    int port, party; // make sure all functions work for non-power-of-two lengths
	parse_party_and_port(argv, &party, &port);
    // NetIO *io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);

    if (argc != 6) {
        cerr << "Parameter error: expected 6, received " << argc << endl;
        exit(1);
    }
    string host = argv[5];
    NetIO *io = new NetIO(party==ALICE ? nullptr:host.c_str(), port);

    IKNP<NetIO> *ot = new IKNP<NetIO>(io, true);  // malicious OT
    // OTNP<NetIO> *ot = new OTNP<NetIO>(io);

    clock_t start_t, end_t;

    unsigned char x_chars[32], y_chars[32];
    unsigned char p_chars[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    // TODO: if x_s or y_s is shorter than 64-digits, it should be padded by zero at its front.
    if (party == ALICE) {
        string x_s = argv[3];
        string y_s = argv[4];
        if (DEBUG) cout << x_s << endl;
        if (DEBUG) cout << y_s << endl;

        if (x_s.length() != 64 || y_s.length() != 64) {
            cerr << "Parameter error: x, y of the point on p256 should be 256 bits" << endl;
            exit(2);
        }
        // unsigned char x_c[32] = {
        //     0x2c, 0xd5, 0x6e, 0xf4, 0x8c, 0x67, 0x19, 0xd8,
        //     0x8a, 0xac, 0x6d, 0x2d, 0x6a, 0x72, 0x18, 0xb5,
        //     0xf7, 0xf6, 0x0e, 0xcd, 0x64, 0x32, 0xff, 0x0b,
        //     0x70, 0x97, 0xbf, 0x43, 0xe9, 0x2a, 0x21, 0xff
        // };
        // unsigned char y_c[32] = {
        //     0x27, 0x94, 0x94, 0x58, 0xe8, 0x0a, 0x77, 0xb5,
        //     0x93, 0x87, 0x3d, 0xa0, 0x45, 0x9d, 0xd6, 0x17,
        //     0xd0, 0x32, 0x7c, 0x81, 0x84, 0x43, 0xc4, 0x2d,
        //     0x21, 0xf8, 0x4c, 0x31, 0xbc, 0x04, 0xbc, 0x8f
        // };
        unsigned char x_c[32], y_c[32];
        hex_string_to_unsigned_char_array(x_s, x_c);
        hex_string_to_unsigned_char_array(y_s, y_c);
        
        for (int i = 0; i < 32; i++) {
            x_chars[i] = x_c[i];
            y_chars[i] = y_c[i];
        }
    } else {
        string x_s = argv[3];
        string y_s = argv[4];
        if (DEBUG) cout << x_s << endl;
        if (DEBUG) cout << y_s << endl;

        if (x_s.length() != 64 || y_s.length() != 64) {
            cerr << "Parameter error: x, y of the point on p256 should be 256 bits" << endl;
            exit(2);
        }
        // unsigned char x_c[32] = {
        //     0x5e, 0xb3, 0x1a, 0xe7, 0x2a, 0x58, 0x31, 0x69,
        //     0x2d, 0xee, 0x56, 0x18, 0xb7, 0xd8, 0x21, 0xef,
        //     0x3c, 0x48, 0x17, 0x4a, 0xe1, 0xdd, 0xb5, 0xda,
        //     0x2a, 0x54, 0x8a, 0x69, 0x0c, 0x70, 0x12, 0xfa
        // };
        // unsigned char y_c[32] = {
        //     0x1e, 0xf5, 0x73, 0xdb, 0x80, 0xae, 0xa4, 0xe2,
        //     0x54, 0xc0, 0xf8, 0x91, 0x35, 0x39, 0xa7, 0x32,
        //     0xa4, 0xce, 0x55, 0x37, 0x0a, 0x63, 0xca, 0xc8,
        //     0x83, 0x5e, 0xd8, 0x4f, 0x9a, 0xcb, 0x85, 0xc9
        // };
        unsigned char x_c[32], y_c[32];
        hex_string_to_unsigned_char_array(x_s, x_c);
        hex_string_to_unsigned_char_array(y_s, y_c);
        
        for (int i = 0; i < 32; i++) {
            x_chars[i] = x_c[i];
            y_chars[i] = y_c[i];
        }
    }

    // initialize the bignum
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return 1;
    }

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *zero = BN_new();

    BN_bin2bn(x_chars, sizeof(x_chars), x);
    BN_bin2bn(y_chars, sizeof(y_chars), y);
    BN_bin2bn(p_chars, sizeof(p_chars), p);
    BN_zero(zero);

    if (DEBUG) cout << party << "'s x: 0x" << BN_bn2hex(x) << endl;
    if (DEBUG) cout << party << "'s y: 0x" << BN_bn2hex(y) << endl;

    start_t = clock();
    /**
     * step 1: rho <-R- Z_p
     */
    BIGNUM *rho = BN_new();
    BN_rand_range(rho, p);

    /**
     * step 2: alpha = MtA(), Alice sends [-x,rho], bob sends [rho,x]
     */
    BIGNUM *mta_data[2], *minus_x = BN_new();
    mta_data[0] = BN_new();
    mta_data[1] = BN_new();
    BN_mod_sub(minus_x, zero, x, p, ctx);
    if (party == ALICE) {
        mta_data[0] = minus_x;
        mta_data[1] = rho;
    } else {
        mta_data[0] = rho;
        mta_data[1] = x;
    }

    BIGNUM *alpha = BN_new();
    mta(&alpha, ot, party, io, mta_data, 2, p, ctx);

    if (DEBUG) cout << party << "'s mta input 0: 0x" << BN_bn2hex(mta_data[0]) << endl;
    if (DEBUG) cout << party << "'s mta input 1: 0x" << BN_bn2hex(mta_data[1]) << endl;
    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(alpha) << endl;

    /**
     * step 3: theta = -x * rho + alpha / x * rho + alpha
     */
    BIGNUM *theta_my = BN_new();
    if (party == ALICE) {
        BN_mod_mul(theta_my, minus_x, rho, p, ctx);
    } else {
        BN_mod_mul(theta_my, x, rho, p, ctx);
    }
    BN_mod_add(theta_my, theta_my, alpha, p, ctx);

    /**
     * step 4: jointly compute theta = theta_1 + theta_2
     */
    BIGNUM *theta = BN_new();
    if (party == ALICE) {
        block theta_blocks[2];
        bignum_to_blocks(theta_my, &theta_blocks[0], &theta_blocks[1]);
        io->send_block(theta_blocks, 2);

        io->recv_block(theta_blocks, 2);
        blocks_to_bignum(theta_blocks[0], theta_blocks[1], &theta);
        BN_mod_add(theta, theta, theta_my, p, ctx);
    } else {
        block theta_blocks[2];
        io->recv_block(theta_blocks, 2);
        blocks_to_bignum(theta_blocks[0], theta_blocks[1], &theta);

        bignum_to_blocks(theta_my, &theta_blocks[0], &theta_blocks[1]);
        io->send_block(theta_blocks, 2);
        BN_mod_add(theta, theta, theta_my, p, ctx);
    }

    /**
     * step 5: eta = rho * theta^-1
     */
    BIGNUM *eta = BN_new();
    BIGNUM *theta_inverse = BN_new();

    BN_mod_inverse(theta_inverse, theta, p, ctx);
    BN_mod_mul(eta, rho, theta_inverse, p, ctx);

    /**
     * step 6: beta = MtA(), Alice sends [-y,eta], bob sends [eta,y]
     */
    BIGNUM *mta_2_data[2], *minus_y = BN_new();
    mta_2_data[0] = BN_new();
    mta_2_data[1] = BN_new();
    BN_mod_sub(minus_y, zero, y, p, ctx);
    if (party == ALICE) {
        mta_2_data[0] = minus_y;
        mta_2_data[1] = eta;
    } else {
        mta_2_data[0] = eta;
        mta_2_data[1] = y;
    }

    BIGNUM *beta = BN_new();
    mta(&beta, ot, party, io, mta_2_data, 2, p, ctx);

    if (DEBUG) cout << party << "'s mta input 0: 0x" << BN_bn2hex(mta_2_data[0]) << endl;
    if (DEBUG) cout << party << "'s mta input 1: 0x" << BN_bn2hex(mta_2_data[1]) << endl;
    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(beta) << endl;

    /**
     * step 7: lambda = -y * eta + beta / lambda = y * eta + beta
     */
    BIGNUM *lambda = BN_new();
    if (party == ALICE) {
        BN_mod_mul(lambda, minus_y, eta, p, ctx);
    } else {
        BN_mod_mul(lambda, y, eta, p, ctx);
    }
    BN_mod_add(lambda, lambda, beta, p, ctx);

    /**
     * step 8: gamma = MtA(), Alice sends [lambda], bob sends [lambda]
     */
    BIGNUM *gamma = BN_new();
    mta(&gamma, ot, party, io, &lambda, 1, p, ctx);

    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(gamma) << endl;

    /**
     * step 9: s = 2 * gamma + lambda^2 - x
     */
    BIGNUM *s = BN_new();
    BIGNUM *double_gamma = BN_new();
    BIGNUM *lambda_square = BN_new();
    BIGNUM *two = BN_new();

    unsigned char two_c[1] = {0x02};
    BN_bin2bn(two_c, 1, two);

    BN_mod_mul(double_gamma, gamma, two, p, ctx);
    BN_mod_mul(lambda_square, lambda, lambda, p, ctx);

    BN_mod_add(s, double_gamma, lambda_square, p, ctx);
    BN_mod_sub(s, s, x, p, ctx);
    end_t = clock();

    if (DEBUG) cout << party <<"'s ECtF output: 0x" << BN_bn2hex(s) << endl;
    if (DEBUG) cout << party << ": ECtF duration: [" << (double) (end_t - start_t) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;
    cout << BN_bn2hex(s) << endl;
}

/**
 * // test mta
    BIGNUM *in[2];
    in[0] = BN_new();
    in[1] = BN_new();
    BN_rand_range(in[0], p);
    BN_rand_range(in[1], p);

    cout << party << " in1: 0x" << BN_bn2hex(in[0]) << endl;
    cout << party << " in2: 0x" << BN_bn2hex(in[1]) << endl;

    BIGNUM *out = BN_new();
    start_t = clock();
    mta(&out, ot, party, io, in, 2, p, ctx);
    end_t = clock();

    cout << "time mta: " << (double) (end_t - start_t) / CLOCKS_PER_SEC * 1000 << "ms" << endl;

    cout << party << " out: 0x" << BN_bn2hex(out) << endl;

    if (party == ALICE) {
        BIGNUM *bob_in1 = BN_new();
        BIGNUM *bob_in2 = BN_new();
        BIGNUM *bob_out = BN_new();
        block a[6];
        io->recv_block(a, 6);

        blocks_to_bignum(a[0], a[1], &bob_in1);
        blocks_to_bignum(a[2], a[3], &bob_in2);
        blocks_to_bignum(a[4], a[5], &bob_out);

        BN_mod_add(out, out, bob_out, p, ctx);
        BN_mod_mul(in[0], in[0], bob_in1, p, ctx);
        BN_mod_mul(in[1], in[1], bob_in2, p, ctx);
        BN_mod_add(in[0], in[0], in[1], p, ctx);

        cout << "multiplication: 0x" << BN_bn2hex(in[0]) << endl;
        cout << "addition:       0x" << BN_bn2hex(out) << endl;
    } else {
        block a[6];
        bignum_to_blocks(in[0], &a[0], &a[1]);
        bignum_to_blocks(in[1], &a[2], &a[3]);
        bignum_to_blocks(out, &a[4], &a[5]);
        io->send_block(a, 6);
    }

    // end test mta
 */