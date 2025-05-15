#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
#include "test/aes128/aes128gcm.h"
using namespace std;
using namespace emp;

#define BLOCK 10
#define ADD_DATA_BLOCK 3

void hex_str_2_unsigned_char(string s, unsigned char* uc);
void print_unsigned_char(unsigned char* uc, int len);
string unsigned_char_2_hex_str(unsigned char* uc, int len);
string utf8_to_hex(const std::string &utf8_str);
string int_to_hex(const int num);
string generate_random_hex_string(size_t length);
string xorHexStrings(const std::string& hexStr1, const std::string& hexStr2);
string hex_to_utf8(const string& hex);

string io_alice_ghash = "00000000000000000000000000000000";
string io_alice_pads = "";
string io_alice_h = "00000000000000000000000000000000";
string io_alice_ek_counter0 = "00000000000000000000000000000000";
string io_alice_len_a_data = "00000000000000000000000000000000";

string io_bob_ciphertext = "";
string io_bob_tag = "00000000000000000000000000000000";
string io_bob_len_c_data = "00000000000000000000000000000000";
string io_bob_mask = "00000000000000000000000000000000";
string io_bob_dummy = "00000000000000000000000000000000";

string res = "";
/**
 * Alice: BTC holder
 *      ghash: the ghash value of add data
 *      pads: the random pad of AES
 *      h: the hash key (AES(k, 0))
 *      len_a_data: the length of add data
 *      ek_counter0: the value of AES(k, CTR) n      
 *      hash_plaintext: the plaintext
 * 
 * Bob: USD holder
 *      plaintexts: the plaintext of msg
 *      len_c_data: the length of ciphertext/plaintext
 *      bob_mask: the random mask of Bob
 */


int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();

    for (int i = 0; i < BLOCK; i++) {
        io_alice_pads += "00000000000000000000000000000000";
        io_bob_ciphertext += "00000000000000000000000000000000";
    }

    if (party == ALICE) {
        const string derived_key = "ceac513493cdcebc20fc2c6a2d9d9005604a46c0b03299e52793aa33f5323ade9243f2edd16d748199d678ee62a8e16ce8d04c63ccdd104c";
        const string add_data_o = "Bob Alice Alice Bob Alice Bob Alice Bob Alice___";

        string key_c_str = derived_key.substr(0, 32);
        string iv_c_str = derived_key.substr(32, 24);
        string key_s_str = derived_key.substr(56, 32);
        string iv_s_str = derived_key.substr(88, 24);
        string add_data_str = utf8_to_hex(add_data_o);

        unsigned char key_c[16];
        unsigned char iv_c[12];
        unsigned char key_s[16];
        unsigned char iv_s[12];
        unsigned char add_data[ADD_DATA_BLOCK * 16];

        hex_str_2_unsigned_char(key_c_str, key_c);
        hex_str_2_unsigned_char(key_s_str, key_s);
        hex_str_2_unsigned_char(iv_c_str, iv_c);
        hex_str_2_unsigned_char(iv_s_str, iv_s);
        hex_str_2_unsigned_char(add_data_str, add_data);

        unsigned char h_c[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char counter_c[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char ek_counter0[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char pads[BLOCK][16];

        InitialHashSubkey(h_c, key_c);
        J0Definition(counter_c, iv_c);
        aes128e(ek_counter0, counter_c, key_c);
        IncrementingFunction(counter_c);

        for (int i = 0; i < BLOCK; i++) {
            // print_unsigned_char(counter_c, 16);
            aes128e(pads[i], counter_c, key_c);
            IncrementingFunction(counter_c);
        }
    
        // for (int i = 0; i < BLOCK; i++) {
        //     print_unsigned_char(pads[i], 16);
        // }

        unsigned char ghash_add_data[16];

        GHASH(ghash_add_data, h_c, add_data, 16 * ADD_DATA_BLOCK);

        io_alice_ghash = unsigned_char_2_hex_str(ghash_add_data, 16);

        // cout << "ALICE ghash: " << io_alice_ghash << endl;
        
        io_alice_pads = "";
        for (int i = 0; i < BLOCK; i++) {
            io_alice_pads += unsigned_char_2_hex_str(pads[i], 16);
        }

        io_alice_h = unsigned_char_2_hex_str(h_c, 16);
        io_alice_ek_counter0 = unsigned_char_2_hex_str(ek_counter0, 16);
        io_alice_len_a_data = int_to_hex(ADD_DATA_BLOCK * 128) + "0000000000000000";

        // cout << io_alice_pads << endl;

        string in = io_bob_ciphertext + io_bob_tag + io_bob_len_c_data + io_bob_mask + io_bob_dummy + io_alice_ghash + io_alice_pads + io_alice_h + io_alice_ek_counter0 + io_alice_len_a_data;

        res = ag2pc_exec(party, io, circuit_file_location + "/AES/dec_ghash_10.txt", in);

        string correctness = res.substr(0, 1);
        string plaintext = res.substr(1, BLOCK * 32);

        if (correctness == "0") {
            cerr << "ALICE: Bob's msg is invalid" << endl;
            exit(-1);
        } else {
            cout << "ALICE: Decrypt correctly" << endl;
        }

    } else {
        const string msg_o = "That is the account of Bob, transfer USD 20.00 to the account of Alice.__________________This is the account of Bob, transfer USD 20.00 to the account of Alice.";
        
        io_bob_ciphertext = "c221d79d81501656ba3d796c437eac0ce4c662c5e315d6651d7fb92f178091c4f704fdba21a164c280080c9af50b1b4f32c869a9bcefe2c09cdcb6680cd45b942b0ec6cea9088e30d0ec10f35e473c73fc6c8e0829f399efb4b4df32b07d3b74f2d127b149c0b7ecdd7d3600cf0f7131ca8c3c0194218c000a420f841a7357757cd9088f4e8f894a66039b015f6b7f40e875b62ca1fbf826aa9edb2202226801";
        io_bob_tag = "4eceb465b8d10355b7a39b02e8addb2e";
        io_bob_len_c_data = "0000000000000000" + int_to_hex(BLOCK * 128);
        io_bob_mask = generate_random_hex_string(32);

        string in = io_bob_ciphertext + io_bob_tag + io_bob_len_c_data + io_bob_mask + io_bob_dummy + io_alice_ghash + io_alice_pads + io_alice_h + io_alice_ek_counter0 + io_alice_len_a_data;

        res = ag2pc_exec(party, io, circuit_file_location + "/AES/dec_ghash_10.txt", in);

        string correctness = res.substr(0, 1);
        string plaintext = res.substr(1, BLOCK * 32);

        if (correctness == "0") {
            cout << "BOB: msg is invalid" << endl;
        }

        string mask_ciphertext = "";
        for (int i = 0; i < BLOCK; i++) {
            mask_ciphertext += io_bob_mask;
        }

        plaintext = xorHexStrings(plaintext, mask_ciphertext);
        plaintext = hex_to_utf8(plaintext);

        cout << "BOB: plaintext: " << plaintext << endl;
    }

	delete io;
	return 0;
}

void hex_str_2_unsigned_char(string s, unsigned char* uc) {
    const int len = s.length() / 2;
    for (int i = 0; i < len; i++) {
        uc[i] = stoi(s.substr(i * 2, 2).c_str(), 0, 16);
    }
}

void print_unsigned_char(unsigned char* uc, int len) {
    cout << "[";
    for (int i = 0; i < len; i++) {
        cout << setfill('0') << setw(2) << hex << (unsigned) uc[i];
        if (i < len - 1) cout << ", ";
    }
    cout << "]" << endl;
}

string unsigned_char_2_hex_str(unsigned char* uc, int len) {
    string s = "";
    for (int i = 0; i < len; i++) {
        ostringstream ss;
        ss << setfill('0') << setw(2) << hex << (int) uc[i];
        s += ss.str();
    }
    return s;
}

string utf8_to_hex(const string &utf8_str) {
    stringstream hex_stream;

    for (unsigned char c : utf8_str) {
        hex_stream << setw(2) << setfill('0') << hex << (int)c;
    }

    return hex_stream.str();
}

string int_to_hex(const int num) {
    stringstream hex_stream;

    hex_stream << setw(16) << setfill('0') << hex << num;

    return hex_stream.str();
}

string generate_random_hex_string(size_t length) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15);

    stringstream ss;

    for (size_t i = 0; i < length; ++i) {
        int random_digit = dis(gen);
        ss << hex << random_digit;
    }

    return ss.str();
}

void hexStringToBytes(const string& hexStr, unsigned char* bytes) {
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteStr = hexStr.substr(i, 2); 
        bytes[i / 2] = static_cast<unsigned char>(stoi(byteStr, nullptr, 16));
    }
}

string bytesToHexString(const unsigned char* bytes, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << setw(2) << setfill('0') << hex << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

string xorHexStrings(const string& hexStr1, const string& hexStr2) {
    if (hexStr1.length() != hexStr2.length()) {
        exit(-1);
    }

    size_t length = hexStr1.length() / 2;
    unsigned char* bytes1 = new unsigned char[length];
    unsigned char* bytes2 = new unsigned char[length];
    unsigned char* resultBytes = new unsigned char[length];

    hexStringToBytes(hexStr1, bytes1);
    hexStringToBytes(hexStr2, bytes2);

    for (size_t i = 0; i < length; ++i) {
        resultBytes[i] = bytes1[i] ^ bytes2[i];
    }

    string result = bytesToHexString(resultBytes, length);

    delete[] bytes1;
    delete[] bytes2;
    delete[] resultBytes;

    return result;
}

string hexToBytes(const string& hex) {
	if (hex.length() % 2 != 0) {
		throw invalid_argument("Hex string length must be even.");
	}

	string result;
	for (size_t i = 0; i < hex.length(); i += 2) {
		unsigned char byte = stoi(hex.substr(i, 2), nullptr, 16);  // 解析两个十六进制字符为一个字节
		result.push_back(byte);
	}
	return result;
}

string hex_to_utf8(const string& hex) {
	string byteStream = hexToBytes(hex);
	return byteStream;
}