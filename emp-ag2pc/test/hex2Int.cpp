#include <emp-tool/emp-tool.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "test/single_execution.h"
#include <time.h>
using namespace std;
using namespace emp;

string generate_random_hex_string(size_t length);
string xorHexStrings(const string& hexStr1, const string& hexStr2);

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
	string a = "0000000000000000000000000000000000000000000000000000000000000000";
	string b = "0000000000000000000000000000000000000000000000000000000000000000";

	string a_mask = "0000000000000000000000000000000000000000000000000000000000000000";
	string b_mask = "0000000000000000000000000000000000000000000000000000000000000000";

	if (party == ALICE) {
		a = "37E83048D214504D78FED52595E8BBE94C6AFF12B6843EB37FBC21426123998A";
		a_mask = generate_random_hex_string(64);
	} else {
		b = "69FC1CF6AB936915BF851C8372230BDDE3F34889A806660BE6BD5DEF7C9E7C9C";
		b_mask = generate_random_hex_string(64);
	}

    string res = ag2pc_exec(party, io, circuit_file_location+"ECtF/add_2_xor copy.txt",
        b + b_mask + a + a_mask
    );

	cout << party << " gets 0x" << res << endl;

	string out = (party == ALICE) ? a_mask : xorHexStrings(res, b_mask);

	cout << party << " gets 0x" << out << endl;

	delete io;
	return 0;
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