#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <vector>
#include <sstream>
#include <iostream>
#include <cstdint>
#include <string.h>
using namespace std;

uint32_t right_rotate(uint32_t x, uint32_t n);
uint32_t little_sigma_0(uint32_t x);
uint32_t little_sigma_1(uint32_t x);
uint32_t big_sigma_0(uint32_t x);
uint32_t big_sigma_1(uint32_t x);
void message_schedule(uint32_t(&W)[64], uint8_t(&block)[64]);
uint32_t choice(uint32_t x, uint32_t y, uint32_t z);
uint32_t majority(uint32_t x, uint32_t y, uint32_t z);
void round(uint32_t(&H)[8], uint32_t round_constant, uint32_t schedule_word);
void compress_block(uint32_t(&H)[8], uint8_t(&block)[64]);
string plaintext_sha256(string m, string state);
string uintArrToBinaryString(const unsigned int arr[], int n);
void display_final_state_as_hex();
void display_final_state_H_as_uint();
void display_final_state_H_as_bits();
string hex_string_to_hex_byte_string(const string& hexStr);
unsigned char reverse_bits(unsigned char byte);
string hex_string_reverse_bits(const std::string& hexStr);
uint32_t get_state_uint32(const string &state);
void get_state_list_uint32(const string &state_str, uint32_t* state);
std::string xorHexStrings(const std::string& hexStr1, const std::string& hexStr2);
std::string generate_random_hex_string(size_t length);

const int a = 0;
const int b = 1;
const int c = 2;
const int d = 3;
const int e = 4;
const int f = 5;
const int g = 6;
const int h = 7;
const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
uint32_t H[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };

uint32_t right_rotate(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

uint32_t little_sigma_0(uint32_t x) {
	return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);
}

uint32_t little_sigma_1(uint32_t x) {
	return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);
}

uint32_t big_sigma_0(uint32_t x) {
	return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22);
}

uint32_t big_sigma_1(uint32_t x) {
	return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25);
}

void message_schedule(uint32_t(&W)[64], uint8_t(&block)[64]) {
	for (int i = 0; i < 16; i++) {
		W[i] =  ( block [i * 4]  <<  24)     |
				( block [i * 4 + 1]  <<  16) |
				( block [i * 4 + 2]  <<  8)  |
				( block [i * 4 + 3]);
	}

	for (int i = 16; i < 64; i++) {
		W[i] =	little_sigma_1( W [i - 2] )  +  W[i - 7]  +
				little_sigma_0( W [i - 15] )  +  W[i - 16];
	}
}

uint32_t choice(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (~x & z);
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

void round(uint32_t(&H)[8], uint32_t round_constant, uint32_t schedule_word) {
	uint32_t T1 =	H[h] +
					big_sigma_1(H[e]) +
					choice(H[e], H[f], H[g]) +
					round_constant +
					schedule_word;

	uint32_t T2 =	big_sigma_0(H[a]) +
					majority(H[a], H[b], H[c]);

	for (int i = 7; i > 0; i--) {
		H[i] = H[i - 1];
	}

	H[a] = T1 + T2;
	H[e] += T1;
}

void compress_block(uint32_t(&H)[8], uint8_t(&block)[64]) {
	uint32_t W[64];
	uint32_t h[8];

	message_schedule(W, block);

	for (int i = 0; i < 8; i++) h[i] = H[i];
	for (int i = 0; i < 64; i++) round(h, W[i], K[i]);
	for (int i = 0; i < 8; i++) H[i] += h[i];
}

string plaintext_sha256(string m, string state) {
	m = hex_string_to_hex_byte_string(m);

	int size = m.size();
	int l = (size * 8);
	vector<uint8_t> message;

	// int N = 1;
	// if ((l + 64) > 512) {
	// 	N += ((l + 64) / 512);
	// }
	//
	// int k = 0;
	// for (int i = l; i < ((N * 512) - 8 - 64); i += 8) {
	// 	k++;
	// }
	//
	// message.reserve(size + k + 1 + 8);
	// copy(m.c_str(), m.c_str() + size, back_inserter(message));
	// message.push_back(128);
	// message.insert(message.end(), k, 0);
	//
	// for (int i = 0; i < 8; ++i) {
	// 	message.push_back(((((unsigned long long) l) >> (56 - (8 * i))) & 0xFFu));
	// }

	int N = l / 512;
	message.reserve(size);
	copy(m.c_str(), m.c_str()+size, back_inserter(message));

	get_state_list_uint32(state, H);

	uint8_t block[64];
	for (int i = 0; i < N; i++) {
		memcpy(block, &message[i * 64], 64);
		compress_block(H, block);
	}

	stringstream ss;
	for (size_t i = 0; i < 8; ++i) {
		ss << hex << setw(8) << setfill('0') << H[i];
	}

	return ss.str();
}

string uintArrToBinaryString(const unsigned int arr[], int n) {
	string binaryString;
	for (int i = 0; i < n; i++) {
		bitset<8> bits(arr[i]);
		binaryString += bits.to_string();
	}
	return binaryString;
}

void display_final_state_as_hex() {
	cout << endl << "Final state (H) as hex = ";
	for (int i = 0; i < 8; i++) {
		stringstream ss;
		ss << hex << H[i];
		string res(ss.str());
		cout << res << " ";
	}
}

void display_final_state_H_as_uint() {
	cout << endl << "Final state (H) as uints = ";
	for (int i = 0; i < 8; i++) {
		cout << H[i] << " ";
	}
}

void display_final_state_H_as_bits() {
	string output = uintArrToBinaryString(H, 8);
	cout << endl << "Final state (H) as bits = " << output;
}

string hex_string_to_hex_byte_string(const string& hexStr) {
	string result;

	for (size_t i = 0; i < hexStr.length(); i += 2) {
		unsigned int byte;
		stringstream ss;
		ss << hex << hexStr.substr(i, 2);
		ss >> byte;

		result += (char)(byte);
	}

	return result;
}

unsigned char reverse_bits(unsigned char byte) {
	unsigned char reversedByte = 0;
	for (int i = 0; i < 8; ++i) {
		reversedByte |= ((byte >> i) & 1) << (7 - i);
	}
	return reversedByte;
}

string hex_string_reverse_bits(const std::string& hexStr) {
	string result;

	for (size_t i = 0; i < hexStr.length(); ++i) {
		unsigned char byte = (hexStr[i] <= '9') ? (hexStr[i] - '0') : (hexStr[i] - 'a' + 10);

		byte = reverse_bits(byte);

		stringstream ss;
		ss << std::hex << (int)byte;
		string reversedHex = ss.str();

		result = reversedHex.substr(0,1) + result;
	}

	return result;
}

uint32_t get_state_uint32(const string &state) {
	// the original state is reversed, so we should reverse back
	return stoul(
		hex_string_reverse_bits(state),
		nullptr,
		16
	);
}

void get_state_list_uint32(const string &state_str, uint32_t* state) {
	for (int i = 0; i < 8; i++) {
		const string tmp = state_str.substr(i * 8, 8);
		state[i] = get_state_uint32(tmp);
	}
}

void hexStringToBytes(const std::string& hexStr, unsigned char* bytes) {
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteStr = hexStr.substr(i, 2); 
        bytes[i / 2] = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
    }
}

std::string bytesToHexString(const unsigned char* bytes, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string xorHexStrings(const std::string& hexStr1, const std::string& hexStr2) {
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

    std::string result = bytesToHexString(resultBytes, length);

    delete[] bytes1;
    delete[] bytes2;
    delete[] resultBytes;

    return result;
}

std::string generate_random_hex_string(size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;

    for (size_t i = 0; i < length; ++i) {
        int random_digit = dis(gen);
        ss << std::hex << random_digit;
    }

    return ss.str();
}