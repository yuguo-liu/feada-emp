import os
import subprocess
import secrets

def generate_hex_string(length):
    byte_length = (length + 1) // 2
    hex_str = secrets.token_hex(byte_length)
    return hex_str[:length]

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")

    for block_length in range(1, 101):
        bob_m           = generate_hex_string(block_length * 32)
        bob_key_share   = generate_hex_string(32)
        bob_iv_share    = generate_hex_string(24)

        alice_auth_data = "0" * 20
        alice_key_share = "0"
        alice_iv_share  = "0"
        
        len_c_i = len(bob_m) * 4
        len_a_i = len(alice_auth_data) * 4

        host = "127.0.0.1"

        cmd = f"./test_aes-gcm-2pc {str(party)} {str(port)} {bob_m} {bob_key_share} {bob_iv_share} {alice_auth_data} {alice_key_share} {alice_iv_share} {str(len_c_i)} {str(len_a_i)} {host}"
        print(f"cmd: {cmd}")
        
        output = subprocess.check_output(cmd, shell=True)
        output_str = output.decode("utf-8")
        print(f"!output: {output_str}")
        outputs = output_str.split('\n')
        print(outputs)
        cipher, tag = outputs[-3], outputs[-2]
        port += 1

        print(f"get cipher 0x{cipher}")
        print(f"get tag    0x{tag}")