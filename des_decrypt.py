from typing import List
SBox =[
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]

def prepare_key(key: str) -> List[str]:
    # define the PC1 table and PC2 table
    pc1_table = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    pc2_table = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    # left shift table
    left_shifts = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # applying PC1 to the key (dropping every 8th bit)
    key_plus = key[0:7] + key[8:15] + key[16:23] + key[24:31] + key[32:39] + key[40:47] + key[48:55] + key[56:63]
    key_plus = "".join(key[i - 1] for i in pc1_table)
    # splitting into two halves
    c = key_plus[:28]
    d = key_plus[28:]

    subkeys = []
    for shift in left_shifts:
        #lLeft shift both halves
        print(len(c))
        print(len(d))
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]

        # combine halves
        cd_combined = c + d
        if len(cd_combined) != 56:
            raise ValueError("Combined CD is not 56 bits long")

        # apply PC2 to generate the subkey
        subkey = "".join(cd_combined[i - 1] for i in pc2_table)
        subkeys.append(subkey)

    return subkeys

def initial_permutation(data: str) -> str:
    # define the initial permutation
    ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # apply the initial permutation
    permuted_data = "".join(data[i - 1] for i in ip_table)
    return permuted_data

def expansion(block: str) -> str:
    # expansion table
    e_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    return "".join(block[i - 1] for i in e_table)

def xor(a: str, b: str) -> str:
    return ''.join('1' if i != j else '0' for i, j in zip(a, b))

def substitution(expanded_block: str) -> str:
    output = ""
    for i in range(8):
        block = expanded_block[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        output += format(SBox[i][row*16 + col], '04b')

    return output

def permutation(block: str) -> str:
    # permutation table
    p_table = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    return "".join(block[i - 1] for i in p_table)

def des_decrypt(ciphertext: str, subkeys: List[str]) -> str:
    # perform initial permutation
    permuted_data = initial_permutation(ciphertext)

    # split data into left and right halves
    left = permuted_data[:32]
    right = permuted_data[32:]

    for i in range(16):
        # subkeys in reverse order
        subkey = subkeys[15 - i]
        # expansion
        expanded_right = expansion(right)
        # subkey mixing
        mixed = xor(expanded_right, subkey)
        # substitution
        substituted = substitution(mixed)
        # permutation and print
        permuted = permutation(substituted)
        print(f"Round {i+1}, f-function output: {permuted}")
        # XOR with left half and swap halves
        new_right = xor(left, permuted)
        left = right
        right = new_right

        # print LnRn
        print(f"Round {i+1}, LnRn: {left}{right}")

    # swap halves one last time
    final_data = right + left
    return final_data


def final_permutation(data: str) -> str:
    # final permutation table
    fp_table = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]

    permuted_data = "".join(data[i - 1] for i in fp_table)
    return permuted_data

def binary_to_text(binary_str: str) -> str:
    text = ''
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        print(byte, int(byte, 2))
        text += chr(int(byte, 2))
    return text

# key and ciphertext in binary
ciphertext =    "1100101011101101101000100110010101011111101101110011100001110011"
key =           "0100110001001111010101100100010101000011010100110100111001000100"

# keys
subkeys = prepare_key(key)
print(subkeys)

# Decrypt the message
decrypted_data = des_decrypt(ciphertext, subkeys)
decrypted_data = final_permutation(decrypted_data)

# convert to text
plaintext = binary_to_text(decrypted_data)
print(plaintext)
