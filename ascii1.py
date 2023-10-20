import streamlit as st
import math
import hashlib

def generate_playfair_matrix(key):
    key = key.replace('j', 'i')
    key = key.replace(" ", "")
    key = "".join(dict.fromkeys(key))
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    key = key + "".join(filter(lambda char: char not in key, alphabet))

    matrix = [list(key[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def format_message(msg):
    msg = msg.replace('j', 'i')
    i = 1
    while i < len(msg):
        if msg[i-1] == msg[i]:
            msg = msg[:i] + 'z' + msg[i:]
        i += 2
    if len(msg) % 2 != 0:
        msg += 'z'
    return msg

def get_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return (row, col)

def encrypt(message, matrix):
    formatted_msg = format_message(message)
    ciphertext = ""
    i = 0
    while i < len(formatted_msg):
        char1 = formatted_msg[i]
        char2 = formatted_msg[i+1]
        pos1 = get_position(matrix, char1)
        pos2 = get_position(matrix, char2)
        x1, y1 = pos1
        x2, y2 = pos2
        if x1 == x2:
            ciphertext += matrix[x1][(y1 + 1) % 5] + matrix[x2][(y2 + 1) % 5]
        elif y1 == y2:
            ciphertext += matrix[(x1 + 1) % 5][y1] + matrix[(x2 + 1) % 5][y2]
        else:
            ciphertext += matrix[x1][y2] + matrix[x2][y1]
        i += 2
    return ciphertext

def decrypt(ciphertext, matrix):
    plaintext = ""
    i = 0
    while i < len(ciphertext):
        char1 = ciphertext[i]
        char2 = ciphertext[i+1]
        pos1 = get_position(matrix, char1)
        pos2 = get_position(matrix, char2)
        x1, y1 = pos1
        x2, y2 = pos2
        if x1 == x2:
            plaintext += matrix[x1][(y1 - 1) % 5] + matrix[x2][(y2 - 1) % 5]
        elif y1 == y2:
            plaintext += matrix[(x1 - 1) % 5][y1] + matrix[(x2 - 1) % 5][y2]
        else:
            plaintext += matrix[x1][y2] + matrix[x2][y1]
        i += 2
    return plaintext

def avalanche_effect(input_awal, input_modifikasi):
    hash_awal = hashlib.sha512(input_awal.encode()).hexdigest()
    hash_modifikasi = hashlib.sha256(input_modifikasi.encode()).hexdigest()
    different_characters = sum(1 for a, b in zip(hash_awal, hash_modifikasi) if a != b)
    ae = (different_characters / len(hash_awal)) * 100
    return ae

def test_entropy(ciphertext):
    byte_counts = {}
    for byte in ciphertext:
        if byte not in byte_counts:
            byte_counts[byte] = 0
        byte_counts[byte] += 1

    entropy_shannon = 0
    for byte, count in byte_counts.items():
        probability = count / len(ciphertext)
        entropy_shannon += probability * math.log2(1/probability)

    if entropy_shannon <= 7:
        return entropy_shannon
    else:
        return False

def text_to_ascii(text):
    ascii_values = [ord(char) for char in text]
    return ascii_values

def bit_error_rate(ascii_list1, ascii_list2):
    if len(ascii_list1) != len(ascii_list2):
        return None
    different_characters = sum(1 for a, b in zip(ascii_list1, ascii_list2) if a != b)
    ber = different_characters / len(ascii_list1)
    return ber

def character_error_rate(original_text, decrypted_text):
    bedakarakter = 0
    cek = len(original_text) < len(decrypted_text)
    if cek:
        panjang = len(original_text)
    else:
        panjang = len(decrypted_text)
    for i in range(panjang):
        if decrypted_text[i] != original_text[i]:
            bedakarakter += 1
    cer = (bedakarakter / len(original_text)) * 100
    return cer

def main():
    st.title("Playfair Cipher with Entropy and Avalanche Effect")

    input_text = st.text_input("Input Text")
    key = st.text_input("Key")
    input_text2 = st.text_input("Input Text for Avalanche Effect Test")

    if st.button("Execute"):
        matrix = generate_playfair_matrix(key)
        ascii_input = text_to_ascii(input_text)
        ascii_input2 = text_to_ascii(input_text2)
        cipher_text = encrypt(input_text, matrix)
        cipher_text2 = encrypt(input_text2, matrix)
        dekripsi_text = decrypt(cipher_text, matrix)

        st.write("Encrypted Text: ", cipher_text)
        st.write("Decrypted Text: ", dekripsi_text)

        ae = avalanche_effect(cipher_text, cipher_text2)
        ber = bit_error_rate(ascii_input, ascii_input2)
        entropy = test_entropy(cipher_text)

        if entropy:
            st.write(f"Entropy is good (<=7) ({entropy} bits)")
        else:
            st.write("Entropy is too high (>7)")

        st.write("Avalanche Effect: ", ae, "%")
        st.write("Bit Error Rate (BER): ", ber)

        cer = character_error_rate(input_text, dekripsi_text)
        st.write("Character Error Rate (CER): ", cer)

if __name__ == "__main__":
    main()
