from tkinter import * # Import tkinter untuk GUI (Graphical User Interface) nya saja
import math # Import math untuk menghitung logaritma basis 2 (log2) nya saja (untuk menghitung entropi Shannon) 
import hashlib # Import hashlib untuk menghitung hash dari teks (untuk menghitung Avalanche Effect) nya saja (untuk menghitung entropi Shannon) 

def main(): # Fungsi main untuk menjalankan program
    def generate_playfair_matrix(key): # Fungsi untuk membuat matriks Playfair
        key = key.replace('j', 'i') # Mengganti karakter 'j' dengan 'i'
        key = key.replace(" ", "") # Menghapus spasi
        key = "".join(dict.fromkeys(key)) # Menghapus karakter yang sama
        alphabet = "abcdefghiklmnopqrstuvwxyz" # Alphabet yang digunakan
        key = key + "".join(filter(lambda char: char not in key, alphabet)) # Menggabungkan key dengan alphabet yang tidak ada di key
         
        matrix = [list(key[i:i+5]) for i in range(0, 25, 5)] # Membuat matriks 5x5
        return matrix

    def format_message(msg): # Fungsi untuk memformat pesan
        msg = msg.replace('j', 'i') # Mengganti karakter 'j' dengan 'i'
        i = 1 
        while i < len(msg): # Menambahkan karakter 'z' jika karakter sebelumnya sama dengan karakter saat ini
            if msg[i-1] == msg[i]: 
                msg = msg[:i] + 'z' + msg[i:] 
            i += 2 
        if len(msg) % 2 != 0: # Menambahkan karakter 'z' jika panjang pesan ganjil
            msg += 'z' 
        return msg

    def get_position(matrix, char): # Fungsi untuk mendapatkan posisi karakter pada matriks
        for row in range(5): 
            for col in range(5): 
                if matrix[row][col] == char: 
                    return (row, col)

    def encrypt(message, matrix): # Fungsi untuk mengenkripsi pesan
         # Menghapus spasi
        formatted_msg = format_message(message) # Memformat pesan
        print(formatted_msg) # Menampilkan pesan yang sudah diformat
        ciphertext = "" 
        i = 0
        while i < len(formatted_msg): # Melakukan enkripsi
            char1 = formatted_msg[i]  # Mengambil 1 karakter
            char2 = formatted_msg[i+1] # Mengambil 2 karakter
            pos1 = get_position(matrix, char1) # Mendapatkan posisi karakter 1
            pos2 = get_position(matrix, char2) # Mendapatkan posisi karakter 2
            x1, y1 = pos1 # Mendapatkan koordinat karakter 1
            x2, y2 = pos2 # Mendapatkan koordinat karakter 2
            if x1 == x2: # Jika karakter 1 dan karakter 2 berada pada baris yang sama
                ciphertext += matrix[x1][(y1 + 1) % 5] + matrix[x2][(y2 + 1) % 5] # Mengambil karakter yang berada di sebelah kanan karakter 1 dan karakter 2
            elif y1 == y2: # Jika karakter 1 dan karakter 2 berada pada kolom yang sama
                ciphertext += matrix[(x1 + 1) % 5][y1] + matrix[(x2 + 1) % 5][y2] # Mengambil karakter yang berada di bawah karakter 1 dan karakter 2
            else: # Jika karakter 1 dan karakter 2 berada pada baris dan kolom yang berbeda
                ciphertext += matrix[x1][y2] + matrix[x2][y1] # Mengambil karakter yang berada di baris dan kolom yang berbeda
            i += 2 # Melanjutkan ke karakter selanjutnya
        return ciphertext # Mengembalikan ciphertext

    def decrypt(ciphertext, matrix): # Fungsi untuk mendekripsi pesan
        plaintext = "" # Inisialisasi plaintext
        i = 0 
        while i < len(ciphertext): # Melakukan dekripsi
            char1 = ciphertext[i] # Mengambil 1 karakter
            char2 = ciphertext[i+1] # Mengambil 2 karakter
            pos1 = get_position(matrix, char1) # Mendapatkan posisi karakter 1
            pos2 = get_position(matrix, char2) # Mendapatkan posisi karakter 2
            x1, y1 = pos1 # Mendapatkan koordinat karakter 1
            x2, y2 = pos2 # Mendapatkan koordinat karakter 2
            if x1 == x2: # Jika karakter 1 dan karakter 2 berada pada baris yang sama
                plaintext += matrix[x1][(y1 - 1) % 5] + matrix[x2][(y2 - 1) % 5] # Mengambil karakter yang berada di sebelah kiri karakter 1 dan karakter 2
            elif y1 == y2: # Jika karakter 1 dan karakter 2 berada pada kolom yang sama
                plaintext += matrix[(x1 - 1) % 5][y1] + matrix[(x2 - 1) % 5][y2] # Mengambil karakter yang berada di atas karakter 1 dan karakter 2
            else: # Jika karakter 1 dan karakter 2 berada pada baris dan kolom yang berbeda
                plaintext += matrix[x1][y2] + matrix[x2][y1] # Mengambil karakter yang berada di baris dan kolom yang berbeda
            i += 2 # Melanjutkan ke karakter selanjutnya
        return plaintext # Mengembalikan plaintext

    def text_to_ascii(text): # Fungsi untuk mengonversi teks ke representasi ASCII
        ascii_values = [ord(char) for char in text] # Mengonversi teks ke representasi ASCII
        return ascii_values # Mengembalikan representasi ASCII

    #=======================
    def avalanche_effect(input_awal, input_modifikasi): # Fungsi untuk menghitung Avalanche Effect (AE)
        hash_awal = hashlib.sha512(input_awal.encode()).hexdigest() # Menghitung hash dari input awal
        hash_modifikasi = hashlib.sha256(input_modifikasi.encode()).hexdigest() # Menghitung hash dari input modifikasi
        different_characters = sum(1 for a, b in zip(hash_awal, hash_modifikasi) if a != b) # Menghitung jumlah karakter yang berbeda
        ae = (different_characters / len(hash_awal)) * 100 # Menghitung Avalanche Effect (AE)
        return ae
    #=======================
    #=======================
    def test_entropy(ciphertext): # Fungsi untuk menghitung entropi Shannon
        byte_counts = {} # Inisialisasi dictionary untuk menyimpan jumlah kemunculan setiap byte
        for byte in ciphertext: # Menghitung jumlah kemunculan setiap byte
            if byte not in byte_counts: # Jika byte belum ada di dictionary, maka tambahkan
                byte_counts[byte] = 0 # Inisialisasi jumlah kemunculan byte
            byte_counts[byte] += 1 # Menambah jumlah kemunculan byte

        # Hitung entropi Shannon dari ciphertext.
        entropy_shannon = 0 # Inisialisasi entropi Shannon
        for byte, count in byte_counts.items(): # Menghitung entropi Shannon
            probability = count / len(ciphertext) # Menghitung probabilitas kemunculan byte
            entropy_shannon += probability * math.log2(1/probability) # Menghitung entropi Shannon

        # Jika entropi Shannon <= 7, maka return Nilai, jika tidak return False.
        if entropy_shannon <= 7: 
            return entropy_shannon # Return entropi Shannon
        else: # Jika entropi Shannon > 7, maka return False.
            return False # Return False
    #=======================
    def bit_error_rate(ascii_list1, ascii_list2): # Fungsi untuk menghitung Bit Error Rate (BER)
        if len(ascii_list1) != len(ascii_list2): # Jika panjang kedua list tidak sama, maka return None
            return None # Return None jika panjang kedua list tidak sama
        different_characters = sum(1 for a, b in zip(ascii_list1, ascii_list2) if a != b) # Menghitung jumlah karakter yang berbeda
        ber = different_characters / len(ascii_list1) # Menghitung Bit Error Rate (BER)
        return ber # Mengembalikan Bit Error Rate (BER)
    
    def character_error_rate(original_text, decrypted_text): # Fungsi untuk menghitung Cross Entropy Rate (CER)
        # # Count character frequencies in the original text
        # char_count_original = {} # Inisialisasi dictionary untuk menyimpan jumlah kemunculan setiap karakter
        # for char in original_text: # Menghitung jumlah kemunculan setiap karakter
        #     if char not in char_count_original: # Jika karakter belum ada di dictionary, maka tambahkan
        #         char_count_original[char] = 0 # Inisialisasi jumlah kemunculan karakter
        #     char_count_original[char] += 1 # Menambah jumlah kemunculan karakter

        # # Count character frequencies in the decrypted text
        # char_count_decrypted = {} # Inisialisasi dictionary untuk menyimpan jumlah kemunculan setiap karakter
        # for char in decrypted_text: # Menghitung jumlah kemunculan setiap karakter
        #     if char not in char_count_decrypted: # Jika karakter belum ada di dictionary, maka tambahkan
        #         char_count_decrypted[char] = 0 # Inisialisasi jumlah kemunculan karakter
        #     char_count_decrypted[char] += 1 # Menambah jumlah kemunculan karakter

        # # Calculate the Cross Entropy Rate (CER)
        # cer = 0 # Inisialisasi Cross Entropy Rate (CER)
        # for char, count in char_count_original.items(): 
        #     probability_original = count / len(original_text)
        #     probability_decrypted = char_count_decrypted.get(char, 0) / len(decrypted_text)
        #     if probability_decrypted > 0:  # Check if probability_decrypted is not zero
        #         cer += probability_original * math.log2(1 / probability_decrypted)
        bedakarakter = 0
        cek = len(original_text)<len(decrypted_text)
        if(cek):
            panjang = len(original_text)
        else:
            panjang = len(decrypted_text)
        for i in range(panjang):
            if(decrypted_text[i] != original_text[i]):
                bedakarakter += 1
        cer = (bedakarakter/len(original_text))*100
        return cer # Mengembalikan Cross Entropy Rate (CER)

    def eksekusi_algoritma(): # Fungsi untuk mengeksekusi algoritma
        input_text = entry_input.get().lower() # Mengambil input teks
        input_text2 = entry_input2.get().lower()
        input_text = input_text.replace(" ","") # Mengambil input teks untuk pengujian AE
        input_text2 = input_text2.replace(" ","") # Mengambil input teks untuk pengujian AE
        key = entry_key.get() # Mengambil input key
        matrix = generate_playfair_matrix(key) # Membuat matriks Playfair
        
        # Mengonversi teks ke representasi ASCII
        ascii_input = text_to_ascii(input_text) 
        ascii_input2 = text_to_ascii(input_text2) 
        
        cipher_text = encrypt(input_text, matrix) # Melakukan enkripsi
        cipher_text2 = encrypt(input_text2, matrix) # Melakukan enkripsi untuk pengujian AE
        
        dekripsi_text = decrypt(cipher_text, matrix)  # Melakukan dekripsi

        label_output.config(text="Encrypted Text: " + cipher_text) # Menampilkan hasil enkripsi
        label_output2.config(text="Decrypted Text: " + dekripsi_text) # Menampilkan hasil dekripsi
        
        # Menghitung dan menampilkan Avalanche Effect (AE) dan Bit Error Rate (BER)
        # ae = avalanche_effect(ascii_cipher, ascii_cipher2)
        ae = avalanche_effect(cipher_text, cipher_text2)  # Menghitung Avalanche Effect (AE)
        ber = bit_error_rate(ascii_input, ascii_input2) # Menghitung Bit Error Rate (BER)
        entropy = test_entropy(cipher_text) # Menghitung entropi Shannon
        if entropy: # Jika entropi Shannon <= 7, maka tampilkan entropi Shannon
            label_enteropy.config(text="Entropy is good (<=7) (" + str(entropy) + ") bits")  # Menampilkan entropi Shannon
        else: # Jika entropi Shannon > 7, maka tampilkan pesan entropi Shannon terlalu tinggi
            label_enteropy.config(text="Entropy is too high (>7)") # Menampilkan pesan entropi Shannon terlalu tinggi
        label_AE.config(text="Avalanche Effect: " + str(ae) + "%") # Menampilkan Avalanche Effect (AE)
        label_ber.config(text="Bit Error Rate (BER): " + str(ber)) # Menampilkan Bit Error Rate (BER)
        print(dekripsi_text)
        print(input_text)
        # Calculate and display the Cross Entropy Rate (CER)
        cer = character_error_rate(input_text, dekripsi_text) # Menghitung Cross Entropy Rate (CER)
        label_cer.config(text="Character error Rate (CER): " + str(cer)) # Menampilkan Cross Entropy Rate (CER)

    label_input = Label(text="Input Text:") # Label untuk input teks
    label_input.pack() # Menampilkan label untuk input teks

    entry_input = Entry() # Input teks
    entry_input.pack() # Menampilkan input teks

    label_key = Label(text="Key:") # Label untuk input key
    label_key.pack() # Menampilkan label untuk input key

    entry_key = Entry() # Input key
    entry_key.pack() # Menampilkan input key

    label_input2 = Label(text="Input Text untuk pengujian AE:") # Label untuk input teks untuk pengujian AE
    label_input2.pack() # Menampilkan label untuk input teks untuk pengujian AE

    entry_input2 = Entry() # Input teks untuk pengujian AE
    entry_input2.pack() # Menampilkan input teks untuk pengujian AE

    button_decrypt = Button(text="Eksekusi", command=eksekusi_algoritma) # Button untuk mengeksekusi algoritma
    button_decrypt.pack() # Menampilkan button untuk mengeksekusi algoritma
    

    label_output = Label(text="") # Label untuk menampilkan hasil enkripsi
    label_output.pack() # Menampilkan label untuk menampilkan hasil enkripsi

    label_output2 = Label(text="") # Label untuk menampilkan hasil dekripsi
    label_output2.pack() # Menampilkan label untuk menampilkan hasil dekripsi

    label_ber = Label(text="") # Label untuk menampilkan Bit Error Rate (BER)
    label_ber.pack() # Menampilkan label untuk menampilkan Bit Error Rate (BER)

    label_cer = Label(text="") # Label untuk menampilkan Cross Entropy Rate (CER)
    label_cer.pack() # Menampilkan label untuk menampilkan Cross Entropy Rate (CER)
    
    label_AE = Label(text="") # Label untuk menampilkan Avalanche Effect (AE)
    label_AE.pack() # Menampilkan label untuk menampilkan Avalanche Effect (AE)

    label_enteropy = Label(text="") # Label untuk menampilkan entropi Shannon
    label_enteropy.pack() # Menampilkan label untuk menampilkan entropi Shannon
    mainloop()

if __name__ == "__main__":
    main()
