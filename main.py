import hashlib

from dominate.tags import output
from pyexpat.errors import messages
from sqlalchemy import select
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer
import random
import json
import string
import math



app = Flask(__name__)
# ======================================================================================================================
def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')
    hash_object = hashlib.sha256()
    hash_object.update(password_bytes)
    hashed_password = hash_object.hexdigest()
    return hashed_password
# ======================================================================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
class Base(DeclarativeBase):
    pass

class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)

with app.app_context():
    db.create_all()
# ======================================================================================================================
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/index')
def ceaser():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('create-name')
    email = request.form.get('create-email')
    password = request.form.get('create-password')
    hashcode = hash_password(password)


    try:
        new_user = User(name=name,email=email,password=hashcode)
        db.session.add(new_user)
        db.session.commit()
        return render_template ("index.html")
    except Exception as e:

        return f"Error: {str(e)}"


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('login-name')
    password = request.form.get('login-password')
    try:
        stmt = select(User).where(User.email == email)
        result = db.session.execute(stmt)
        account = result.scalar_one_or_none()

        if account:
            hashed = hash_password(password)
            if hashed == account.password:
                return render_template ("index.html")
            else:
                return "Incorrect password"
        else:
            return "User not found"

    except Exception as e:
        return f"Error: {str(e)}"
# ======================================================================================================================
#                                           ALGORITHMS
# ======================================================================================================================
                                          # Ceaser cipher
# ======================================================================================================================
def ceaser_cipher(message,amount,type):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M','N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    message_letters = []
    cipher_letters = []
    decrypt_letters=[]
    for letter in message.upper():
        message_letters.append(letter)
    if type == "encrypt" or type == "Encrypt":
        for letter in message_letters:
            if letter not in alphabet and letter!= " ":
                continue
            else:
                if letter == ' ':
                    cipher_letters.append(letter)
                else:
                    index = alphabet.index(letter)
                    cipher_letter = alphabet[(index + amount)%26]
                    cipher_letters.append(cipher_letter)
        cipher_message =  "".join(cipher_letters)
        return cipher_message

    elif type == "decrypt" or type == "Decrypt":
        for letter in message_letters:
            if letter not in alphabet and letter != " ":
                continue
            else:
                if letter == ' ':
                    decrypt_letters.append(letter)
                else:
                    index = alphabet.index(letter)
                    decrypt_letter = alphabet[(index - amount)%26]
                    decrypt_letters.append(decrypt_letter)
        plaintext = "".join(decrypt_letters)
        return plaintext

# ======================================================================================================================
                                          # Vigenere cipher
# ======================================================================================================================

def vigenere_cipher(message,key,type):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U','V', 'W', 'X', 'Y', 'Z']
    message_letters = []
    cipher_letters = []
    decrypt_letters=[]
    cipher_message=""
    decrypt_message=""
    key_index = 0
    for letter in message.upper():
        message_letters.append(letter)
    if type == "encrypt" or type == "Encrypt":
        for letter in message_letters:
            if letter not in alphabet and letter!= " ":
                continue
            elif letter == "@":
                continue
            else:
                if letter == ' ':
                    cipher_letters.append(letter)
                else:
                    shift = alphabet.index(key[key_index % len(key)].upper())
                    index = alphabet.index(letter)
                    cipher_letter = alphabet[(index + shift) % 26]
                    cipher_letters.append(cipher_letter)
                    key_index += 1
            cipher_message = "".join(cipher_letters)
        return cipher_message
    elif type == "decrypt" or type == "Decrypt":
        for letter in message_letters:
            if letter not in alphabet and letter!= " ":
                continue
            elif letter == "@":
                continue
            else:
                if letter == ' ':
                    decrypt_letters.append(letter)

                else:
                    shift = alphabet.index(key[key_index % len(key)].upper())
                    index = alphabet.index(letter)
                    decrypt_letter = alphabet[(index - shift) % 26]
                    decrypt_letters.append(decrypt_letter)
                    key_index += 1
            decrypt_message = "".join(decrypt_letters)
        return decrypt_message


# ======================================================================================================================
                                          # playfair cipher
# ======================================================================================================================
def playfair_matrix(key):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    key = key.upper().replace('J', 'I')
    key_array = []
    matrix = []
    row_data = []

    for x in key:
        if x not in key_array and x in alphabet:
            key_array.append(x)

    for x in alphabet:
        if x not in key_array:
            key_array.append(x)

    for i in range(0, 25, 5):
        matrix.append(key_array[i:i + 5])
    return matrix


def insert_filler_pairs(text):
    result = ''
    i = 0
    while i < len(text):
        first = text[i]
        if i + 1 < len(text):
            second = text[i + 1]
            if first == second:
                result += first + 'X'
                i += 1
            else:
                result += first + second
                i += 2
        else:
            result += first + 'X'
            i += 1
    return result


def get_position(matrix, letter):
    for row_index, row in enumerate(matrix):
        if letter in row:
            col_index = row.index(letter)
            return (row_index, col_index)
    return None


def playfair_cipher(message,key,type):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    matrix = playfair_matrix(key)
    temp_message= message.upper().replace('J', 'I')
    pairs_array= []
    cipher_array = []
    decrypt_array=[]
    decrypt_message=""
    encrypt_message=""
    for x in temp_message:
        if x not in alphabet:
            temp_message=temp_message.replace(x,"")
        else:
            continue
    temp_message = insert_filler_pairs(temp_message)

    if len(temp_message) %2 != 0:
        temp_message+"x"
    i=0
    while i != len(temp_message):
        pairs_array.append(f"{temp_message[i]}{temp_message[i+1]}")
        i +=2
    if type == "encrypt":
        for pair in pairs_array:
            position_first = get_position(matrix, pair[0])
            position_second= get_position(matrix, pair[1])
            if position_first[0] == position_second[0]:
                cipher_first = matrix[position_first[0]][(position_first[1]+1)%5]
                cipher_second = matrix[position_second[0]][(position_second[1] + 1) % 5]
                cipher_array.append(f'{cipher_first}{cipher_second}')
            elif position_first[1] == position_second[1]:
                cipher_first = matrix[(position_first[0]+ 1) % 5][position_first[1]]
                cipher_second = matrix[(position_second[0]+ 1) % 5][position_second[1]]
                cipher_array.append(f'{cipher_first}{cipher_second}')
            else:
                cipher_first = matrix[position_first[0]][position_second[1]]
                cipher_second = matrix[position_second[0]][position_first[1]]
                cipher_array.append(f'{cipher_first}{cipher_second}')
        encrypt_message = "".join(cipher_array)
        return encrypt_message
    elif type == "decrypt":
        for pair in pairs_array:
            position_first = get_position(matrix, pair[0])
            position_second= get_position(matrix, pair[1])
            if position_first[0] == position_second[0]:
                cipher_first = matrix[position_first[0]][(position_first[1]-1)%5]
                cipher_second = matrix[position_second[0]][(position_second[1] - 1) % 5]
                decrypt_array.append(f'{cipher_first}{cipher_second}')
            elif position_first[1] == position_second[1]:
                cipher_first = matrix[(position_first[0]- 1) % 5][position_first[1]]
                cipher_second = matrix[(position_second[0]- 1) % 5][position_second[1]]
                decrypt_array.append(f'{cipher_first}{cipher_second}')
            else:
                cipher_first = matrix[position_first[0]][position_second[1]]
                cipher_second = matrix[position_second[0]][position_first[1]]
                decrypt_array.append(f'{cipher_first}{cipher_second}')
        decrypt_message = "".join(decrypt_array)
        return decrypt_message
# ======================================================================================================================
                                          # Monoalphabetic  cipher
# ======================================================================================================================


def generate_monoalphabetic_key():
    letters = list(string.ascii_uppercase)
    shuffled = letters.copy()
    random.shuffle(shuffled)
    key = dict(zip(letters, shuffled))
    return key

def save_dict_as_json(key_dict, filename):
    with open(filename, 'w') as file:
        json.dump(key_dict, file)

def load_dict_from_json(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def monoalphabetic_cipher(message, type):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V','W', 'X', 'Y', 'Z']

    key = generate_monoalphabetic_key()
    message = message.upper()
    message_list=[]
    decrypt_list = []
    cipher_list=[]

    for x in message:
        if x not in alphabet:
            if x == " ":
                message_list.append(x)
            else:
                continue
        else:
            message_list.append(x)
    if type == "encrypt":
        save_dict_as_json(key, 'cipher_key.json')
        for letter in  message_list:
            if letter == " ":
                cipher_list.append(letter)
            else :
                cipher_letter = key[letter]
                cipher_list.append(cipher_letter)
        encrypt_message = "".join(cipher_list)
        return encrypt_message
    else :
        decrypt_key = load_dict_from_json('cipher_key.json')
        decrypt_key = {v: k for k, v in decrypt_key.items()}
        for letter in message_list:
            if letter == " ":
                decrypt_list.append(letter)
            else:
                decrypt_letter= decrypt_key[letter]
                decrypt_list.append(decrypt_letter)
        decrypt_message = "".join(decrypt_list)
        return decrypt_message

# ======================================================================================================================
                                          # Rail Fence  cipher
# ======================================================================================================================
def rail_fence(message, amount, type):
    message = message.upper().replace(" ", "")
    if type == "encrypt":
        rails = [""] * amount
        rail = 0
        direction = 1
        returned = ""
        for char in message:
            rails[rail] += char
            rail += direction

            if rail == 0 or rail == amount - 1:
                direction *= -1
        for x in rails:
            returned = f"{returned} {x}"

        return returned
    elif type == 'decrypt':
        length = len(message)
        pattern = [['' for _ in range(length)] for _ in range(amount)]

        rail = 0
        direction = 1
        for i in range(length):
            pattern[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == amount - 1:
                direction *= -1

        index = 0
        for r in range(amount):
            for c in range(length):
                if pattern[r][c] == '*' and index < length:
                    pattern[r][c] = message[index]
                    index += 1

        result = ''
        rail = 0
        direction = 1
        for i in range(length):
            result += pattern[rail][i]
            rail += direction
            if rail == 0 or rail == amount - 1:
                direction *= -1

        return result

# ======================================================================================================================
                                          # vernam  cipher
# ======================================================================================================================
import random
import json

def generate_key(length):
    binary = ["0", "1"]
    return ''.join(random.choice(binary) for x in range(length))

def save_dict_as_json_vernam(key_dict, filename):
    with open(filename, 'w') as file:
        json.dump(key_dict, file)

def load_dict_from_json_vernam(filename):
    with open(filename, 'r') as file:
        return json.load(file)
def repeat_key_to_length(key, length):
    repeated_key = (key * (length // len(key) + 1))[:length]
    return repeated_key

def vernam_cipher(message,key, type):
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    cipher_binary=""
    cipher_message=""

    if key ==None or key=="":
        if type == "encrypt":
            key_n  = generate_key(len(binary_message))
            save_dict_as_json_vernam({"key":key_n},"vernam_cipher.json")
            for i in range(len(binary_message)):
                if binary_message[i] == key_n[i]:
                    cipher_binary = cipher_binary+"0"
                else:
                    cipher_binary = cipher_binary+"1"
            for i in range(0, len(cipher_binary), 8):
                binary_letter = cipher_binary[i:i+8]
                cipher_message= cipher_message+(chr(int(binary_letter, 2)))
            return cipher_message


        else:
            key_n = load_dict_from_json_vernam("vernam_cipher.json")["key"]
            for i in range(len(binary_message)):
                if binary_message[i] == key_n[i]:
                    cipher_binary = cipher_binary+"0"
                else:
                    cipher_binary = cipher_binary+"1"
            for i in range(0, len(cipher_binary), 8):
                binary_letter = cipher_binary[i:i+8]
                cipher_message= cipher_message+(chr(int(binary_letter, 2)))
            return cipher_message
    else:
        if type == "encrypt":
            key_length = repeat_key_to_length(key, len(binary_message) // 8)
            key = ''.join(format(ord(c), '08b') for c in key_length)
            for i in range(len(binary_message)):
                if binary_message[i] == key[i]:
                    cipher_binary = cipher_binary + "0"
                else:
                    cipher_binary = cipher_binary + "1"
            for i in range(0, len(cipher_binary), 8):
                binary_letter = cipher_binary[i:i + 8]
                cipher_message = cipher_message + (chr(int(binary_letter, 2)))
            return cipher_message


        else:
            key_length = repeat_key_to_length(key, len(binary_message) // 8)
            key= ''.join(format(ord(c), '08b') for c in key_length)
            for i in range(len(binary_message)):
                if binary_message[i] == key[i]:
                    cipher_binary = cipher_binary + "0"
                else:
                    cipher_binary = cipher_binary + "1"
            for i in range(0, len(cipher_binary), 8):
                binary_letter = cipher_binary[i:i + 8]
                cipher_message = cipher_message + (chr(int(binary_letter, 2)))
            return cipher_message
# ======================================================================================================================
                                          # One time pad cipher
# ======================================================================================================================
def save_dict_as_json_pad(key_dict, filename):
    with open(filename, 'w') as file:
        json.dump(key_dict, file)

def load_dict_from_json_pad(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def one_time_pad_cipher(plaintext, type):
    plaintext = plaintext.upper().replace(" ", "")
    if type == 'encrypt':
        key_one_time_pad = ''.join(random.choice(string.ascii_uppercase) for _ in plaintext)
        save_dict_as_json_pad({"key": key_one_time_pad}, "key_one_time_pad.json")
        cipher_text = vigenere_cipher(plaintext, key_one_time_pad, "encrypt")
        return cipher_text
    else:
        key_one_time_pad = load_dict_from_json_pad("key_one_time_pad.json")["key"]
        decrypt_text = vigenere_cipher(plaintext, key_one_time_pad, "decrypt")
        return decrypt_text
# ======================================================================================================================
                                          # AUtokey cipher
# ======================================================================================================================
def autokey_cipher(message, key):
    alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V','W', 'X', 'Y', 'Z']
    for x in message:
        if x not in alphabet:
            clean_message = message.replace(x,"")
    clean_message = message.upper()
    key = key.upper()
    extended_key = (key + clean_message)[:len(clean_message)]
    return vigenere_cipher(message, extended_key, "encrypt")
# ======================================================================================================================
                                          # Row transposition cipher
# ======================================================================================================================

def key_to_order(key):
    key = key.upper()
    key_nums = [(ord(c) - 64) if c.isalpha() else int(c) for c in key]
    return sorted(range(len(key_nums)), key=lambda i: key_nums[i])

def build_matrix(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    cols = len(key)
    rows = math.ceil(len(plaintext) / cols)

    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(plaintext):
                matrix[r][c] = plaintext[idx]
                idx += 1
    return matrix

def row_transposition_encrypt(plaintext, key):
    matrix = build_matrix(plaintext, key)
    order = key_to_order(key)

    ciphertext = ''
    for col_index in order:
        for r in range(len(matrix)):
            if matrix[r][col_index]:
                ciphertext += matrix[r][col_index]
    return ciphertext

def row_transposition_decrypt(ciphertext, key):
    ciphertext = ciphertext.replace(" ", "").upper()
    order = key_to_order(key)
    cols = len(order)
    rows = math.ceil(len(ciphertext) / cols)

    total_cells = rows * cols
    empty_cells = total_cells - len(ciphertext)
    col_lengths = [rows] * cols
    for i in range(empty_cells):
        col_lengths[order[-(i + 1)]] -= 1

    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for sorted_pos, col_index in enumerate(order):
        for r in range(col_lengths[col_index]):
            matrix[r][col_index] = ciphertext[idx]
            idx += 1

    plaintext = ''
    for r in range(rows):
        for c in range(cols):
            if matrix[r][c]:
                plaintext += matrix[r][c]
    return plaintext


# ======================================================================================================================
@app.route('/ceaser', methods=['GET', 'POST'])
def ceaserCipher():
    if request.method == 'POST':
        output = ""
        type = request.form.get('action')
        message = request.form.get('Text')
        amount = int(request.form.get('rangeInput'))
        if message == None or message =="" or amount=="" or amount==None:
            output = "Empty"
        else:
            output = ceaser_cipher(message, amount, type)
        return render_template('ceaser.html', input=message, output=output)
    return render_template('ceaser.html')

# ======================================================================================================================
@app.route('/Vigenère', methods=['GET', 'POST'])
def vigenereCipher():
    output = ""
    message = ""
    key = ""
    if request.method == 'POST':
        action = request.form.get('action')
        message = request.form.get('Text')
        key = request.form.get('key')
        if message == None or message =="" or key=="" or key==None:
            output = "Empty"
        else:
            output = vigenere_cipher(message, key, action)
    return render_template('Vigenère.html', input=message, key=key, output=output)
# ======================================================================================================================
@app.route('/Playfair', methods=['GET', 'POST'])
def playfair():
    if request.method == 'POST':
        type = request.form.get('action')
        message = request.form.get('Text')
        key = request.form.get('key')

        if message == None or message =="":
            output = "Empty"
            matrix = playfair_matrix(key)
        else:
            matrix = playfair_matrix(key)
            output = playfair_cipher(message, key, type)
        return render_template(
            'playfair.html',
            matrix=matrix,
            key = key,
            input=message,
            output=output
        )
    return render_template('playfair.html')
# ======================================================================================================================
@app.route('/monoalphabetic', methods=['GET', 'POST'])
def monoalphabetic():
    if request.method == 'POST':
        type = request.form.get('action')
        message = request.form.get('Text')
        if message == None or message == "":
            output_message = "Empty"
        else:
            output_message = monoalphabetic_cipher(message, type)
        return render_template(
            'monoalphabetic.html',
            input=message,
            output=output_message
        )
    return render_template('monoalphabetic.html')
# ======================================================================================================================
@app.route('/railfence', methods=['GET', 'POST'])
def railfence():
    if request.method=='POST':
        type = request.form.get('action')
        message = request.form.get('Text')
        rails = int(request.form.get("rangeInput"))

        if message == None or message == "" or rails == None:
            output_message = "Empty"
        else:
            output_message = rail_fence(message, rails, type)

        return render_template(
            'rail-fence.html',
            input=message,
            amount= rails,
            output=output_message
        )
    return render_template('rail-fence.html')
# ======================================================================================================================
@app.route('/vernamcipher', methods=['GET', 'POST'])
def vernamcipher():
    if request.method == 'POST':
        type = request.form.get('action')
        message = request.form.get('Text')
        key = request.form.get("key")
        random_key = request.form.get("generate_key")
        output_message = ""

        if message == None or message =="":
            output_message = "Empty"
        else:
            if random_key == "yes":
                output_message = vernam_cipher(message, "", type)

            else:
                output_message = vernam_cipher(message, key, type)


        return  render_template(
            'vernam.html',
            input=message,
            output=output_message
        )
    return render_template('vernam.html')
# ======================================================================================================================
@app.route('/onepad', methods=['GET', 'POST'])
def onepad():
    if request.method == "POST":
        type = request.form.get('action')
        message = request.form.get('Text')
        output_message=""
        if message == None or message == "":
            output_message ="Empty"
        else:
            output_message = one_time_pad_cipher(message, type)

        return  render_template(
            "one_time_pad.html",
            input=message,
            output = output_message
        )
    return render_template("one_time_pad.html")

# ======================================================================================================================
@app.route('/autokey', methods=['GET', 'POST'])
def autokey():
    if request.method=="POST":
        type = request.form.get('action')
        message = request.form.get('Text')
        key = request.form.get("key")
        output_message=""
        if message == None or message == "" or key == "" or key == None:
            output_message = "Empty"
        else:
            output_message = autokey_cipher(message, key)

        return render_template(
            "autokey.html",
            input = message,
            output = output_message
        )
    return render_template("autokey.html")
# ======================================================================================================================
@app.route('/row_transpostion', methods=['GET', 'POST'])
def rowtranspostion():
    if request.method == 'POST':
        type = request.form.get('action')
        message = request.form.get('Text')
        key = request.form.get('key')
        output_message=""
        if message == None or message == "":
            output_message ="Empty"
            matrix=build_matrix("Empty message you enter", key)
        else:
            if type == 'encrypt':
                output_message = row_transposition_encrypt(message, key)
                matrix = build_matrix(message, key)
            else:
                output_message = row_transposition_decrypt(message, key)
                matrix = build_matrix(message, key)

        return render_template(
            'row_transpostion.html',
            matrix=matrix,
            key = key,
            input=message,
            output=output_message
        )
    return render_template('row_transpostion.html')

# ======================================================================================================================
# /multi"
@app.route('/multi', methods=['GET', 'POST'])
def multi_cipher():
    if request.method == 'POST':
        type = 'encrypt'
        message = request.form.get('Text')
        output_message = message
        ceaser = request.form.get('generate_key_1')
        vigenere = request.form.get('generate_key_2')
        playfair = request.form.get('generate_key_3')
        monoalphabetic = request.form.get('generate_key_4')
        vernam = request.form.get('generate_key_5')
        one_pad = request.form.get('generate_key_6')
        railfence = request.form.get('generate_key_7')
        row_transpostion = request.form.get('generate_key_8')
        auto_key = request.form.get('generate_key_9')


        if ceaser != None:
            amount = request.form.get("cipher_shift")
            if amount == None:
                amount = 1
                output_message = ceaser_cipher(output_message, amount, type)
            else:
                output_message = ceaser_cipher(output_message,int(amount),type)

        if vigenere != None:
            key = request.form.get("vigenère_key")
            if key == None:
                key = "key"
                output_message = vigenere_cipher(output_message, key, type)
            else:
                output_message = vigenere_cipher(output_message,key,type)

        if playfair != None:
            key = request.form.get("playfair_key")
            if key == None:
                key = "key"
                output_message = playfair_cipher(output_message, key, type)
            else:
                output_message = playfair_cipher(output_message, key, type)

        if monoalphabetic != None:
            output_message = monoalphabetic_cipher(output_message, type)

        if one_pad !=None:
            output_message = one_time_pad_cipher(output_message, type)

        if railfence != None:
            key = request.form.get("rails")
            if key == None:
                output_message=rail_fence(output_message, 2, type)
            else:
                output_message = rail_fence(output_message, int(key), type)

        if row_transpostion != None:
            key = request.form.get("row_key")
            if key == None:
                key = "4312567"
                output_message = row_transposition_encrypt(output_message, key)
            else:
                output_message = row_transposition_encrypt(output_message, key)

        if  auto_key != None:
            key = request.form.get("key_autokey")
            if key == None:
                key = "key"
                output_message = autokey_cipher(output_message, key)
            else :
                output_message = autokey_cipher(output_message, key)
        if vernam != None:
            output_message = vernam_cipher(output_message,None, type)


        return render_template(
            'Multi_cipher.html',
            input = message,
            output=output_message
        )

    return render_template('Multi_cipher.html')



if __name__ == '__main__':
    app.run(debug=True)
