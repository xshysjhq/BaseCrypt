"""
这是一个base家族加解密程序
author：flex_xie
"""
import base64
import tkinter as tk
from tkinter import messagebox
import base36
import string
import base58
import base62
import base91
import py3base92
def base_encode():
    encode_text = plain_text_entry.get("1.0", "end").strip()
    try:
        base16_encode_string = base64.b16encode(encode_text.encode('utf-8')).decode('utf-8')
        base16_text.delete("1.0", tk.END)
        base16_text.insert("1.0", base16_encode_string)
    except Exception as e:
        base16_text.delete("1.0", tk.END)
        base16_text.insert("1.0", "Error: " + str(e))
    try:
        base32_encode_string = base64.b32encode(encode_text.encode('utf-8')).decode('utf-8')
        base32_text.delete("1.0", tk.END)
        base32_text.insert("1.0", base32_encode_string)
    except Exception as e:
        base32_text.delete("1.0", tk.END)
        base32_text.insert("1.0", "Error: " + str(e))
    try:
        base36_encode_string = base36.dumps(int.from_bytes(encode_text.encode('utf-8'), 'big'))
        base36_text.delete("1.0", tk.END)
        base36_text.insert("1.0", base36_encode_string)
    except Exception as e:
        base36_text.delete("1.0", tk.END)
        base36_text.insert("1.0", "Error: " + str(e))
    try:
        base52_encode_string =base52_encode(encode_text)
        base52_text.delete("1.0", tk.END)
        base52_text.insert("1.0", base52_encode_string)
    except Exception as e:
        base52_text.delete("1.0", tk.END)
        base52_text.insert("1.0", "Error: " + str(e))
    try:
        base56_encode_string =base56_encode(encode_text.encode("utf-8"))
        base56_text.delete("1.0", tk.END)
        base56_text.insert("1.0", base56_encode_string)
    except Exception as e:
        base56_text.delete("1.0", tk.END)
        base56_text.insert("1.0", "Error: " + str(e))
    try:
        base58_encode_string =base58.b58encode(encode_text.encode("utf-8"))
        base58_text.delete("1.0", tk.END)
        base58_text.insert("1.0", base58_encode_string.decode('utf-8'))
    except Exception as e:
        base58_text.delete("1.0", tk.END)
        base58_text.insert("1.0", "Error: " + str(e))
    try:
        base62_encode_string =base62.encodebytes(encode_text.encode("utf-8"))
        base62_text.delete("1.0", tk.END)
        base62_text.insert("1.0", base62_encode_string)
    except Exception as e:
        base62_text.delete("1.0", tk.END)
        base62_text.insert("1.0", "Error: " + str(e))
    try:
        base64_encode_string =base64.b64encode(encode_text.encode("utf-8"))
        base64_text.delete("1.0", tk.END)
        base64_text.insert("1.0", base64_encode_string.decode('utf-8'))
    except Exception as e:
        base64_text.delete("1.0", tk.END)
        base64_text.insert("1.0", "Error: " + str(e))
    try:
        base85_encode_string =base64.a85encode(encode_text.encode("utf-8"))
        base85_text.delete("1.0", tk.END)
        base85_text.insert("1.0", base85_encode_string.decode('utf-8'))
    except Exception as e:
        base85_text.delete("1.0", tk.END)
        base85_text.insert("1.0", "Error: " + str(e))
    try:
        base91_encode_string =base91.encode(encode_text.encode("utf-8"))
        base91_text.delete("1.0", tk.END)
        base91_text.insert("1.0", base91_encode_string)
    except Exception as e:
        base91_text.delete("1.0", tk.END)
        base91_text.insert("1.0", "Error: " + str(e))
    try:
        base92_encode_string =py3base92.b92encode(encode_text.encode("utf-8"))
        base92_text.delete("1.0", tk.END)
        base92_text.insert("1.0", base92_encode_string)
    except Exception as e:
        base92_text.delete("1.0", tk.END)
        base92_text.insert("1.0", "Error: " + str(e))

    try:
        base94_encode_string =base94_encode(encode_text)
        base94_text.delete("1.0", tk.END)
        base94_text.insert("1.0", base94_encode_string)
    except Exception as e:
        base94_text.delete("1.0", tk.END)
        base94_text.insert("1.0", "Error: " + str(e))

    try:
        base100_encode_string =base100_encode(encode_text)
        base100_text.delete("1.0", tk.END)
        base100_text.insert("1.0", base100_encode_string)
    except Exception as e:
        base100_text.delete("1.0", tk.END)
        base100_text.insert("1.0", "Error: " + str(e))
    try:
        base128_encode_string =base128_encode(encode_text)
        base128_text.delete("1.0", tk.END)
        base128_text.insert("1.0", base128_encode_string)
    except Exception as e:
        base128_text.delete("1.0", tk.END)
        base128_text.insert("1.0", "Error: " + str(e))
def base_decode():
    decode_text = plain_text_entry.get("1.0", "end").strip()
    try:
        base16_decode_string = base64.b16decode(decode_text)
        base16_text.delete("1.0", tk.END)
        base16_text.insert("1.0", base16_decode_string.decode('utf-8'))
    except Exception as e:
        base16_text.delete("1.0", tk.END)
        base16_text.insert("1.0", "Error: " + str(e))
    try:
        base32_decode_string = base64.b32decode(decode_text)
        base32_text.delete("1.0", tk.END)
        base32_text.insert("1.0", base32_decode_string.decode('utf-8'))
    except Exception as e:
        base32_text.delete("1.0", tk.END)
        base32_text.insert("1.0", "Error: " + str(e))
    try:
        base36_decode_int = base36.loads(decode_text)
        base36_decode_string=base36_decode_int.to_bytes((base36_decode_int.bit_length() + 7) // 8, 'big').decode('utf-8')
        base36_text.delete("1.0", tk.END)
        base36_text.insert("1.0", base36_decode_string)
    except Exception as e:
        base36_text.delete("1.0", tk.END)
        base36_text.insert("1.0", "Error: " + str(e))
        
    try:
        base52_decode_string=base52_decode(decode_text)
        base52_text.delete("1.0", tk.END)
        base52_text.insert("1.0", base52_decode_string)
    except Exception as e:
        base52_text.delete("1.0", tk.END)
        base52_text.insert("1.0", "Error: " + str(e))

    try:
        base56_decode_string=base56_decode(decode_text)
        base56_text.delete("1.0", tk.END)
        base56_text.insert("1.0", base56_decode_string.decode('utf-8'))
    except Exception as e:
        base56_text.delete("1.0", tk.END)
        base56_text.insert("1.0", "Error: " + str(e))

    try:
        base58_decode_string=base58.b58decode(decode_text)
        base58_text.delete("1.0", tk.END)
        base58_text.insert("1.0", base58_decode_string.decode('utf-8'))
    except Exception as e:
        base58_text.delete("1.0", tk.END)
        base58_text.insert("1.0", "Error: " + str(e))
        
    try:
        base62_decode_string=base62.decodebytes(decode_text)
        base62_text.delete("1.0", tk.END)
        base62_text.insert("1.0", base62_decode_string.decode('utf-8'))
    except Exception as e:
        base62_text.delete("1.0", tk.END)
        base62_text.insert("1.0", "Error: " + str(e))
    try:
        base64_decode_string=base64.b64decode(decode_text)
        base64_text.delete("1.0", tk.END)
        base64_text.insert("1.0", base64_decode_string.decode('utf-8'))
    except Exception as e:
        base64_text.delete("1.0", tk.END)
        base64_text.insert("1.0", "Error: " + str(e))
    try:
        base85_decode_string=base64.a85decode(decode_text)
        base85_text.delete("1.0", tk.END)
        base85_text.insert("1.0", base85_decode_string.decode('utf-8'))
    except Exception as e:
        base85_text.delete("1.0", tk.END)
        base85_text.insert("1.0", "Error: " + str(e))
    try:
        base91_decode_string=base91.decode(decode_text)
        base91_text.delete("1.0", tk.END)
        base91_text.insert("1.0", base91_decode_string.decode('utf-8'))
    except Exception as e:
        base91_text.delete("1.0", tk.END)
        base91_text.insert("1.0", "Error: " + str(e))
    try:
        base92_decode_string=py3base92.b92decode(decode_text)
        base92_text.delete("1.0", tk.END)
        base92_text.insert("1.0", base92_decode_string.decode('utf-8'))
    except Exception as e:
        base92_text.delete("1.0", tk.END)
        base92_text.insert("1.0", "Error: " + str(e))

    try:
        base94_decode_string=base94_decode(decode_text)
        base94_text.delete("1.0", tk.END)
        base94_text.insert("1.0", base94_decode_string)
    except Exception as e:
        base94_text.delete("1.0", tk.END)
        base94_text.insert("1.0", "Error: " + str(e))
        
    try:
        base100_decode_string=base100_decode(decode_text)
        base100_text.delete("1.0", tk.END)
        base100_text.insert("1.0", base100_decode_string)
    except Exception as e:
        base100_text.delete("1.0", tk.END)
        base100_text.insert("1.0", "Error: " + str(e))

    try:
        base128_decode_string = base128_decode(decode_text)
        base128_text.delete("1.0", tk.END)
        base128_text.insert("1.0", base128_decode_string)
    except Exception as e:
        base128_text.delete("1.0", tk.END)
        base128_text.insert("1.0", "Error: " + str(e))
# Base56 字符集 (去除了 0, O, I, l 等容易混淆的字符)
BASE56_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
BASE = 56
BASE52_CHARSET = string.ascii_uppercase + string.ascii_lowercase
# 创建字符到索引的映射字典
char_to_index = {char: index for index, char in enumerate(BASE56_ALPHABET)}
BASE94_CHARSET = ''.join(chr(i) for i in range(32, 127))
BASE100_CHARSET = ''.join(chr(i) for i in range(32, 132))
BASE128_CHARSET = ''.join(chr(i) for i in range(128))
def base52_encode(input_string: str) -> str:
    # 将字符串转换为整数
    num = int.from_bytes(input_string.encode('utf-8'), 'big')

    # 进行Base52编码
    encoded = ""
    while num > 0:
        encoded = BASE52_CHARSET[num % 52] + encoded
        num //= 52
    return encoded


# Base52解码
def base52_decode(encoded_string: str) -> str:
    # 将Base52字符串转换为数字
    num = 0
    for char in encoded_string:
        num = num * 52 + BASE52_CHARSET.index(char)

    # 将数字转换回字符串
    byte_length = (num.bit_length() + 7) // 8  # 计算字节长度
    decoded_bytes = num.to_bytes(byte_length, 'big')
    return decoded_bytes.decode('utf-8')
def base56_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")  # 将字节转换为整数
    if num == 0:
        return BASE56_ALPHABET[0]

    encoded = ""
    while num > 0:
        num, remainder = divmod(num, BASE)
        encoded = BASE56_ALPHABET[remainder] + encoded

    return encoded

def base56_decode(encoded: str) -> bytes:
    num = 0
    for char in encoded:
        if char not in char_to_index:
            raise ValueError(f"字符 {char} 不在 Base56 字符集内")
        num = num * BASE + char_to_index[char]

    num_bytes = (num.bit_length() + 7) // 8  # 计算所需字节数
    return num.to_bytes(num_bytes, "big")


def base94_encode(input_string: str) -> str:
    # 将输入字符串转换为整数
    num = int.from_bytes(input_string.encode('utf-8'), 'big')

    encoded = ""
    while num > 0:
        encoded = BASE94_CHARSET[num % 94] + encoded
        num //= 94
    return encoded


# Base94解码
def base94_decode(encoded_string: str) -> str:
    # 将Base94字符串转换为数字
    num = 0
    for char in encoded_string:
        num = num * 94 + BASE94_CHARSET.index(char)
    byte_length = (num.bit_length() + 7) // 8  # 计算字节长度
    decoded_bytes = num.to_bytes(byte_length, 'big')
    return decoded_bytes.decode('utf-8')


# Base100编码
def base100_encode(input_string: str) -> str:
    num = int.from_bytes(input_string.encode('utf-8'), 'big')
    encoded = ""
    while num > 0:
        encoded = BASE100_CHARSET[num % 100] + encoded
        num //= 100
    return encoded


# Base100解码
def base100_decode(encoded_string: str) -> str:
    num = 0
    for char in encoded_string:
        num = num * 100 + BASE100_CHARSET.index(char)
    byte_length = (num.bit_length() + 7) // 8  # 计算字节长度
    decoded_bytes = num.to_bytes(byte_length, 'big')
    return decoded_bytes.decode('utf-8')


def base128_encode(input_string: str) -> str:
    # 将输入字符串转换为整数
    num = int.from_bytes(input_string.encode('utf-8'), 'big')

    # 进行Base128编码
    encoded = ""
    while num > 0:
        encoded = BASE128_CHARSET[num % 128] + encoded
        num //= 128
    return encoded


# Base128解码
def base128_decode(encoded_string: str) -> str:
    # 将Base128字符串转换为数字
    num = 0
    for char in encoded_string:
        num = num * 128 + BASE128_CHARSET.index(char)

    # 将数字转换回字节
    byte_length = (num.bit_length() + 7) // 8  # 计算字节长度
    decoded_bytes = num.to_bytes(byte_length, 'big')
    return decoded_bytes.decode('utf-8')



window = tk.Tk()
window.title("base转换")
window.geometry("1000x650")
# 创建输入框和标签
plain_text_label = tk.Label(window, text="输入需\n要加密\n或解密\n的内容：",font=("Arial",18))
plain_text_label.place(x=100,y=50)
plain_text_entry = tk.Text(window, height=7, width=85, wrap="word")
plain_text_entry.place(x=200,y=50)


# 创建按钮
encode_btn = tk.Button(window, text="一键加密",command=base_encode,font=("Arial",18))
encode_btn.place(x=280,y=160)
decode_btn = tk.Button(window, text="一键解密",command=base_decode,font=("Arial",18))
decode_btn.place(x=480,y=160)

base16_label = tk.Label(window, text="base16：",font=("Arial",12))
base16_label.place(x=100,y=240)
base16_text = tk.Text(window, height=10, width=15, wrap="word")
base16_text.place(x=100,y=270)
base32_label = tk.Label(window, text="base32：",font=("Arial",12))
base32_label.place(x=220,y=240)
base32_text = tk.Text(window, height=10, width=15, wrap="word")
base32_text.place(x=220,y=270)
base36_label = tk.Label(window, text="base36：",font=("Arial",12))
base36_label.place(x=340,y=240)
base36_text = tk.Text(window, height=10, width=15, wrap="word")
base36_text.place(x=340,y=270)
base52_label = tk.Label(window, text="base52：",font=("Arial",12))
base52_label.place(x=460,y=240)
base52_text = tk.Text(window, height=10, width=15, wrap="word")
base52_text.place(x=460,y=270)
base56_label = tk.Label(window, text="base56：",font=("Arial",12))
base56_label.place(x=580,y=240)
base56_text = tk.Text(window, height=10, width=15, wrap="word")
base56_text.place(x=580,y=270)
base58_label = tk.Label(window, text="base58：",font=("Arial",12))
base58_label.place(x=700,y=240)
base58_text = tk.Text(window, height=10, width=15, wrap="word")
base58_text.place(x=700,y=270)
base62_label = tk.Label(window, text="base62：",font=("Arial",12))
base62_label.place(x=820,y=240)
base62_text = tk.Text(window, height=10, width=15, wrap="word")
base62_text.place(x=820,y=270)
base64_label = tk.Label(window, text="base64：",font=("Arial",12))
base64_label.place(x=100,y=440)
base64_text = tk.Text(window, height=10, width=15, wrap="word")
base64_text.place(x=100,y=470)
base85_label = tk.Label(window, text="base85：",font=("Arial",12))
base85_label.place(x=220,y=440)
base85_text = tk.Text(window, height=10, width=15, wrap="word")
base85_text.place(x=220,y=470)
base91_label = tk.Label(window, text="base91：",font=("Arial",12))
base91_label.place(x=340,y=440)
base91_text = tk.Text(window, height=10, width=15, wrap="word")
base91_text.place(x=340,y=470)
base92_label = tk.Label(window, text="base92：",font=("Arial",12))
base92_label.place(x=460,y=440)
base92_text = tk.Text(window, height=10, width=15, wrap="word")
base92_text.place(x=460,y=470)
base94_label = tk.Label(window, text="base94：",font=("Arial",12))
base94_label.place(x=580,y=440)
base94_text = tk.Text(window, height=10, width=15, wrap="word")
base94_text.place(x=580,y=470)
base100_label = tk.Label(window, text="base100：",font=("Arial",12))
base100_label.place(x=700,y=440)
base100_text = tk.Text(window, height=10, width=15, wrap="word")
base100_text.place(x=700,y=470)
base128_label = tk.Label(window, text="base128：",font=("Arial",12))
base128_label.place(x=820,y=440)
base128_text = tk.Text(window, height=10, width=15, wrap="word")
base128_text.place(x=820,y=470)
window.mainloop()

