#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time : 2022/2/16 15:27
# @Author : raysuen
# @version 1.3
# Packages needed before running: PySide6,pycryptodomex
#       run to install:
#           pip3 install pycryptodomex
#           pip3 install PySide6


import sys
from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication,
    QVBoxLayout, QDialog,QLabel)
from PySide6 import QtCore
from Cryptodome.Cipher import AES
from binascii import b2a_hex, a2b_hex

AES_LENGTH = 16

class prpcrypt():

    def __init__(self, key=None):
        if key != None:
            self.key = key
            self.cryptor = AES.new(self.pad_key(self.key).encode(), self.mode)
        self.mode = AES.MODE_ECB


    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    # 加密内容需要长达16位字符，所以进行空格拼接
    def pad(self,text):
        if isinstance(text,bytes):
            while len(text) % AES_LENGTH != 0:
                text += ' '.encode()
        elif isinstance(text,(str,int)):
            while len(text) % AES_LENGTH != 0:
                text += ' '
        return text

    # 加密密钥需要长达16位字符，所以进行空格拼接
    def pad_key(self,key):
        while len(key) % AES_LENGTH != 0:
            key += ' '
        return key

    def encrypt(self,text, key=None):
        if key != None:
            self.key=key
            self.cryptor = AES.new(self.pad_key(self.key).encode(), self.mode)
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        # 加密的字符需要转换为bytes
        # print(self.pad(text))
        self.ciphertext = self.cryptor.encrypt(self.pad(text).encode())
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text, key=None):
        if key != None:
            self.key=key
            self.cryptor = AES.new(self.pad_key(self.key).encode(), self.mode)
        plain_text = self.cryptor.decrypt(a2b_hex(text)).decode()
        return plain_text.rstrip(' ')


class Form(QDialog):

    def __init__(self, prpcrypt,parent=None):
        super(Form, self).__init__(parent)
        pc = prpcrypt
        # Create widgets
        self.keytext = QLabel("Key:", alignment=QtCore.Qt.AlignLeft)
        self.stringtext = QLabel("Strings:", alignment=QtCore.Qt.AlignLeft)
        self.keys = QLineEdit("    keys")
        self.edit = QLineEdit("    input strings")
        self.buttonEncrypt = QPushButton("加密")
        self.buttonDecrypt = QPushButton("解密")
        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addWidget(self.keytext)
        layout.addWidget(self.keys)
        layout.addWidget(self.stringtext)
        layout.addWidget(self.edit)
        layout.addWidget(self.buttonEncrypt)
        layout.addWidget(self.buttonDecrypt)
        # Set dialog layout
        self.setLayout(layout)
        # Add button signal to greetings slot
        self.buttonEncrypt.clicked.connect(self.EncryptString)
        # Add button signal to greetings slot
        self.buttonDecrypt.clicked.connect(self.DecryptString)

    # Show Encrypt string
    def EncryptString(self):
        self.edit.setText(str(pc.encrypt(self.edit.text(),self.keys.text()))[2:-1])

    #Show Decrypt string
    def DecryptString(self):
        self.edit.setText(str(pc.decrypt(self.edit.text(), self.keys.text())))


if __name__ == '__main__':
    pc = prpcrypt()
    # Create the Qt Application
    app = QApplication(sys.argv)
    # Create and show the form
    form = Form(pc)
    form.resize(350,100)
    form.show()
    # Run the main Qt loop
    sys.exit(app.exec())

