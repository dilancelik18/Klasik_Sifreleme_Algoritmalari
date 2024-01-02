import sys
from PyQt5 import QtCore
from PyQt5.QtWidgets import QWidget, QApplication, QLineEdit, QPushButton, QLabel, QVBoxLayout


class PlayfairCipher(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.resize(500, 500)
        self.move(700, 100)
        self.setWindowTitle('Playfair Şifreleme')

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("ANAHTARI GİRİNİZ")
        self.text_input = QLineEdit(self)
        self.text_input.setPlaceholderText("Metni Giriniz")

        self.encrypt_button = QPushButton("ŞİFRELE", self)
        

        self.decrypt_button = QPushButton("ÇÖZ", self)

        self.result_label = QLabel("", self)

        vbox = QVBoxLayout()
        vbox.addWidget(self.text_input)
        vbox.addWidget(self.key_input)
        vbox.addWidget(self.encrypt_button)
        vbox.addWidget(self.decrypt_button)
        vbox.addWidget(self.result_label)

        self.setLayout(vbox)

        self.encrypt_button.clicked.connect(self.encrypt_clicked)
        self.decrypt_button.clicked.connect(self.decrypt_clicked)

    def generate_matrix(self, key):
        key = key.replace(" ", "").upper()
        result = []
        for c in key:
            if c not in result:
                if c == 'J':
                    result.append('I')
                else:
                    result.append(c)
        flag = 0
        for i in range(65, 91):
            if chr(i) not in result:
                if i == 73 and chr(74) not in result:
                    result.append("I")
                    flag = 1
                elif flag == 0 and i == 73 or i == 74:
                    pass
                else:
                    result.append(chr(i))
        k = 0
        matrix = [[0 for _ in range(5)] for _ in range(5)]
        for i in range(0, 5):
            for j in range(0, 5):
                matrix[i][j] = result[k]
                k += 1
        return matrix

    def get_char_location(self, c, matrix):
        loc = []
        if c == 'J':
            c = 'I'
        for i, row in enumerate(matrix):
            for j, char in enumerate(row):
                if c == char:
                    loc.append(i)
                    loc.append(j)
                    return loc

    def encrypt_text(self, matrix):
        msg = self.text_input.text().upper().replace(" ", "")
        i = 0
        sifreli_metin = ""
        for s in range(0, len(msg) + 1, 2):
            if s < len(msg) - 1:
                if msg[s] == msg[s + 1]:
                    msg = msg[:s + 1] + 'X' + msg[s + 1:]
        if len(msg) % 2 != 0:
            msg = msg[:] + 'X'
        while i < len(msg):
            loc = self.get_char_location(msg[i], matrix)
            loc1 = self.get_char_location(msg[i + 1], matrix)
            if loc[1] == loc1[1]:
                sifreli_metin += "{}{}".format(matrix[(loc[0] + 1) % 5][loc[1]], matrix[(loc1[0] + 1) % 5][loc1[1]])
            elif loc[0] == loc1[0]:
                sifreli_metin += "{}{}".format(matrix[loc[0]][(loc[1] + 1) % 5], matrix[loc1[0]][(loc1[1] + 1) % 5])
            else:
                sifreli_metin += "{}{}".format(matrix[loc[0]][loc1[1]], matrix[loc1[0]][loc[1]])
            i = i + 2
        self.result_label.setText(f" {sifreli_metin}")

    def decrypt_text(self, matrix):
        msg = self.text_input.text().upper().replace(" ", "")
        cozulmus_metin = ""
        i = 0
        while i < len(msg):
            loc = self.get_char_location(msg[i], matrix)
            loc1 = self.get_char_location(msg[i + 1], matrix)
            if loc[1] == loc1[1]:
                cozulmus_metin += "{}{}".format(matrix[(loc[0] - 1) % 5][loc[1]], matrix[(loc1[0] - 1) % 5][loc1[1]])
            elif loc[0] == loc1[0]:
                cozulmus_metin += "{}{}".format(matrix[loc[0]][(loc[1] - 1) % 5], matrix[loc1[0]][(loc1[1] - 1) % 5])
            else:
                cozulmus_metin += "{}{}".format(matrix[loc[0]][loc1[1]], matrix[loc1[0]][loc[1]])
            i = i + 2
        self.result_label.setText(f" {cozulmus_metin}")

    def encrypt_clicked(self):
        key = self.key_input.text()
        matrix = self.generate_matrix(key)
        self.encrypt_text(matrix)

    def decrypt_clicked(self):
        key = self.key_input.text()
        matrix = self.generate_matrix(key)
        self.decrypt_text(matrix)


app = QApplication(sys.argv)
playfair_cipher = PlayfairCipher()
playfair_cipher.show()
sys.exit(app.exec_())