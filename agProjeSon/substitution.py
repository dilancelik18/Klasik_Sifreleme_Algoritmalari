import sys
from PyQt5 import QtCore
from PyQt5.QtWidgets import QWidget, QApplication, QLineEdit, QPushButton, QLabel, QVBoxLayout

class Pencere(QWidget):
    def __init__(self):
        super().__init__()
        self.ozellikEkle()
        self.ekOzellikEkle()
        self.birOzellikEkle()
        self.buton.clicked.connect(self.tiklandi)
        self.buton1.clicked.connect(self.tiiklandi)

    def ozellikEkle(self):
        self.resize(500, 500)
        self.move(700, 100)
        self.setWindowTitle('Substitution Şifreleme')

    def ekOzellikEkle(self):
        self.input_metin = QLineEdit(self)
        self.input_metin.setPlaceholderText("Şifrelenecek Metni Giriniz")
        self.input_metin.setGeometry(10, 10, 470, 25)

        self.input_anahtar = QLineEdit(self)
        self.input_anahtar.setPlaceholderText("Şifreleme Anahtarını Giriniz")
        self.input_anahtar.setGeometry(10, 50, 470, 25)

        self.buton = QPushButton("ŞİFRELE", self)
        self.buton.setGeometry(10, 90, 470, 25)

        self.label = QLabel( self)
        self.label.setGeometry(10, 150, 200, 75)

        

    def tiklandi(self):
        plain_text = self.input_metin.text()
        key = self.input_anahtar.text()

        encrypted_text = self.substitution_encrypt(plain_text, key)
        self.label.setText(encrypted_text)

    def birOzellikEkle(self):
        self.buton1 = QPushButton("ÇÖZ", self)
        self.buton1.setGeometry(10, 130, 470, 25)

        self.label1 = QLabel( self)
        self.label1.setGeometry(250, 150, 200, 75)

    def tiiklandi(self):
        encrypted_text = self.input_metin.text()
        key = self.input_anahtar.text()

        decrypted_text = self.substitution_decrypt(encrypted_text, key)
        self.label1.setText(decrypted_text)

    def substitution_encrypt(self, plain_text, key):
        import string

        alphabet = string.ascii_uppercase
        unique_key = ''.join(sorted(set(key.upper()), key=lambda x: key.upper().index(x)))
        encrypted_alphabet = unique_key + ''.join(sorted(set(alphabet) - set(unique_key)))

        encrypted_text = ''
        for char in plain_text.upper():
            if char in alphabet:
                index = alphabet.index(char)
                encrypted_text += encrypted_alphabet[index]
            else:
                encrypted_text += char
        return encrypted_text

    def substitution_decrypt(self, encrypted_text, key):
        import string

        alphabet = string.ascii_uppercase
        unique_key = ''.join(sorted(set(key.upper()), key=lambda x: key.upper().index(x)))
        encrypted_alphabet = unique_key + ''.join(sorted(set(alphabet) - set(unique_key)))

        decrypted_text = ''
        for char in encrypted_text.upper():
            if char in encrypted_alphabet:
                index = encrypted_alphabet.index(char)
                decrypted_text += alphabet[index]
            else:
                decrypted_text += char
        return decrypted_text

app = QApplication(sys.argv)
pencere = Pencere()
pencere.show()
sys.exit(app.exec_())