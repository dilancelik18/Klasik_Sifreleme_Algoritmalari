import sys
from PyQt5.QtWidgets import QWidget, QApplication, QLineEdit, QPushButton, QLabel

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
        self.setWindowTitle('Dogrusal Şifreleme')

    def ekOzellikEkle(self):
        self.input_metin = QLineEdit(self)
        self.input_metin.setPlaceholderText("Şifrelenecek Metni Giriniz")
        self.input_metin.setGeometry(10, 10, 470, 25)

        self.input_anahtar = QLineEdit(self)
        self.input_anahtar.setPlaceholderText("Şifreleme için 1.Anahtarı Giriniz")
        self.input_anahtar.setGeometry(10, 50, 470, 25)

        self.input_anahtar2 = QLineEdit(self)
        self.input_anahtar2.setPlaceholderText("Şifreleme için 2.Anahtarı Giriniz")
        self.input_anahtar2.setGeometry(10, 90, 470, 25)

        self.buton = QPushButton("ŞİFRELE", self)
        self.buton.setGeometry(10, 130, 470, 25)

        self.label = QLabel( self)
        self.label.setGeometry(10, 200, 200, 75)

    def tiklandi(self):
        metin = self.input_metin.text()
        a =int(self.input_anahtar.text())
        b =int(self.input_anahtar2.text())

        sifreli_metin = self.dogrusal_sifrele(metin, a, b)
        self.label.setText(sifreli_metin)

    def birOzellikEkle(self):

        self.buton1 = QPushButton("ÇÖZ", self)
        self.buton1.setGeometry(10, 170, 470, 25)

        self.label1 = QLabel( self)
        self.label1.setGeometry(250, 200, 200, 75)

    def tiiklandi(self):
        sifreli_metin = self.input_metin.text()
        a =int(self.input_anahtar.text())
        b =int(self.input_anahtar2.text())

        cozulmusmetin = self.dogrusal_coz(sifreli_metin, a,b)
        self.label1.setText(cozulmusmetin)


    def dogrusal_sifrele(self,metin, a, b):
            sifreli_metin = ""
            for karakter in metin:
                if karakter.isalpha():
                    buyuk_harf = karakter.isupper()
                    karakter_sira = ord(karakter.upper()) - ord('A')
                    sifreli_sira = (a * karakter_sira + b) % 26
                    sifreli_karakter = chr(sifreli_sira + ord('A'))
                    if buyuk_harf:
                        sifreli_metin += sifreli_karakter
                    else:
                        sifreli_metin += sifreli_karakter.lower()
                else:
                    sifreli_metin += karakter
            return sifreli_metin

    def dogrusal_coz(self,sifreli_metin, a, b):
            mod_tersi = pow(a, -1, 26)  # a'nın modüler tersini hesapla
            orjinal_metin = ""
            for karakter in sifreli_metin:
                if karakter.isalpha():
                    buyuk_harf = karakter.isupper()
                    karakter_sira = ord(karakter.upper()) - ord('A')
                    orjinal_sira = (mod_tersi * (karakter_sira - b)) % 26
                    orjinal_karakter = chr(orjinal_sira + ord('A'))
                    if buyuk_harf:
                        orjinal_metin += orjinal_karakter
                    else:
                        orjinal_metin += orjinal_karakter.lower()
                else:
                    orjinal_metin += karakter
            return orjinal_metin

app = QApplication(sys.argv)
pencere = Pencere()
pencere.show()
sys.exit(app.exec_())

