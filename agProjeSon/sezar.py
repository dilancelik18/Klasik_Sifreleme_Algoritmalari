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
        self.setWindowTitle('Sezar Şifreleme')

    def ekOzellikEkle(self):
        self.input_metin = QLineEdit(self)
        self.input_metin.setPlaceholderText("ŞİFRELENECEK METNİ GİRİNİZ") 
        self.input_metin.setGeometry(10, 10, 470, 25)


        self.input_anahtar = QLineEdit(self)
        self.input_anahtar.setPlaceholderText("KAYDIRMA MİKTARINI GİRİNİZ") 
        self.input_anahtar.setGeometry(10, 50, 470, 25)

        self.buton = QPushButton("ŞİFRELE", self)
        self.buton.setGeometry(10, 90, 470, 25)

        self.label = QLabel(self)
        self.label.setGeometry(10, 150, 200, 75)

    def tiklandi(self):
        metin = self.input_metin.text()
        kaydirma =int(self.input_anahtar.text())

        sifreli_metin = self.sezar_sifrele(metin, kaydirma)
        self.label.setText(sifreli_metin)

    def birOzellikEkle(self):

        self.buton1 = QPushButton("ÇÖZ", self)
        self.buton1.setGeometry(10, 130, 470, 25)

        self.label1 = QLabel(self)
        self.label1.setGeometry(250, 150, 200, 75)

    def tiiklandi(self):
        sifreli_metin = self.input_metin.text()
        kaydirma = int(self.input_anahtar.text())

        cozulmusmetin = self.sezar_coz(sifreli_metin, kaydirma)
        self.label.setText(cozulmusmetin)

    def sezar_sifrele(self,metin, kaydirma):
        sifreli_metin = ""
        for karakter in metin:
            if karakter.isalpha():
                buyuk_harf = karakter.isupper()
                karakter_sira = ord(karakter.upper()) - ord('A')
                sifreli_sira = (karakter_sira + kaydirma) % 26
                sifreli_karakter = chr(sifreli_sira + ord('A'))
                if buyuk_harf:
                    sifreli_metin += sifreli_karakter
                else:
                    sifreli_metin += sifreli_karakter.lower()
            else:
                sifreli_metin += karakter
        return sifreli_metin


    def sezar_coz(self,sifreli_metin, kaydirma):
        cozulmus_metin = ""
        for karakter in sifreli_metin:
            if karakter.isalpha():
                buyuk_harf = karakter.isupper()
                karakter_sira = ord(karakter.upper()) + ord('A')
                sifreli_sira = (karakter_sira - kaydirma) % 26
                sifreli_karakter = chr(sifreli_sira + ord('A'))
                if buyuk_harf:
                    cozulmus_metin += sifreli_karakter
                else:
                    cozulmus_metin += sifreli_karakter.lower()
            else:
                cozulmus_metin += karakter
        return cozulmus_metin


app = QApplication(sys.argv)
pencere = Pencere()
pencere.show()
sys.exit(app.exec_())