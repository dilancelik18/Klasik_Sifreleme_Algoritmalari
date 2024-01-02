import tkinter as tk
import sys
from PyQt5.QtWidgets import QWidget, QApplication, QLineEdit, QPushButton, QLabel
    

def sayfa_degistir():
    secilen_sayfa = secenek.get()
    
    if secilen_sayfa == "Sezar Şifreleme":
        import sezar
    elif secilen_sayfa == "Doğrusal Şifreleme":
        import dogrusalSifreleme
    elif secilen_sayfa == "Substitution Şifreleme":
        import substitution
    elif secilen_sayfa == "Playfair Sifreleme":
        import playfair
    elif secilen_sayfa == "Kendi Algoritmamiz":
        import kendialgoritmamiz
   
root = tk.Tk()
root.geometry("700x500")
root.title("ŞİFRELEME VE ŞİFRE ÇÖZME UYGULAMASI")
secenekler = ["Şifreleme Yöntemi seciniz","Sezar Şifreleme", "Doğrusal Şifreleme", "Substitution Şifreleme","Playfair Sifreleme","Kendi Algoritmamiz"]

secenek = tk.StringVar(root)
secenek.set(secenekler[0])

etiket = tk.Label(root, text="ŞİFRELEME VE ŞİFRE ÇÖZME UYGULAMASINA HOŞ GELDİNİZ",font="verdana 12 bold",width=50,height=12)
etiket.pack()

etiket1 = tk.Label(root,text="ŞİFRELEME UYGULAMAMIZDA 5 ŞİFRELEME ALGORİTMASI BULUNMAKTADIR",font="verdana 10 bold",height=10)
etiket1.pack()

secenek_menu = tk.OptionMenu(root, secenek, *secenekler)
secenek_menu.config(width=100)
secenek_menu.pack()

buton_git = tk.Button(root, text="GİT",bg="black",fg="white",font="verdana 12 bold", command=sayfa_degistir)
buton_git.place(x=250,y=300,width=200, height=70)
buton_git.pack()


root.mainloop()