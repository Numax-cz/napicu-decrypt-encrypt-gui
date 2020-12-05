from tkinter import *
import tkinter as tk
from tkinter import filedialog
import os
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from PIL import Image, ImageTk

# pillow
# cryptography

bg = "#2c3e50"
SouborVyberSlozekHodnota = []
# font = ("Courier", 25, 'bold')
font2 = ('calibri', 25, 'bold')
font19 = ('calibri', 19, 'bold')
font16 = ('calibri', 16, 'bold')
class Obrazovka(Tk):
    def __init__(self):
        super().__init__()
        self.geometry("1000x800")
        self.title('NaPicu-Crypt')
        self.iconphoto(False, tk.PhotoImage(file='favicon.png'))

    def IMG(self):
        imgRE = Label(self, bg=bg)
        imgRE.place(relheight=1, relwidth=1)

    def upozorneni(self):
        global TextZadej
        TextZadej = tk.Label(text='Zadej heslo', font=font2, bg=bg, foreground="#2ecc71")
        TextZadej.place(relwidth=1, relheight=0.1)

    def HESLO(self):
        global Heslo
        Heslo = tk.Entry( show='*',font=font16, bg="white")
        Heslo.place(relx=0.5, rely=0.1, relwidth= 0.45, relheight=0.03, anchor='n')
        
    def WARN(self):
        global WarnText
        WarnText = tk.Label(text='Upozornění!!!',foreground='#c0392b',font=font19, bg=bg)
        WarnText.place(relx=0.5, rely=0.15, relwidth= 0.75, relheight=0.06, anchor='n')
    
    def WARNPodText(self):
        global WARNPodText
        WARNPodText = tk.Label(text='Před použitím přejděte do nápovědy!',foreground='#c0392b',font=font16, bg=bg)
        WARNPodText.place(relx=0.5, rely=0.2, relwidth= 0.75, relheight=0.03, anchor='n')

    def TlacitkoKlikSoubory(self):
        global h
        h = Heslo.get() 
        if h != '':
            # Otevření souboru - cesta
            global soubor
            soubor = filedialog.askopenfilename(initialdir="/", title='Vyber soubory',)
            SouborVyberSlozekHodnota.append(soubor)
            if soubor != '':
                #DESTROY
                Heslo.destroy()
                TextZadej.destroy()
                WarnText.destroy()
                WARNPodText.destroy()
                #DESTROY
                WarnText2 = tk.Label(text='Varování!!!',foreground='#c0392b',font=font19, bg=bg)
                WarnText2.place(relx=0.5, rely=0.15, relwidth= 0.75, relheight=0.06, anchor='n')
                WARNPodText2 = tk.Label(text='Opravdu chcete zašifrovat tento soubor? ' + soubor,foreground='#c0392b',font=font16, bg=bg)
                WARNPodText2.place(relx=0.5, rely=0.2, relwidth= 0.75, relheight=0.03, anchor='n')
                TextZadej2 = tk.Label(text='Potvrďte heslo', font=font2, bg=bg)
                TextZadej2.place(relwidth=1, relheight=0.1)
                global klic_us
                heslo_en = h.encode()
                # EJ JOU MORE ŠIFROVANI
                saltA = b'U\xf7+\xe9=4\xbd\xd1\xf3\xd7$\xa2\xa7H\xbe\xc5'
                decod = PBKDF2HMAC(
                    algorithm=hashes.SHA3_512(),
                    length = 32,
                    salt = saltA,
                    iterations = 10000,
                    backend = default_backend()
                )
                klic_us = base64.urlsafe_b64encode(decod.derive(heslo_en))
                # ------FÁZE 3------
                # ------FÁZE 3------
                global Heslo2
                Heslo2 = tk.Entry( show='*',font=font16)
                Heslo2.place(relx=0.5, rely=0.1, relwidth= 0.45, relheight=0.03, anchor='n')    
                # HESLO POTVRZENI 
                Heslo2Potvrzeni = tk.Button(text='Potvrdit heslo',font=font16, borderwidth=0, bg='#e74c3c', activebackground='#c0392b', command=self.PotvrditHeslo) 
                Heslo2Potvrzeni.place(relx=0.5, rely=0.25, relwidth= 0.35, relheight=0.05, anchor='n')  
    def PotvrditHeslo(self):
        h2 = Heslo2.get()
        if h == h2:
            # BASENAME
            SouborBaseName = os.path.basename(soubor)
            # BASENAME - KONCOVKA
            info = os.path.splitext(SouborBaseName)
            SouborBaseNameKoncovka = info[1]
            SouborBaseNameKoncovkaNula = info[0]
            # OVERENI ZDA JE SOUBOR .NAPICUCRYPT
            if SouborBaseNameKoncovka != '.napicucrypt':
                # Otevření souboru - čtení
                try:    #SIFRACE
                    with open(soubor, 'rb') as t:
                        # h = heslo.get() ---- global TlacitkoKlik
                        data = t.read()
                        fernet = Fernet(klic_us)
                        NapicuCrypt = fernet.encrypt(data)
                        t.close
                        f = open(soubor + '.napicucrypt', 'wb')
                        f.write(NapicuCrypt)
                        f.close
                except:
                    # hej more toto opravit potom někdy
                    self.tk.quit()
                os.remove(soubor)
            elif SouborBaseNameKoncovka == '.napicucrypt':
                try:    #DESIFRACE
                    with open (soubor, 'rb') as t:
                        data = t.read()
                        fernet = Fernet(klic_us)
                        NapicuCrypt = fernet.decrypt(data)
                        t.close
                        f = open(SouborBaseNameKoncovkaNula , 'wb')
                        f.write(NapicuCrypt)
                        f.close
                except:
                    # toto taky možná někdy opravit asi
                    self.tk.quit()
    # -----BUTTON-----
    def tlacitko(self):
        global HesloTlacitko
        HesloTlacitko = tk.Button(text='Potvrdit heslo',font=font16, borderwidth=0, bg='#2ecc71', activebackground='#27ae60', command=self.TlacitkoKlikSoubory) 
        HesloTlacitko.place(relx=0.5, rely=0.25, relwidth= 0.35, relheight=0.05, anchor='n')
if __name__ == '__main__':
    window = Obrazovka()
    window.IMG()
    window.upozorneni()
    window.HESLO()
    window.WARN()
    window.WARNPodText()
    window.tlacitko()
    window.mainloop()