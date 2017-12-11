from Tkinter import *
import Tkinter as tk
import tkMessageBox
import sys
from subprocess import call

def writeClient():
    filename = namel.get()
    key = passl.get()

    call(['./client','w', filename, key])

def readClient():
    filename = namel.get()
    key = passl.get()

    call(['./client','r', filename, key])


def printColor():
    print 'red: ', RedE.get()
    print 'green: ', GreenE.get()
    print 'blue: ', BlueE.get()


top=Tk()
top.title("Gumstix Vault")
namel= Label(top, text="File Name")
namel.grid(row=1,column=1)
namel = Entry(top)
namel.grid(row=1,column=2)

passl = Label(top, text="Password")
passl.grid(row=2,column=1)
passl = Entry(top)
passl.grid(row=2,column=2)

write = Button(top,text='Write File', command=writeClient, height=2)
write.grid(row=6,column=1)

read = Button(top,text='Read File', command=readClient, height=2)
read.grid(row=6,column=2)

top.mainloop()
print 'here'


