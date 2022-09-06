from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
import hashlib
import os

def reset_fields():
    global file
    root.title('GUI HashGen')
    e0.delete(0,END)
    e1.delete(0,END)
    e2.delete(0,END)
    e3.delete(0,END)
    e4.delete(0,END)
    file = None
    b2.config(state=DISABLED)
    statusvar.set("READY")

def fileopen():
    "Open File"
    global file
    file = askopenfilename(filetypes=[("All Files", "*.*")])
    if file == () or file == "":
        #print(file)
        b2.config(state=DISABLED)
        file = None
        statusvar.set('NO FILE SELECTED')
    else:
        #print(file)
        b2.config(state=NORMAL)
        root.title(os.path.basename(file) + " - GUI HashGen")
        statusvar.set('FILE SELECTED')

def calchash():
    "Calculate hash"
    global file
    if(file == None):
        statusvar.set('NO FILE SELECTED')
    else:
        e1.config(state=NORMAL)
        e2.config(state=NORMAL)
        e3.config(state=NORMAL)
        e4.config(state=NORMAL)

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        list_hash_objects = [md5, sha1, sha256, sha512]

        L={} #empty dictionary
        for hash_object in list_hash_objects:
            with open(file, 'rb') as opened_file:
                for onebyte in opened_file:
                    hash_object.update(onebyte)
                L[hash_object.name]=hash_object.hexdigest()
                #print('{}: {}'.format(hash_object.name, hash_object.hexdigest()))
        #print(L)

        checksum = h0.get() #get checksum input
        if checksum=='':
            statusvar.set('DONE')
        elif checksum==L['md5']:
            statusvar.set('DONE : MD5 VERIFIED')
        elif checksum==L['sha1']:
            statusvar.set('DONE : SHA1 VERIFIED')
        elif checksum==L['sha256']:
            statusvar.set('DONE : SHA256 VERIFIED')
        elif checksum==L['sha512']:
            statusvar.set('DONE : SHA512 VERIFIED')
        else:
            statusvar.set('DONE : ALERT! GIVEN CHECKSUM DOESN\'T MATCH MD5, SHA1, SHA256 OR SHA512')
        h1.set(L['md5'])
        h2.set(L['sha1'])
        h3.set(L['sha256'])
        h4.set(L['sha512'])
        del L

if __name__ == '__main__':
    file = None

    root=Tk()
    root.geometry("1555x207")
    root.title('GUI HashGen')
    root.maxsize(1555,207)
    root.minsize(1555,207)

    b0 = Button(root, text="Reset fields", command=reset_fields, font="lucida 13", relief=RAISED, border=3)
    b0.grid(row=0, column=0)

    b1 = Button(root, text="Select File", command=fileopen, font="lucida 13", relief=RAISED, border=3)
    b2 = Button(root, text="Calculate hash!", command=calchash, font="lucida 13", relief=RAISED, border=3, state=DISABLED)
    b1.grid(row=0, column=1)
    b2.grid(row=0, column=1, sticky=E)

    l0 = Label(root, text="Checksum :", font="lucida 13")
    l1 = Label(root, text="MD5          :", font="lucida 13")
    l2 = Label(root, text="SHA1         :", font="lucida 13")
    l3 = Label(root, text="SHA256     :", font="lucida 13")
    l4 = Label(root, text="SHA512     :", font="lucida 13")
    
    l0.grid(row=1, column=0)
    l1.grid(row=2, column=0)
    l2.grid(row=3, column=0)
    l3.grid(row=4, column=0)
    l4.grid(row=5, column=0)

    h0=StringVar()
    h1=StringVar()
    h2=StringVar()
    h3=StringVar()
    h4=StringVar()

    e0=Entry(root, width=128, textvariable=h0, font="lucida 13")
    e1=Entry(root, width=128, textvariable=h1, font="lucida 13", state=DISABLED)
    e2=Entry(root, width=128, textvariable=h2, font="lucida 13", state=DISABLED)
    e3=Entry(root, width=128, textvariable=h3, font="lucida 13", state=DISABLED)
    e4=Entry(root, width=128, textvariable=h4, font="lucida 13", state=DISABLED)

    e0.grid(row=1, column=1)
    e1.grid(row=2, column=1)
    e2.grid(row=3, column=1)
    e3.grid(row=4, column=1)
    e4.grid(row=5, column=1)

    statusvar = StringVar()
    statusvar.set("READY")
    sbar = Label(root, textvariable=statusvar, font="lucida 13", justify=CENTER, relief=SUNKEN, width=141)
    sbar.grid(row=6, column=0, columnspan=2)
    root.mainloop()