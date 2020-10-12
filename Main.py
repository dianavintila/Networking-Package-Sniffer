import json
from tkinter import Tk, Label, StringVar, Entry, Button, W
from PIL import ImageTk
from PIL.ImageWin import Window
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sniff
from SaveJSON import *
import matplotlib.pyplot as plt

# -------Variabila globala----------#
pachete = None
# -------INTERFATA PROIECT-----------#
root = Tk()
root.geometry('500x100')
root.title("PROJECT")
widget = Label(root, text="PROJECT")

# declaring string variable for storing filter_var and path_var
filter_var = StringVar()
path_var = StringVar()

# set value
filter_var.set("")
path_var.set("")


# metoda pentru captura de pachete
def submit_socket():
    '''
    Daca nu se doreste filtru in entry nu se va scrie nimic
    '''
    filter = filter_entry.get()
    if filter == '':
        print('No filter selected.')
    else:
        print("Filter is : " + filter)
    Captura.sniffing()
    filter_var.set("")

# metoda pentru crearea fisierului de tip JSON
def submit_saveasJSON():
    """
    Se va introduce numele fisierului de tip 'file.json' sau calea fisierului

    """
    path = path_var.get()
    print("Path is : " + path)
    Captura.save_as_json()
    path_var.set("")

# metoda pentru crearea unui pie char
def submit_showStatistics():
    Captura.show_statistics()


# creating a label for filter using widget Label
filter_label = Label(root, text='Filter', font=('calibre', 10, 'bold'))

# creating a entry for input filter using widget Entry
filter_entry = Entry(root, textvariable=filter_var, font=('calibre', 10, 'normal'))

# creating a label for path
path_label = Label(root, text='Path for JSON', font=('calibre', 10, 'bold'))

# creating a entry for path
path_entry = Entry(root, textvariable=path_var, font=('calibre', 10, 'normal'))

# creating a button using the widget Button that will call the submit function
sub_btn = Button(root, text='Packet Sniffer', command=submit_socket)
subJSON_btn = Button(root, text='Save as JSON', command=submit_saveasJSON)
subStat_btn = Button(root,text='Show Statistics', command=submit_showStatistics)
close_btn = Button(root, text='Quit', command=root.destroy).grid(row=4, column=0, sticky=W)

# size Button
filter_label.grid(row=0, column=0)
filter_entry.grid(row=0, column=1)
path_label.grid(row=1, column=0)
path_entry.grid(row=1, column=1)
sub_btn.grid(row=0, column=4)
subJSON_btn.grid(row=0,column=5)
subStat_btn.grid(row=0, column=6)

##################################################################
class Captura():  # clasa de tip singleton

    # instanta -> atribut al clasei
    _instance = None

    @staticmethod
    def get_instance():
        # metoda statica ce returneaza instanta
        if Captura._instance == None:
            Captura()
        return Captura._instance

    def __init__(self):
        # initializator ce implementeaza logica de singleton
        if Captura._instance != None:
            raise Exception("This class is a singleton!")
        else:
            Captura._instance = self

    def sniffing():
        # captura pachete
        global pachete
        pachete = sniff(count=4, filter=filter_var.get())
        for pachet in pachete:
            print(pachet.summary())
            print(pachet.show())

    def save_as_json():
        for pachet in pachete:
            pack_json = Pachet()
            json_dict=pack_json.to_json()

            json_dict['Ethernet']['src'] = pachet["Ethernet"].src
            json_dict['Ethernet']['dst'] = pachet["Ethernet"].dst

            if pachet.haslayer(IP):
                json_dict['IP']['src'] =  pachet["IP"].src
                json_dict['IP']['dst'] =  pachet["IP"].dst
                json_dict['IP']['version'] = pachet["IP"].version
                json_dict['IP']['proto'] = pachet["IP"].proto

            if pachet.haslayer(UDP):
                json_dict['UDP']['sport'] =  pachet["UDP"].sport
                json_dict['UDP']['dport'] =  pachet["UDP"].sport

            if pachet.haslayer(TCP):
                json_dict['TCP']['sport'] = pachet["TCP"].sport
                json_dict['TCP']['dport'] = pachet["TCP"].sport
            print(str(json_dict))
            # nu am folosit str pt ca in fisier imi punea ceva de genu
             # "{\"Ethernet\": {\"src\": \"34:6a:c2:dd:75:76\", \"dst\": \"b8:9a:2a:47:da:06\"}, \"IP\": {\"src\": \"61.9.111.98\", \"dst\": \"192.168.100.14\", \"version\": 4, \"proto\": 17}, \"TCP\": {\"sport\": \"\", \"dport\": \"\"}, \"UDP\": {\"sport\": 28031, \"dport\": 28031}}"
            pack_json.json_file(json_dict, path_var.get())




    def show_statistics():
        size_TCP = len(pachete[TCP])
        size_UDP = len(pachete[UDP])
        slices = [size_TCP, size_UDP]
        label = ['TCP', 'UDP']
        cols = ['c', 'm', 'r', 'b']
        plt.pie(slices, labels=label, colors=cols, startangle=90, shadow=True, autopct='%.2f%%')
        plt.title('UDP TCP')
        plt.show()
        plt.savefig('plot.png')
       

 # performing an infinite loop for the window to display
root.mainloop()
