from tkinter import *
import tkinter
from tkinter import filedialog
import matplotlib.pyplot as plt
from tkinter.filedialog import askopenfilename
import numpy as np
import pandas as pd
import shodan
import whois

main = tkinter.Tk()
main.title("IP Masking Detection")
main.geometry("1200x1200")


global filename
global original,vpn
global dataset

def uploadIP():
    global filename
    global dataset
    text.delete('1.0', END)
    filename = filedialog.askopenfilename(initialdir="IP")
    dataset = pd.read_csv(filename)
    text.insert(END,str(filename)+" Dataset Loaded\n\n")
    text.insert(END,str(dataset.head()))
    pathlabel.config(text=str(filename)+" Dataset Loaded\n\n")

def scanIP():
    global original,vpn
    global dataset
    original = 0
    vpn = 0
    text.delete('1.0', END)
    api = shodan.Shodan('OzI0bPD2XXxeT7FCAqWeOvuOLh6IqdeF')
    dataset = dataset.values
    for i in range(len(dataset)):
        try:
            ipinfo = api.host(dataset[i,0])
            if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
                text.insert(END,str(dataset[i,0])+' is connecting from a VPN\n\n')
                vpn = vpn + 1
            else:
                text.insert(END,str(dataset[i,0])+" is an Original IP\n\n")
                original = original + 1
        except:
            text.insert(END,str(dataset[i,0])+" is an Original IP\n\n")
            original = original + 1
        text.update_idletasks()
        
def runWhois():
    text.delete('1.0', END)
    global dataset
    for i in range(len(dataset)):
        w = whois.whois(str(dataset[i,0]))
        text.insert(END,"IP Address    : "+str(dataset[i,0])+"\n")
        text.insert(END,"WHOIS Records : "+str(w)+"\n\n")
        text.update_idletasks()

def graph():
    plt.pie([original,vpn],labels=["Original IP","VPN/Proxy IP"],autopct='%1.1f%%')
    plt.title('Original & VPN IP Graph')
    plt.axis('equal')
    plt.show()

def close():
    main.destroy()

def scanSingleIP():
    text.delete('1.0', END)
    ip = tf1.get()
    api = shodan.Shodan('OzI0bPD2XXxeT7FCAqWeOvuOLh6IqdeF')
    try:
        ipinfo = api.host(ip)
        if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
            text.insert(END,str(ip)+' is connecting from a VPN\n\n')
        else:
            text.insert(END,str(ip)+" is an Original IP\n\n")
            
    except:
        text.insert(END,str(ip)+" is an Original IP\n\n")
    print("\n")
    w = whois.whois(str(ip))
    text.insert(END,"IP Address    : "+str(ip)+"\n")
    text.insert(END,"WHOIS Records : "+str(w)+"\n\n")
    text.update_idletasks()
    

font = ('times', 14, 'bold')
title = Label(main, text='IP Masking Detection')
title.config(bg='DarkGoldenrod1', fg='black')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=5,y=5)

font1 = ('times', 13, 'bold')
uploadButton = Button(main, text="Upload IP Addresses List", command=uploadIP)
uploadButton.place(x=50,y=100)
uploadButton.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='brown', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=560,y=100)

scanButton = Button(main, text="Scan IP Address", command=scanIP)
scanButton.place(x=50,y=150)
scanButton.config(font=font1)

whoisButton = Button(main, text="Fetch Whois Details", command=runWhois)
whoisButton.place(x=50,y=200)
whoisButton.config(font=font1)

graphButton = Button(main, text="Original & VPN IP Graph", command=graph)
graphButton.place(x=50,y=250)
graphButton.config(font=font1)

l1 = Label(main, text='Enter IP Address')
l1.config(font=font1)
l1.place(x=50,y=300)

tf1 = Entry(main,width=30)
tf1.config(font=font1)
tf1.place(x=50,y=350)

predictButton = Button(main, text="Scan Given IP", command=scanSingleIP)
predictButton.place(x=50,y=400)
predictButton.config(font=font1)

closeButton = Button(main, text="Exit", command=close)
closeButton.place(x=50,y=450)
closeButton.config(font=font1)


font1 = ('times', 12, 'bold')
text=Text(main,height=25,width=100)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=400,y=150)
text.config(font=font1)


main.config(bg='LightSteelBlue1')
main.mainloop()
