#Team 04 UNP Network Monitor (python)
#Christiaan Obbink, Salar Darwish, Ka Yue Sin
#Packet sniffer client used to monitor network traffic
#For Linux (tested in Ubuntu)- Client for packet sniffer
#!/usr/bin/python

import socket, sys               # Import socket module
import MySQLdb
from csv import Sniffer

s = socket.socket()         # Create a socket object
host = '192.168.56.101'     # Get local machine name
port = 12345                # Reserve a port for your service.

while True:     
    print("""
    Please choice your option:
        1. Begin Sniffer
        2. Show historic data
        3. Exit Sniffer
        """)

    ans=raw_input("Enter your option: ")
    if not ans:
            continue
    if ans == "1":
        try:
            s.connect((host, port))
            print ("\n------------------------------------------------------------------"
                   "\n**                                                                **"
                   "\n**               Welcome to the network monitoring                **"
                   "\n** This network monitoring will monitor the following packets:    **"
                   "\n**                 the  ETHERNET packets                          **"
                   "\n**                    the  IP packets                             **"
                   "\n**                    the TCP packets                             **"
                   "\n**                    the UDP packets                             **"
                   "\n**                    the ICMP packets                            **" 
                   "\n--------------------------------------------------------------------")
            
            print ("\n                        "+(s.recv(1024))+"                        \n")
        except:    
            continue
    elif ans == "2":
        while True:
            print ("""
            Historic data
                1. Ethernet packets
                2. Ip packets
                3. TCP packets
                4. UDP packets
                5. ICMP packets   
            """)
            
            dtb = raw_input("Enter your option: ")
            if not dtb:
                break
            
            #---------------------ETH-------------------------------
            if dtb == "1":
                try:
                # Open database connection
                    con = MySQLdb.connect("localhost","root","Welkom01","UNP" )
                
                # prepare a cursor object using cursor() method
                    sql = con.cursor()
                # Prepare SQL query to INSERT a record into the database.
                    sql.execute("SELECT Datetime,Dest_mac,Source_mac,Protocol FROM ETH")
                    con.commit()
                    
                    data = sql.fetchall()
                    
                    for (Datetime,Dest_mac,Source_mac,Protocol) in data:
                        print(Datetime,"Dest_mac:",Dest_mac,"Source_mac:",Source_mac,"Protocol:",Protocol)
                    
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0],e.args[1])
                    sys.exit(1)   
                finally:    
                    if con:    
                        con.close()
                break
            
            #---------------------IP-------------------------------
            elif dtb == "2":
                try:
                # Open database connection
                    con = MySQLdb.connect("localhost","root","Welkom01","UNP" )
                
                # prepare a cursor object using cursor() method
                    sql = con.cursor()
                # Prepare SQL query to INSERT a record into the database.
                    sql.execute("SELECT Datetime,Version,IHL,TTL,Protocol,Source_addr,Dest_addr FROM IP")
                    con.commit()
                    
                    data = sql.fetchall()
                    
                    for (Datetime,Version,IHL,TTL,Protocol,Source_addr,Dest_addr) in data:
                        print("Date:",Datetime,"Version:",Version,"IHL:",IHL,"TTL:",TTL,"Protocol:",Protocol,"Source_addr:",Source_addr,"Dest_addr:",Dest_addr)
                    
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0],e.args[1])
                    sys.exit(1)   
                finally:    
                    if con:    
                        con.close()
                break
            
            #---------------------TCP-------------------------------
            elif dtb == "3":
                try:
                # Open database connection
                    con = MySQLdb.connect("localhost","root","Welkom01","UNP" )
                
                # prepare a cursor object using cursor() method
                    sql = con.cursor()
                # Prepare SQL query to INSERT a record into the database.
                    sql.execute("SELECT Datetime,Source_port,Desc_port,Sequence,Acknowledge,Length FROM TCP")
                    con.commit()
                    
                    data = sql.fetchall()
                    
                    for (Datetime,Source_port,Desc_port,Sequence,Acknowledge,Length) in data:
                        print(Datetime,"Source_port:",Source_port,"Dest_port:",Desc_port,"Sequence:",Sequence,"Acknowledge:",Acknowledge,"Length:",Length)
                    
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0],e.args[1])
                    sys.exit(1)   
                finally:    
                    if con:    
                        con.close()
                break       
            
            #---------------------UDP-------------------------------
            elif dtb == "4":
            
                try:
                # Open database connection
                    con = MySQLdb.connect("192.168.56.101","root","Welkom01","UNP" )
                
                # prepare a cursor object using cursor() method
                    sql = con.cursor()
                # Prepare SQL query to INSERT a record into the database.
                    sql.execute("""SELECT Datetime,Source_port,Dest_port,Length,Checksum FROM UDP""")
                    con.commit()
                    
                    data = sql.fetchall()
                    
                    for (Datetime,Source_port,Dest_port,Length,Checksum) in data:
                        print("Date:",Datetime,"Source_port:",Source_port,"Dest_port:",Dest_port,"Length:",Length,"Checksum:",Checksum)
                    
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0],e.args[1])
                    sys.exit(1)   
                finally:    
                    if con:    
                        con.close()
                break
            
            #---------------------ICMP-------------------------------
            elif dtb == "5":
                try:
                # Open database connection
                    con = MySQLdb.connect("localhost","root","Welkom01","UNP" )
                
                # prepare a cursor object using cursor() method
                    sql = con.cursor()
                # Prepare SQL query to INSERT a record into the database.
                    sql.execute("SELECT Datetime,Type,Code,Checksum FROM ICMP")
                    con.commit()
                    
                    data = sql.fetchall()
                    
                    for (Datetime,Type,Code,Checksum) in data:
                        print(Datetime,"Type:",Type,"Code:",Code,"Checksum:",Checksum)
                    
                except MySQLdb.Error, e:
                    print "Error %d: %s" % (e.args[0],e.args[1])
                    sys.exit(1)   
                finally:    
                    if con:    
                        con.close()
                break                     
              
    elif ans == "3":
        s.close
        print ("""
        Program will exit
        """)
        sys.exit()     
    elif ans != "":
        print ("""
        Wrong option, please select again
        """)         
