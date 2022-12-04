"""

Author: Non pack Smoothing


"""
import time 
import openmesh as om
from phe import paillier
import numpy as np
mesh = om.read_trimesh("example.stl")
if mesh:
        print ("everything worked")
else:
        print ("something went wrong")

#original packet
mainpack = []
valencenumber = []
valencehighest = 0


#generate the two keys
public_key, private_key = paillier.generate_paillier_keypair()

#start time of execution
start_time = time.time()

#count the highest valence and store then in a list 
for vh in mesh.vertices():
    valencount = 0
    #print(vh.idx())
    point = mesh.point(vh)
    for i in point:
        mainpack.append(i)  
    #goes thru the neighbors
    for vhl in mesh.vv(vh):
        valencount+=1
    valencenumber.append(valencount)
    valencenumber.append(valencount)
    valencenumber.append(valencount)


    if(valencehighest < valencount):
        valencehighest = valencount
    #print "~~~~~~~~~~~~~~~~~~~~~~~~~~"

#creat a list of n list based on the highest valence
sidepacks = [[] for x in range(valencehighest)]
#print(valencehighest)
#print(len(sidepacks))


#separate each neighbors into packets
n =0
for vh in mesh.vertices():
    #print("n is ", n)

    counter =0
    for vhl in mesh.vv(vh):  
        point_packs = mesh.point(vhl)
        for l in point_packs:
            sidepacks[counter].append(l)
        #print(counter)
        counter+=1
        #print("counter is ", counter)
    if(valencenumber[n] < valencehighest):
        difference = valencehighest - valencenumber[n]
        #print("difference is" , difference)
        restofnum = valencenumber[n]
        #print(restofnum)
        for i in range(restofnum,valencehighest):
            #print("printing i" , i)
            sidepacks[i].append(0.0)
            sidepacks[i].append(0.0)
            sidepacks[i].append(0.0)
            #print(i)
    n+=3
    #print(n, end = " ")


"""
print(len(valencenumber))
for n in range(len(sidepacks)):
    print(len(sidepacks[n]))
print(len(mainpack))
print(valencenumber)
"""

##
##                  ENCRYPTION
##
##



#print(mainpack)
#initialize n numbers of lists
encrypted_number_list = [[] for x in range(valencehighest)]
encrypted_number_mainpack = []
sum_packet_list =[]


print("Encrypting main packet first....")
### encrypt the main packet
for i in range(len(mainpack)):
    #print(i)
    encrypted_number = public_key.encrypt(mainpack[i])
    encrypted_number_mainpack.append(encrypted_number)
print("Done")


print("Encrypting neighbors...")
###encrypt the neigbors

for i in range(len(sidepacks)):
    print("Encrypting packet number ", i)
    for x in range(len(sidepacks[i])):
        encrypted_number = public_key.encrypt(sidepacks[i][x])
        encrypted_number_list[i].append(encrypted_number)
        #print(private_key.decrypt(encrypted_number))
        #print(x)
print("Done...")



##
##                  Operations
##
##            THIS SHOULD BE DONE OUTSIDE


print("Calculating the sum of the neighbors")
#Find the Vcenter first by adding all the numbers and divide by valencenumber
#sum would already average the numbers up
for i in range(len(encrypted_number_list[0])):
    sum = 0
    for l in range(1,len(encrypted_number_list)):
        encrypted_number_list[0][i] += encrypted_number_list[l][i]
    sum = encrypted_number_list[0][i]
    #print(private_key.decrypt(sum))
    #print(valencenumber[i])
    sum = sum  / valencenumber[i]                  
    sum_packet_list.append(sum)

#subtract the two and divide my the valencecount
for l in range(len(encrypted_number_mainpack)):
    sum_packet_list[l] = sum_packet_list[l] - encrypted_number_mainpack[l]
    sum_packet_list[l] = sum_packet_list[l] * .55

#add by Vi
realpacket = []
for l in range(len(encrypted_number_mainpack)):
    lastmod = encrypted_number_mainpack[l] + sum_packet_list[l]
    realpacket.append(lastmod)

##
##                  DECRYPTION
##
##


decrypted_packs = []
for left in range(len(realpacket)):
    decr = private_key.decrypt(realpacket[left])
    decrypted_packs.append(decr)

#print(decrypted_packs)

for vh in mesh.vertices():
    cog = []
    for x in range(1,4):
        l = decrypted_packs.pop(0)
        cog.append(l)
    mesh.set_point(vh, cog)

print("--- %s seconds ---" % (time.time() - start_time))
#write into an output file
om.write_mesh('Pailler_example.stl', mesh)

#print the time to the screen:
