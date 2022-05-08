import csv
import struct
import random
import socket

file = 'x.csv'
field = ['Destination', 'd_port', 'Protocol']
fields2 = ['Source']
out = 'target_ipv4.csv'
out2 = 'attacker_ipv4.csv'
port1 = 1
port2 = 65535

n = int(input('Enter size: '))

values = []
ip = set()
check = set()
insert = set()
k = 0
l = 0
with open(file, mode='r') as file:
    csv_file = csv.DictReader(file)
    for row in csv_file:
        k+=1
        if row['Protocol'] == 'IPv6':
            continue
        ran_port_src = random.randint(port1, port2) #49152, 49220
        ran_port_src = format(ran_port_src,'x')
        item = tuple(row['Destination']+row['Protocol'])
        item2 = tuple(row['Source']+row['Protocol'])
        item3 = tuple(row['Source']+row['Destination']+row['Protocol'])
        if item not in check:
            check.add(item)
            ip.add(row['Destination'])
            values.append({'Destination':row['Destination'], 'Protocol':row['Protocol']})
            l+=1
        if item2 not in check:
            check.add(item2)
            ip.add(row['Source'])
            values.append({'Destination':row['Source'], 'Protocol':row['Protocol']})
            l+=1
        insert.add(item3)
        run = "\rDiscovered: {} \t Added = {} \t Elements = {}".format(k,l,len(insert))
        print(run, end=('\r'))
        if len(insert) == n:
            break

print()
print("Inserted :", len(insert))
print("Writing to file the target addresses...")
with open(out, 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames = field)
    writer.writeheader()
    writer.writerows(values)

print("...Done")

items = []
j=0
while j<20000:
    a = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    if a not in ip:
        ip.add(a)
        items.append({'Source':a})
        j+=1

print("Writing to file the Source addresses...")
with open(out2, 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames = fields2)
    writer.writeheader()
    writer.writerows(items)