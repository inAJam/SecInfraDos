from bloom_filter import BloomFilter
import time
import csv

source = 'attacker_ipv4.csv'
destination = 'target_ipv4.csv'
src = []
dest = []

with open(source, mode='r') as file:
    csv_file = csv.DictReader(file)
    for row in csv_file:
        src.append(row['Source'])

with open(destination, mode='r') as file:
    csv_file = csv.DictReader(file)
    for row in csv_file:
        dest.append(row)


goal = 100

p = 2**-5
n = int(input("Enter size: "))
field = ['Attacker access size', 'Time']
items = []
for i in range(10,2,-2):
    print("No. of insertions : ", n)
    print("False Positive probability : ", p)
    y = BloomFilter(n, p)
    y.read_csv('x.csv', int(i*n/10))
    start = time.time()
    y.craft_items(0, y.size,src, dest, goal)
    end = time.time()
    print("Total time : ", (end-start))
    t = end-start
    items.append({'Attacker access size': i, 'Time':t})

print(items)
with open('array_size.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames = field)
    writer.writeheader()
    writer.writerows(items)