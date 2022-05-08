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



rate = [-1,-2,-3,-4,-5,-6,-7,-8]
field = ['Total items', 'False Positive probability','Time', 'hash count', 'Bitarray Size', 'Crafted items']
items = []
i = int(input("Enter size: "))
goal = i*0.1    
print("No. of insertions : ", (i))
for j in rate:
    print("False Positive probability : ", (2**j))
    y = BloomFilter(i, 2**j)
    y.read_csv('x.csv', i)
    start = time.time()
    y.craft_items(0, y.size, src, dest, goal)
    end = time.time()
    print("Total time : ", (end-start))
    t = end-start
    items.append({'Total items': i, 'False Positive probability': 2**j, 'Time':t, 'hash count': y.hash_count, 'Bitarray Size': y.size, 'Crafted items': goal})

print(items)
with open('fpr_variance.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames = field)
    writer.writerows(items)