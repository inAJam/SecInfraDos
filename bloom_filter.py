# Python 3 program to build Bloom Filter
import math
import mmh3
import random
import csv
import socket
import struct
from bitarray import bitarray

class BloomFilter(object):
    '''
    Class for bloom filter, using murmur3 hash function
    '''
    
    def __init__(self, items_count, fp_prob):
        '''
        items_count: int
            Number of items expected to be stored in bloom filter
        fp_prob: float
            False Positive probability in decimal
        '''

        if not (0 < fp_prob < 1):
            raise ValueError("False Positive Probability rate must be between 0 and 1")
        if not items_count > 0:
            raise ValueError("Items_count must be > 0")
        
        # False possible probability in decimal
        self.fp_prob = fp_prob

        # Size of bit array to use
        self.size = self.get_size(items_count, fp_prob)
        print("Size: ",self.size)

        # number of hash functions to use
        self.hash_count = self.get_hash_count(self.size, items_count)
        print("Hash counts: ",self.hash_count)

        # Bit array of given size
        self.bit_array = bitarray(self.size)
        self.bit_array_fake = bitarray(self.size)

        # initialize all bits as 0
        self.bit_array.setall(0)
        self.bit_array_fake.setall(0)
        self.list = set()
        self.list_fake = set()


    def check(self,item):
        '''
        Check for the presence of an item
        '''
        for i in range(self.hash_count):
            if self.bit_array[mmh3.hash(item,i) % self.size] == False:
                return False
        return True
    
    def check_fake(self,item):
        for i in range(self.hash_count):
            if self.bit_array_fake[mmh3.hash(item,i) % self.size] == False:
                return False
        return True
    
    def add(self,item):
        '''
        Add items to the filter
        '''
        digests = []
        for i in range(self.hash_count):
            digest = mmh3.hash(item,i) % self.size
            digests.append(digest)

            self.bit_array[digest] = True
        self.list.add(item)
    
    def send_copy(self,start,end):
        for i in range(start,end):
            if self.bit_array[i]:
                self.bit_array_fake[i] = True
    
    def read_csv(self,file,n):        
        with open(file, mode='r') as file:
            csv_file = csv.DictReader(file)
            i = 0
            for row in csv_file:
                if row['Protocol'] == 'IPv6':
                    continue
                
                ran_int_ip_src = row['Source'].split('.')
                ran_int_ip_src = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, ran_int_ip_src))
                
                ran_int_ip_dst = row['Destination'].split('.')
                ran_int_ip_dst = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, ran_int_ip_dst))
        
                item = str(ran_int_ip_src)+str(ran_int_ip_dst)+str(row['Protocol'])
                if item in self.list:
                    continue
                print("Source: ",row['Source'], "\nDestination: ", row['Destination'], "\nProtocol: ", row['Protocol'])
                print("\n\nItem: \n",item)
                input()
                self.add(item)
                i+=1
                if i==n:
                    return
    
    def craft_items(self,start,end,src,dest,goal):
        num = 0
        x = 0
        z = 0
        self.send_copy(start, end)
        for s in src:
            ran_ip_src = s.split('.')
            ran_int_ip_src = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, ran_ip_src))
            z+=1
                
            for y in dest:
                ran_ip_dst = y['Destination'].split('.')
                ran_int_ip_dst = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, ran_ip_dst))
            
                ip_proto = y['Protocol']
            
                item = str(ran_int_ip_src)+str(ran_int_ip_dst)+str(ip_proto)
                if self.check_fake(item) and item not in self.list and item not in self.list_fake:
                    num+=1
                    self.list_fake.add(item)
                run = "\rRun: {}\t Source ID: {} \t crafted = {}".format(x,z,num)
                print(run, end=('\r'))
                x+=1
                if num == goal:
                    return
        
    
    '''
    m : int
        size of bit array
    k : int
        Number of hash functions
    n : int
        Number of items to be inserted into the filter
    p : float
        False Positive probability
    '''

    @classmethod
    def get_size(self,n,p):
        '''
        Returns the size of the bit array(m) to be used using the formula:
        m = -(n * lg(p)) / (lg(2)^2)
        '''
        return int(math.ceil((n * abs(math.log(p)))/(math.log(2)**2)))
    
    @classmethod
    def get_hash_count(self,m,n):
        '''
        Returns the Number of Hash functions to be used using the formula:
        k = (m/n) * lg(2)
        '''
        return int((m/n) * math.log(2))