# Crypto challenges from http://cryptopals.com
# Beware: this code is far from being perfect! But I tried :P
# -------
# For edutainmental purposes only!
# c0rdis, 2015

from string import printable
from collections import Counter
import operator
import itertools


## CUSTOM CLASS FOR CRYPTOPALS	
## SET 1 (http://cryptopals.com/sets/1/)	
class Set1:
	def __init__(self):
		#intentionally left blank
		pass
        
# ----------------------------------------------- #    
#                   utilities                     #
# ----------------------------------------------- #   
	def hex2plain(self,hexstr):
		return hexstr.decode("hex")
	
	def plain2hex(self,hexstr):
		return hexstr.encode("hex")
	
	def plain2base64(self,plain):
		return plain.encode("base64")
        
        # with care to extend/trim a key
        def xor_plain(self,str,xorkey):
		if len(str)-len(xorkey) > 0:
                    ratio = ( len(str)/len(xorkey) ) + 1
                    xorkey += xorkey*ratio
                    xorkey = xorkey[:len(str)]
		elif len(str)-len(xorkey) < 0:
                    xorkey = xorkey[:len(str)]
		return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(str,xorkey))
            
        # find the correct accuracy value for the best XOR key bruteforcing
	def adjust_accuracy(self,str):
                accuracy = 13
                while self.is_english(str,accuracy) is False:
                        print accuracy
                        accuracy -= 1
                return accuracy
            
        # break a string into list of chunks of fixed length
	def list_of_chunks(self,str,chunkLen):
                return [str[i:i+chunkLen] for i in xrange(0, len(str), chunkLen)]
                
	# input: plain text
	# output: list of transposed bytes in hex
	def transpose(self,text,keyLen):
		text = self.plain2hex(text)
                residue = len(text) % (2*keyLen)
                residue_text = ''
		if residue:
			n = len(text)/(2*keyLen)
                        l = len(text)
                        residue_text = text[n*2*keyLen:]
			text = text[:n*2*keyLen]
                text = [self.list_of_chunks(t,2) for t in self.list_of_chunks(text,2*keyLen)]
                residue_text = self.list_of_chunks(residue_text,2)
                result = [None] * len(text[0])
                # construct first part of the transposed text of equal-length blocks
                for t in text:
                    for i in xrange(0,len(t)): 
                            result[i] = result[i]+t[i] if result[i] is not None else t[i]
                # add residues
                for r in residue_text:
                    j = residue_text.index(r)
                    result[j] += r
		return result
            
        def hamming(self,string1,string2):	
		# counting num of ones in a str after xoring each byte
                # hamming('this is a test','wokka wokka!!!') ;-)
		return sum([bin(ord(x)^ord(y)).count('1') for x,y in zip(string1,string2)])
		
	#using hamming distances due to non-uniform distribution
        #this algorithm is a bit more complicated than described (two pairs)
	def find_xor_len(self,text):
		normalized = (self.hamming(text[:2],text[2:4]) + self.hamming(text[4:6],text[6:8])) / (2*2)
		possible_len = ([2],normalized)
		for i in xrange(3,40):
			string1 = text[:i]
			string2 = text[i:2*i]
			string3 = text[2*i:3*i]
			string4 = text[3*i:4*i]
			normalized = (self.hamming(string1,string2) + self.hamming(string1,string3) + self.hamming(string1,string4) 
                                    + self.hamming(string2,string3) + self.hamming(string2,string4) + self.hamming(string3,string4)) / (6*i)
			if normalized < possible_len[1]:
				possible_len = (i,normalized)
                        elif normalized == possible_len[1]:
                                posLen = possible_len[0]
                                posLen.append(i)
				possible_len = (posLen,normalized)
		return possible_len[0]
	
	

# ----------------------------------------------- #    
#                  Solutions                      #
# ----------------------------------------------- # 
        ## Task 1    
        def hex2base64(self,hexstr):
		return self.plain2base64(self.hex2plain(hexstr)).strip()
	
	## Task 2
	def xor_hex(self,hexstr,xorkey):
		hexstr = self.hex2plain(hexstr)
		xorkey = self.hex2plain(xorkey)
		return self.xor_plain(hexstr,xorkey).encode("hex")
	
	## Task 3
        def is_english(self,engtext,accuracy=4):
		# if not contains non-printable chars
		#printset = set(string.printable)
		#if not set(engtext).issubset(printset):
		#	return False	
                
		#ETAOIN SHRDLU :)
		mostused = set([' ','e','t','a','o','i','n','s','h','r','d','l','u'])
		count = Counter(engtext)
		common = count.most_common(accuracy)
		if ( all(cm[0] in mostused for cm in common) ):
		#if ( all(cm[0] in mostused for cm in common) and
		#	any(cm[0] == ' ' for cm in common) ):
			# that one is good for at least several sentences
			# in case of single words omit it
			return True
		return False
	
        ## Task 4
	def find_xor(self,xordStr,xorLen=2,accuracy=13):
		keyLen = 16**xorLen
		# for bigger keyLen theoretically lrange can be used
                while accuracy:
                    key = []
                    for x in xrange(0x01,keyLen):
                            # convert to hex value without 0x
                            xr = '%02X'%x
                            decodedHex = self.xor_hex(xordStr,xr)
                            decodedHex = self.hex2plain(decodedHex)
                            if self.is_english(decodedHex,accuracy):
                                    #return xr, decodedHex
                                    key.append(xr)
                    if key:
                            return key, decodedHex
                    accuracy -= 1
		
	## Task 5	
        # xorkey should be binary!
	def xor_file(self,file,xorkey):
		f = open(file, 'rb')
		contents = f.read()
		hexFile = self.plain2hex(contents)
		return self.xor_hex(hexFile,xorkey) 
                
        ## Task 6
        # Yep, both find_vigenere_key() and decrypt_vigenere() are here
	def find_vigenere_key(self,text,guessedLen):
            possibleKey = []
            blockText = self.transpose(text,guessedLen)
            for b in blockText:
                oneByteKeyLen = 2
                maxAccuracy = 13
                newKey = self.find_xor(b,oneByteKeyLen,maxAccuracy)
                if newKey is None:
                    return []
                possibleKey.append(newKey[0])
            return possibleKey
        
        def decrypt_vigenere(self,base64text):
            text = base64text.decode("base64")
            guessedLen = self.find_xor_len(text)
            # compose a list of all possible keys and make it flat
            possibleKeys = [self.find_vigenere_key(text,gLen) for gLen in guessedLen]
            finalSet = [''.join(combo) for fixedLen in possibleKeys for combo in itertools.product(*fixedLen)]
            # decrypted must be all printable
            for key in finalSet:
                decrypted = self.xor_hex(text.encode("hex"),key).decode('hex')
                if ( all(d in printable for d in decrypted) ):
                    return key,decrypted
            return None,None
        
        
        
        
