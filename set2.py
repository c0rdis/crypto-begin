# Crypto challenges from http://cryptopals.com
# Beware: this code is far from being perfect! But I tried :P
# -------
# For edutainmental purposes only!
# c0rdis, 2015

#imports...


## CUSTOM CLASS FOR CRYPTOPALS	
## SET 2 (http://cryptopals.com/sets/2/)	
class Set2:
	def __init__(self):
		#intentionally left blank
		pass
            
            
# ----------------------------------------------- #    
#                  Solutions                      #
# ----------------------------------------------- # 
        ## Task 9
        def PKS7(self,hexstring,BLOCK_SIZE):
            residue = (len(hexstring)/2) % BLOCK_SIZE
            residue = BLOCK_SIZE - residue
            padding = str(residue) if residue > 9 else '0'+str(residue)
            return hexstring + residue*padding
