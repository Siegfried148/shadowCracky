#!/usr/bin/python
# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
#Usage: ./shadowCracky.py -d dictionary.txt -s shadow.txt -o prueba -v 1 -t 100
#https://github.com/Siegfried148/shadowCracky

from crypt import crypt
from os.path import isfile
from math import ceil
from threading import Thread
import sys
import optparse
results = []
cracked = False


#Se hereda y sobreescribe la clase myThread
class myThread(Thread):
	def __init__(self, user, salt, hash, passwords):
		Thread.__init__(self)
		self.user = user
		self.passwords = passwords
		self.salt = salt
		self.hash = hash

	#Itera sobre todas las contraseñas que le tocan, manda a llamar a la función que crackea
	def run(self):
		for word in self.passwords:
			if cracked: break
			w = word.strip('\n')
			if verbose in ['2']: print '\tThread %s: (%s -> %s)?'  % (self.id, self.user, w)
			crack(self.user, self.salt, self.hash, w)


#Si hay un error, avisa y termina ejecución
def printError(msg):
	sys.stderr.write('Error:\t%s\n' % msg)
	sys.exit(1)


#Escribe el reporte sólo si se indica el nombre del archivo
def writeReport(file):
	if file is not None:
		with open(file, 'w') as f:
			for r in results:
				f.write('%s\t--\t%s\n' % (r[0],r[1]))


#Regresa una lista de los ususarios con contraseña del archivo shadow
def parseShadow(shadow, verbose):
	registers = []
	with open(shadow,'r') as f:
		for line in f.readlines():
			l = line.split(':')
			if l[1] != '!' and l[1] != '*': registers.append(l[:2])
	if verbose in ['1','2']:
		print '\tUSERS\tHASHES'
		for r in registers:
			print '\t%s\t%s' % (r[0],r[1])
	return registers


#Regresa una lista de todas las palabras para probar
def parseDictionary(dict, verbose):
	passwords = []
	with open(dict,'r') as f:
		for line in f.readlines():
			passwords.append(line)
	if verbose in ['1','2']:
		print '\n\tUSING %s PASSWORDS' % len(passwords)
	return passwords


#Itera sobre los registros de shadow
#Genera los hilos necesarios y manda a llamar la ejecución sobre cada hilo
def crackShadow(shadow_regs, chunked_dict):
	for r in shadow_regs:
		threads = []
		for t in range(len(chunked_dict)): #Sobre cada palabra de su pedazo de diccionario
			passwd = r[1].split('$')
			salt = '$%s$%s' % (passwd[1],passwd[2])
			thread = myThread(r[0], salt, r[1], chunked_dict[t]) #Hace un hilo nuevo
#			thread = Thread(target=crack, args=(r[0], salt, r[1], chunked_dict[t])) #Hace un hilo nuevo
			thread.start()
			threads.append(thread)
		for t in threads: #Espera a que terminen los demás hilos
			t.join()
		global cracked
		cracked = False


#Obtiene el hash y compara, agrega resultados exitosos y avisa que ya lo encontró
def crack(user, salt, hash, password):
	global cracked
#	for word in passwords:
#	if cracked: break
#	w = word.strip('\n')
#	if verbose in ['2']: print '\t\t(%s -> %s)?'  % (user, w)
	if crypt(password, salt) == hash:
		print "\t¡¡GREAT!!\tUSER: %s\tPASS: %s" % (user, password)
		results.append([user, password])
		cracked = True


#Agrega las opciones que acepta el programa y las valida
def addOptions():
	parser = optparse.OptionParser()
	parser.add_option('-d','--dictionary', dest='dict', default=None, help='Password dictionary used for cracking')
	parser.add_option('-s', '--shadowFile', dest='shadow', default=None, help='Shadow file to crack')
	parser.add_option('-o', '--output', dest='out', default=None, help='File where results are written')
	parser.add_option('-t', '--threads', dest='thread', default=50, help='Number of threads to be used per shadow register')
	parser.add_option('-v', '--verbose', dest='verbose', default='0', help='Show the progress (0, 1 ,2)')
	opts, args = parser.parse_args()
	if opts.dict is None: printError('Specify a dictionary file')
	if opts.shadow is None: printError('Specify a shadow file')
	if opts.thread < 1: printError('Write a valid thread number')
	if opts.verbose not in ('0','1','2'): printError('Verbose mode can ony be 0, 1 or 2')
	if not isfile(opts.shadow): printError('Shadow file does not exist')
	if not isfile(opts.dict): printError('Dictionary file does not exist')
	return opts.shadow, opts.dict, opts.out, opts.verbose, int(opts.thread)


#Excepciones: SI
#Verbose: SI
#Inicia programa
#parsea los registros y el diccionario
#Separa el diccionario en diccionarios más pequeños para cada hilo
#Llama a la fucnión para crackear
#Genera reporte
if __name__ == '__main__':
	shadow, dict, outF, verbose, threadNum = addOptions()
	if verbose in ['1','2']:
		print 'SHADOW CRACKY v1.0\n'
	shadow_regs = parseShadow(shadow, verbose)
	passwords = parseDictionary(dict, verbose)
	if len(passwords) < threadNum:
		threadNum = len(passwords)	#si no hay tantas contraseñas, no hacer tantos hilos
	n = int(ceil(len(passwords) / float(threadNum)))	#n es el número de elementos que tendrá cada sublista de contraseñas
	chunked_dictionary = [passwords[i:i+n] for i in xrange(0, len(passwords), n)]	 #Separa el diccionario en pedazos para pasarlos a los hilos
	if verbose in ['1','2']:
		print '\tUSING %s THREADS\n' % len(chunked_dictionary)
	try:
		crackShadow(shadow_regs, chunked_dictionary)
		writeReport(outF)
	except(KeyboardInterrupt, SystemExit):
		printError('Keyboard interrupted')
	except Exception as e:
		printError(e)
