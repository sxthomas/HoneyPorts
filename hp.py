#!/user/bin/python

#Version 0.5 by Stephen Thomas - @sthomas0x90 - LegalButFrownedUpon.com
#Version 0.4 by Paul Asadoorian of PaulDotCom/Black Hills Information Security with contributions: Benjamin Donnelly
#
#New features in version 0.5
#-Multithreaded
#-Runs on multiple ports
#-Set firewall rules to be removed after X minutes
#-Config file
#-Custom port messages
#-Whitelist
#-Auto-whitelist of local IPs
#-Output logging
#-Interactive command mode
#-List and Flush Firewall rules while running
#

import sys
import getopt
import threading
import time
import socket
import platform
import os
import ConfigParser
import subprocess
import platform
import ast
import io
import Queue

#Global variables
#Get running operating system.
currentPlatform=platform.system()
outputLog = ''
whitelist = []
threadStatusQ = Queue.Queue()
messageQ = Queue.Queue()

def main():
	#Setup variables
	global outputLog
	clconfigLocation = False
	cloutputLog = False
	verbose = False
	expireSwitch = False
	version = '0.5'
	failedPortList = []
	
	argLen=len(sys.argv)
	threadList=[]
	command = ''
	
	#Exit if operating system is not supported.
	if currentPlatform != 'Windows' and currentPlatform != 'Linux' and currentPlatform != 'Darwin':
		print 'Your operating system was detected as ' + currentPlatform + ' which is not supported by HoneyPorts.  We recommend checking out the Active Defense Harbinger Distribution.'
		
		sys.exit(1)
	#Make sure running as root if on Linux and Mac
	if currentPlatform != 'Windows':
		if not os.geteuid()==0:
			print '\nHoneyPorts needs to be run as root.  Try using sudo.\n'
			sys.exit(1)
		
	#Get all local ips as well as 127.0.0.1 and create add them to the whitelist
	#For Windows, it will grab all local IPs including VM IPs.
	
	if currentPlatform == 'Windows':
		myIps = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:2])
		for wl_ips in myIps:
			whitelist.append(wl_ips)
	else:
		whitelist.append([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
	
	whitelist.append('127.0.0.1')

	#Get command line args
	if (argLen < 2):
		usage()
		return (0)
	try:
		options, args = getopt.getopt(sys.argv[1:], 'hvp:c:o:e:')
	except getopt.GetoptError as err:
		print str(err)
		sys.exit(2)
		
	for option, value in options:
		if option == '-p':
			inputport = value
		elif option == '-v':
			verbose = True
		elif option == '-o':
			outputLog = value
			cloutputLog = True
		elif option == '-c':
			configLocation = value
			clconfigLocation = True
		elif option == '-e':
			expireSwitch = True
			expireTime = value
		elif option == '-h':
			usage()
			sys.exit(2)
		else:
			print 'command not recognized!!!'
			sys.exit(2)
	#Check to see if there is a hpconfig.conf file in the cwd and if the -c options was used.
	#If no config flie is found the program will exit.
	if (os.path.isfile(os.path.join(os.getcwd(), 'hpconfig.conf'))== False) and (clconfigLocation == False):
		print 'Config file was not found in current working directory and -c option was not used.  HoneyPorts needs its config file to operate.'
		sys.exit(2)
	#Read in args from the config file
	config = ConfigParser.RawConfigParser()
	if clconfigLocation == False:
		configLocation = os.path.join(os.getcwd(), 'hpconfig.conf')	
	
	config.read(configLocation)
	if cloutputLog == False:
		if currentPlatform == 'Linux':
			try:
				outputLog=config.get('logs','outputLoglin')
			except:
				outputLog=''
		elif currentPlatform == 'Windows':
			try:
				outputLog=config.get('logs','outputLogwin')
			except:
				outputLog=''
		elif currentPlatform == 'Darwin':
			try:
				outputLog=config.get('logs','outputLogmac')
			except:
				outputLog=''
	
		if outputLog == '':
			outputLog = os.path.join(os.getcwd(), 'hplog.txt')
		
		
	#Read custom banners from the config file
	global bannerList
	bannerList = ast.literal_eval(config.get('banners', 'banners'))

	#Add the IPs from the config file into the whitelist
	wlFromFile = config.get('whitelist','whitelist').split(',')
	for wlItem in wlFromFile:
		whitelist.append(wlItem)
	
	#Print verbose information
	if verbose:
		print 'HoneyPorts Version ' + str(version)
		print 'Whitelist:', 
		for ips in whitelist:
			print ips,
		print '\r'
		print 'Output Log File:', outputLog
		print 'Config File:', configLocation
		if expireSwitch == True:
			print 'Firewall rules set to expire every ' + expireTime + ' minutes'
	
	#Validate ports
	portList = inputport.split(',')
	for ports in portList:
		if int(ports) > 65535 or int(ports) < 1:
			print 'Port must be between 1 and 65535'
			sys.exit(2)
		
	#Validate firewall timer value
	if expireSwitch == True:
		try:
			expireTime = int(expireTime)
		except:
			print 'Please enter an integer for the firewall expiration time.'
			sys.exit(2)
		if expireTime > 9999 or expireTime < 1:
			print 'Please enter a time value between 1 and 9,999 minutes.'
			sys.exit(2) 

	#Create threads for listening - one per port
	counter = 0
	while (counter < (len(portList))):
		t=threading.Thread(target=listenFunc, args=(portList[counter],)) 
		t.setDaemon( True )
		t.start()
		threadList.append(t)
		counter += 1
	
	#Create the thread for the firewall rule removal timer if needed
	if expireSwitch == True:
		t=threading.Thread(target=expireFunc, args=(expireTime,)) 
		t.setDaemon( True )
		t.start()
	
	#Create the thread for printing messages to the log file from the message queue
	t=threading.Thread(target=printMessageFunc) 
	t.setDaemon( True )
	t.start()
	
	#Wait for status queue to fill up from the listening threads
	while threadStatusQ.qsize() < len(portList):
		pass
		
	#Clear out the queue and add any failed ports to the failed port list	
	while threadStatusQ.empty() == False:
		threadStatus=threadStatusQ.get()
		if threadStatus[1] == 'fail':
			print 'Unable to listen on port ' + str(threadStatus[0]) + '. Is another service running on this port?'
			failedPortList.append(str(threadStatus[0]))

	#Take the failed ports out of the port list for printing to screen
	for failedPorts in failedPortList:
		if failedPorts in portList:
			portList.remove(failedPorts)
	
	#Print out listening ports with commas after all pots except the last one
	print 'listening on port(s): ',
	portListLen = len(portList)
	portCount = 1
	for ports in portList:
		if portCount < portListLen:
			print ports + ',',
		else:
			print ports + '',
		portCount += 1
		
	print '\n'
	

	# Command mode
	# For each operating system, wait for runtime commands
	if (currentPlatform == 'Windows'):
		while(command != 'q' and command != 'quit'):
			print '>>',
			command=raw_input('')
			if(command == 'help' or command == 'h'):
				print '  COMMAND LIST:'
				print '  q or quit - exit the program'
				print '  fwlist    - list created firewall rules'
				print '  fwflush   - remove all created firewall rules'
			elif(command =='fwlist'):
				try:
					print 'Firewall Rule List:'
					subprocess.call('netsh advfirewall firewall show rule name=honeyports| findstr RemoteIP', shell=True)
				except:
					print 'Error listing firewall rules'
			elif(command =='fwflush'):
				try:
					print 'Firewall Rules Flushed!'
					subprocess.call('netsh advfirewall reset > nul', shell=True)
				except:
					print 'Error flushing firewall rules'
			elif(command == 'q' or command == 'quit'):
				pass
			else:
				print 'Command not recognized'
				
	elif(currentPlatform == 'Linux'):
		while(command != 'q' and command != 'quit'):
			command=raw_input('')
			if(command == 'help' or command == 'h'):
				print '  COMMAND LIST:'
				print '  q or quit - exit the program'
				print '  fwlist    - list created firewall rules'
				print '  fwflush   - remove all created firewall rules'
				print '\n'
			elif(command == 'fwlist'):
				try:
					print 'Firewall Rule List:'		
					subprocess.call('iptables -nL| grep REJECT', shell=True)
				except:
					print 'Error listing firewall rules'
			elif(command == 'fwflush'):
				try:
					print 'Firewall Rules Flushed!'			
					subprocess.call('iptables -F', shell=True)
				except:
					print 'Error flushing firewall rules'
			elif(command == 'q' or command == 'quit'):
				pass
			else:
				print 'Command not recognized'
				
	elif(currentPlatform == 'Darwin'):
		while(command != 'q' and command != 'quit'):
			command=raw_input('')
			if(command == 'help' or command == 'h'):
				print '  COMMAND LIST:'
				print '  q or quit - exit the program'
				print '  fwlist    - list created firewall rules'
				print '  fwflush   - remove all created firewall rules'
				print '\n'
			elif(command == 'fwlist'):
				try:
					print 'Firewall Rule List:'
					subprocess.call('ipfw list', shell=True)
				except:
					print 'Error listing firewall rules'
			elif(command == 'fwflush'):
				try:
					print 'Firewall Rules Flushed!'		
					subprocess.call('ipfw -q flush', shell=True)
				except:
					print 'Error flushing firewall rules'
			elif(command == 'q' or command == 'quit'):
				pass
			else:
				print 'Command not recognized'
	sys.exit(0)

#Function to create listeners on each port given.  Each thread will go to this function.
def listenFunc(port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		if currentPlatform == 'Linux':
			host = s.getsockname()[0]
		elif platform == 'Darwin':
			host = socket.gethostname()
		elif platform == 'Windows':
			host = ''
		else:
			host = ''
		
		currentPort=int(port)
		s.bind((host, currentPort))
		s.listen(5) 
		
		#Create the tuple of the passed status and add it to the queue
		socStatus=(currentPort, 'pass')
		threadStatusQ.put(socStatus)
		
	except:
		#Create the tuple of the failed status and add it to the queue
		socStatus = (currentPort, 'fail')
		threadStatusQ.put(socStatus)		
		return(0)
	
	#Establish the connection with the attacker
	while True:
		c, addr = s.accept()
		hostname = str(addr[0])
		currentTime = time.strftime('%x %X')
		connectionMessage = (currentTime)+' Connection attempt from '+(hostname)+' on port: '+str((currentPort))
		
		messageQ.put(connectionMessage)
		#Get Banner message from config file
		try:
			outputMsg = bannerList[str(currentPort)]
		except:
			#If no current port message, use default from port 0
			try:
				outputMsg = bannerList[str(0)]
			#Backup message if something fails from config file
			#This is a backup and should never execute if working correctly
			except:
				outputMsg = 'Dont scan me bro!'
		#Send the message
		try:
			c.send(outputMsg)
		except:
			print 'Message was unable to send.'
		#Close the connection
		c.close()
		#Check to see if the attacking IP is in the whitelist
		if hostname in whitelist:
			whitelistMessage = 'Host was whitelisted. No firewall rule created.\n'
			messageQ.put(whitelistMessage)
		#If not in whitelist, goto firewall function to create rule
		else:
			firewall(hostname)	

#Function to create firewall rule for attacking IP		
def firewall(hostname):
	hostname=hostname
	#Check each OS and use subprocess.call to use the built-in firewall to create a rule.
	if currentPlatform == 'Windows':
		#Create firewall rule
		try:
			fw_result=subprocess.call('netsh advfirewall firewall add rule name="honeyports" dir=in remoteip= ' + hostname + ' localport=any protocol=TCP action=block > NUL', shell=True)
			#Save info to log file.
			try:
				fwMessage='A Windows Firewall rule was created.\n'
				messageQ.put(fwMessage)

			except:
				print 'Firewall rule was created but failed to log event'
		#Print error message to file	
		except:
			fwMessage='Error crating Windows Firewall rule.\n'
			messageQ.put(fwMessage)	
        
	elif currentPlatform == 'Linux':
		#Create firewall rule
		try:
			fw_result = subprocess.call( 'iptables -A INPUT -s ' + hostname + ' -j REJECT', shell=True)
			#Save info to log file.
			try:
				fwMessage='A, IPtables Firewall rule was created.\n'
				messageQ.put(fwMessage)

			except:
				print 'Firewall rule was created but failed to log event'
		#Print error message to file
		except:
			fwMessage='Error crating IPTables Firewall rule.\n'
			messageQ.put(fwMessage)

	elif currentPlatform == 'Darwin':
		#Create firewall rule
		try:
			fw_result = subprocess.call('ipfw -q add deny src-ip ' + hostname, shell=True)
			#Save info to log file.
			try:
				fwMessage='An IPFW Firewall rule was created.\n'
				messageQ.put(fwMessage)

			except:
				print 'Firewall rule was created but failed to log event'
		#Print error message to file
		except:
			fwMessage='Error crating IPFW Firewall rule.\n'
			messageQ.put(fwMessage)

#Firewall rule expiriation function
def expireFunc(expireTime):
	#convert argument given to minutes
	waitTime = int(expireTime) * 60
	while True:
		#Wait
		time.sleep(int(waitTime))
		if (currentPlatform == 'Windows'):
			try:
				fwTimeMessage='Firewall rules flushed via timer\n'
				messageQ.put(fwTimeMessage)
				subprocess.call('netsh advfirewall reset > nul', shell=True)
			except:
				print 'Error flushing firewall rules via timer'

		elif(currentPlatform == 'Linux'):
			try:
				fwTimeMessage='Firewall rules flushed via timer\n'
				messageQ.put(fwTimeMessage)			
				subprocess.call('iptables -F', shell=True)
			except:
				print 'Error flushing firewall rules via timer'

		elif(currentPlatform == 'Darwin'):
			try:
				fwTimeMessage='Firewall rules flushed via timer\n'
				messageQ.put(fwTimeMessage)				
				subprocess.call('ipfw -q flush', shell=True)
			except:
				print 'Error flushing firewall rules via timer'

	return(0)
			
#Function to print messages to log file
def printMessageFunc():	
	while True:
		#Check the queue every half second
		time.sleep(0.5)
		if messageQ.empty() == False:
			messageString=messageQ.get()
			writeMessageString = '\n' + messageString
			print messageString
			print '>>',
			sys.stdout.flush()
			#Write the message to file
			try:
				f = open(outputLog, 'a')
				f.write(writeMessageString)
				f.close()
			except:
				print '\n!!Failed to log message!!\n'
		
#Print usage file			
def usage():
	print '\n########## HoneyPorts Usage ##########\n'
	print 'HoneyPorts has two modes for commands; runtime commands and Interactive Mode commands.'
	print ''
	print 'Runtime Commands:'
	print ' -p     Port numbers.  Single port number or comma separated.'
	print ' -v     Verbose mode.  Shows more information about local IPs and whitelist.'
	print ' -o     Output file.  Specify a location for the output file.'
	print ' -c     Config file.  specify a location for the config file.'
	print ' -e     Firewall rules expire.  specify a time in minutes for the firewall rules to be removed.'
	print ' -h     Display usage.'
	print '\n'
	print 'Once the application is running, commands can be issued at any time.'
	print 'Interactive Mode Commands:'
	print ' q or quit    Exit the program'
	print ' h or help    List all Interactive Mode Commands'
	print ' fwlist       List all firewall rules created'
	print ' fwflush      Flush all firewall rules created'
	
if __name__ == "__main__":
    main()
