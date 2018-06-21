#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import os
import socket
import sys
import getopt
#from scapy_ssl_tls.ssl_tls import *
from scapy.layers.ssl_tls import *
from scapy.all import *
import binascii
import subprocess

from Cryptodome.Hash import *
	
	#This script was written to test FCS_TLSS_EXT.1.1&2
	#These commands can be run directly in Scapy, provided the server variable is set.
	#Set the server with the command server=(<addr>, <port>)

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "/"))

configured_cipher_suites=[TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA384]
configured_certificate_Path="/etc/FCS_TLSC/TestServerRSA.pem"
	
def successful_handshake():
	
	#client_cert= os.path.join(basedir, "etc/FCS_TLSC/clientRSA.der")
	#with open(client_cert, "rb") as f:
		#cert = f.read()
	#certificate = TLSCertificate(data=cert)
	print("Successfull Handshake Test")

    	tls_version = TLSVersion.TLS_1_2

    	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	tls_socket.connect(server)
	tls_socket = TLSSocket(tls_socket, client=True)
    	#tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
        	#basedir, "etc/FCS_TLSC/clientRSA.key"))

    	client_hello = TLSRecord(version=tls_version) / \
                   TLSHandshakes(handshakes=[TLSHandshake() /
                                             TLSClientHello(version=tls_version,
                                                            cipher_suites=configured_cipher_suites,
								extensions=[TLSExtension() /
								TLSExtSignatureAlgorithms()])])
    	tls_socket.sendall(client_hello)
    	server_hello = tls_socket.recvall()
    	server_hello.show()

    	client_key_exchange = TLSRecord(version=tls_version) / \
                          	TLSHandshakes(handshakes=[TLSHandshake() /
                                                    	tls_socket.tls_ctx.get_client_kex_data()])
    
	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()	
	
	p = TLS.from_records([client_key_exchange, client_ccs])
    	tls_socket.sendall(p)

    	tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
							TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
    	server_finished = tls_socket.recvall()
    	server_finished.show()
	
    	tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
    	resp = tls_socket.recvall()
    	print("Got response from server")
    	#resp.show()
    	print(tls_socket.tls_ctx)

def tls_null():
	try:

		print("FCS_TLSS_EXT.1.1 Test 2: TLS_Null_Null Cipher")
		client_cert= os.path.join(basedir, "etc/FCS_TLSC/clientRSA.der")
		with open(client_cert, "rb") as f:
			cert = f.read()
		certificate = TLSCertificate(data=cert)
 

    		tls_version = TLSVersion.TLS_1_2

    		tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    		tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)
    		tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
        		basedir, "etc/FCS_TLSC/clientRSA.key"))

    		client_hello = TLSRecord(version=tls_version) / \
        	           TLSHandshakes(handshakes=[TLSHandshake() /
        	                                     TLSClientHello(version=tls_version,
        	                                                    cipher_suites=[TLSCipherSuite.NULL_WITH_NULL_NULL],
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
    		tls_socket.sendall(client_hello)
    		server_hello = tls_socket.recvall()
    		server_hello.show()

#		print("FCS_TLSS_EXT.1.1 Test 2: No Supported Cipher & Null Cipher")
		#Establish a session
#		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#		sock.connect(server)
#		sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello") with Null cipher
#		client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.NULL_WITH_NULL_NULL])
#		sock.sendall(client_hello)
#		server_hello = sock.recvall()
	except socket.error as e:
		print("FCS_TLSS_EXT.1.1 Test 2 failed -- ", e)

			
def FCS_TLSS_EXT_1_1_Test_3():
	
	#This consists of two connections. The first is with ECDHE, and the context is saved. The second is with RSA, but after the Client Hello, the context is switched to the saved ECDHE context.
	try:
		#Establish a session using ECDHE to get an ECDHE key exchange.
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#Send an ECDHE Client Hello.
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#Send an ECDHE Client Key Exchange.
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#Save the ECDHE Context for reuse.
		#ecdhectx = sock.tls_ctx
		#Send the KEX and CCS packets to make sure they are properly formed
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#Send the Client Finished.
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
	
		#Establish a session using RSA.
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#Send an RSA Client Hello.
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#Switch the context to the saved ECDHE context and send the key exchange. It will appear as a malformed packet because Wireshark expects the connection to stay RSA. Compare the packet lengths to see that the key exchange is similar to an ECDHE one, not an RSA one.
		#sock.tls_ctx = ecdhectx
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
    		
		tls_version = TLSVersion.TLS_1_2

    		tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   		tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)

    		client_hello = TLSRecord(version=tls_version) / \
                	   TLSHandshakes(handshakes=[TLSHandshake() /
                	                             TLSClientHello(version=tls_version,
                	                                            cipher_suites=configured_cipher_suites,
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
	    	tls_socket.sendall(client_hello)
    		server_hello = tls_socket.recvall()
    		server_hello.show()

		tls_socket.tls_ctx.negotiated.key_exchange = TLSKexNames.RSA
		
    		client_key_exchange = TLSRecord(version=tls_version) / \
        	                  	TLSHandshakes(handshakes=[TLSHandshake() /
        	                                            	tls_socket.tls_ctx.get_client_kex_data()])
		client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()

		p = TLS.from_records([client_key_exchange, client_ccs])
    		tls_socket.sendall(p)

		#tls_socket.tls_ctx.negotiated.key_exchange = TLSKexNames.RSA
    		#client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
    		tls_socket.sendall(client_ccs)
    		tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
								TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
    		server_finished = tls_socket.recvall()
    		server_finished.show()
	
	    	tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
#    	resp = tls_socket.recvall()
    		print("Got response from server")
    	#resp.show()
    		print(tls_socket.tls_ctx)
		
	except socket.error as e:
		print("FCS_TLSS_EXT.1.1 Test 3 failed -- ", e)
	
def FCS_TLSS_EXT_1_1_Test_4a():	

		print("FCS_TLSS_EXT.1.1 Test 4a: Nonce change")
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#print("Sending Client Key Exchange")
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#Nonce Change
		#print("Original Nonce: " + binascii.b2a_hex(sock.tls_ctx.crypto.session.randombytes.client))
		#print("Changing last byte of nonce from " + binascii.b2a_hex(sock.tls_ctx.crypto.session.randombytes.client[-1]) + "' to '7a'")
		#sock.tls_ctx.crypto.session.randombytes.client = sock.tls_ctx.crypto.session.randombytes.client[0:-1]+'z'
		#print("Altered Nonce: " + binascii.b2a_hex(sock.tls_ctx.crypto.session.randombytes.client))
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
		#Final Response
		#server_finished.show()

	    	tls_version = TLSVersion.TLS_1_2
	
	    	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    	tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)

	    	client_hello = TLSRecord(version=tls_version) / \
	                   TLSHandshakes(handshakes=[TLSHandshake() /
	                                             TLSClientHello(version=tls_version,
	                                                            cipher_suites=configured_cipher_suites,
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
	    	tls_socket.sendall(client_hello)
	    	server_hello = tls_socket.recvall()
	    	server_hello.show()
	
	    	client_key_exchange = TLSRecord(version=tls_version) / \
	                          	TLSHandshakes(handshakes=[TLSHandshake() /
	                                                    	tls_socket.tls_ctx.get_client_kex_data()])
		#Nonce Change
		print("Original Nonce: " + binascii.b2a_hex(tls_socket.tls_ctx.client_ctx.random))
		print("Changing last byte of nonce from " + binascii.b2a_hex(tls_socket.tls_ctx.client_ctx.random[-1]) + "' to '7a'")
		tls_socket.tls_ctx.client_ctx.random = tls_socket.tls_ctx.client_ctx.random[0:-1]+'z'
		print("Altered Nonce: " + binascii.b2a_hex(tls_socket.tls_ctx.client_ctx.random))
	    	p = TLS.from_records([client_key_exchange])
	    	tls_socket.sendall(p)
	
	    # sig = sig[:128] + chr(ord(sig[128]) ^ 0xff) + sig[129:]
	    	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
	    	tls_socket.sendall(client_ccs)
	    	tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
								TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
	    	server_finished = tls_socket.recvall()
	    	server_finished.show()
		
	    	#tls_socket.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
	    	#resp = tls_socket.recvall()
	    	print("Got response from server")
	    	#resp.show()
	    	print(tls_socket.tls_ctx)
			
def FCS_TLSS_EXT_1_1_Test_4b():
	try:
		print("FCS_TLSS_EXT_1_1_Test_4b: Modify signature block")
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#print("Sending Client Key Exchange")
		#The signature block is altered by changing the context to a different cipher. Wireshark doesn't pick up on it because it can't read inside the encrypted signature block.
		#print("Changing signature block by switching from RSA_WITH_AES_128_CBC_SHA to an unsupported cipher (TLS_ECDH_ECDSA_WITH_RC4_128_SHA). This will not be detected in wireshark because the signature block is encrypted.")
		#sock.tls_ctx.params.handshake.server.cipher_suite=48
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
		#Final Response
		#server_finished.show()

    		tls_version = TLSVersion.TLS_1_2

	    	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    	tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)

	    	client_hello = TLSRecord(version=tls_version) / \
	                   TLSHandshakes(handshakes=[TLSHandshake() /
	                                             TLSClientHello(version=tls_version,
	                                                            cipher_suites=configured_cipher_suites,
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
	    	tls_socket.sendall(client_hello)
	    	server_hello = tls_socket.recvall()
	    	server_hello.show()

		#The signature block is altered by changing the context to a different cipher. Wireshark doesn't pick up on it because it can't read inside the encrypted signature block.
		#print("Changing signature block by switching from RSA_WITH_AES_128_CBC_SHA to an unsupported cipher (TLS_ECDH_ECDSA_WITH_RC4_128_SHA). This will not be detected in wireshark because the signature block is encrypted.")
		tls_socket.tls_ctx.negotiated.ciphersuite=TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA
	    	client_key_exchange = TLSRecord(version=tls_version) / \
	                          	TLSHandshakes(handshakes=[TLSHandshake() /
	                                                    	tls_socket.tls_ctx.get_client_kex_data()])
	    	p = TLS.from_records([client_key_exchange])
	    	tls_socket.sendall(p)
	
	    	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
	    	tls_socket.sendall(client_ccs)
	    	tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
								TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
	    	server_finished = tls_socket.recvall()
	    	server_finished.show()
		
	    	#tls_socket.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
	    	#resp = tls_socket.recvall()
	    	print("Got response from server")
	    	#resp.show()
	    	print(tls_socket.tls_ctx)
	except socket.error as e:
		print("FCS_TLSS_EXT_1_1_Test_4b failed -- ", e)	

def FCS_TLSS_EXT_1_1_Test_4c():
	try:
		print("FCS_TLSS_EXT.1.1 Test 4c: Alter Client Finish packet")
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#print("Sending Client Key Exchange")
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
    		
		tls_version = TLSVersion.TLS_1_2

	    	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    	tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)
	
	    	client_hello = TLSRecord(version=tls_version) / \
	                   TLSHandshakes(handshakes=[TLSHandshake() /
	                                             TLSClientHello(version=tls_version,
	                                                            cipher_suites=configured_cipher_suites,
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
	    	tls_socket.sendall(client_hello)
	    	server_hello = tls_socket.recvall()
	    	server_hello.show()
	
	    	client_key_exchange = TLSRecord(version=tls_version) / \
	                          	TLSHandshakes(handshakes=[TLSHandshake() /
	                                                    	tls_socket.tls_ctx.get_client_kex_data()])
	    	p = TLS.from_records([client_key_exchange])
	    	tls_socket.sendall(p)
	
	    #sig = sig[:128] + chr(ord(sig[128]) ^ 0xff) + sig[129:]
	    	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
	    	tls_socket.sendall(client_ccs)
		finished=TLSHandshakes(handshakes=[TLSHandshake() /
							TLSFinished(data=tls_socket.tls_ctx.get_verify_data())])
		print(finished)
		tr=to_raw(finished,tls_socket.tls_ctx)
#		tr=to_raw(TLSFinished(),tls_socket.tls_ctx)
		print("Last byte of client finish is: " + binascii.b2a_hex(tr[Raw].load[-1]))
		print("Altering last byte of Client Finish from '" + binascii.b2a_hex(tr[Raw].load[-1]) + "' to '7a'")
		tr[Raw].load = tr[Raw].load[0:-1]+'z'
		print("Last byte of client finish is: " + binascii.b2a_hex(tr[Raw].load[-1]))
		tls_socket._s.sendall(str(tr))
		server_finished = tls_socket.recvall()
		#Final Response
		#server_finished.show()
	except socket.error as e:
		print("FCS_TLSS_EXT.1.1 Test 4c&e failed -- ", e)

def FCS_TLSS_EXT_1_1_Test_4d():
	#try:
		print("FCS_TLSS_EXT.1.1 Test 4d: Generating a Fatal Alert, Try a new connection using the session ID of the dead session.")
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#Saving the session ID for the next Client Hello
		#oldsessid=server_hello[TLSServerHello].session_id
		#print("Sending a Client Key Exchange without a Change Cipher Spec, followed by a Finish to generate a Fatal Alert")
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#sock.sendall(TLS.from_records([client_key_exchange]))
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
		#Part II: Sending a Client Hello with the old session ID
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1, cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA], session_id=oldsessid)
		#sock.sendall(client_hello)
		#server_hello = sock.recvall()
		#print("Sending Client Key Exchange")
		#client_key_exchange = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		#sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
		#sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
		#server_finished = sock.recvall()
		#Final Response
		#server_finished.show()
		
		#TLSHandshakes(handshakes=[TLSHandshake() / tls_socket.tls_ctx.get_client_kex_data()])
		
		tls_version = TLSVersion.TLS_1_2
		
		#Establish a session
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect(server)
		sock = TLSSocket(sock, client=True)
		print("Sending Client Hello")
		client_hello = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / TLSClientHello(version=tls_version,cipher_suites=configured_cipher_suites, extensions=[TLSExtension() / TLSExtSignatureAlgorithms()])])
		sock.sendall(client_hello)
		server_hello = sock.recvall()
		#Saving the session ID for the next Client Hello
		print("The server_hello value is:")
		server_hello.show()
		oldsessid=server_hello[TLSServerHello].session_id
		print("Sending a Client Key Exchange without a Change Cipher Spec, followed by a Finish to generate a Fatal Alert")
		client_key_exchange = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / sock.tls_ctx.get_client_kex_data()])
		sock.sendall(TLS.from_records([client_key_exchange]))
		sock.sendall(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=sock.tls_ctx.get_verify_data())]))
		server_finished = sock.recvall()
		#Part II: Sending a Client Hello with the old session ID
		#Establish a session
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect(server)
		sock = TLSSocket(sock, client=True)
		print("Sending Client Hello")
		client_hello = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / TLSClientHello(version=tls_version, cipher_suites=configured_cipher_suites, session_id=oldsessid)])
		sock.sendall(client_hello)
		server_hello = sock.recvall()
		print("Sending Client Key Exchange")
		client_key_exchange = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / sock.tls_ctx.get_client_kex_data()])
		client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
		sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		print("Sending Client Finished")
		sock.sendall(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=sock.tls_ctx.get_verify_data())]))
		server_finished = sock.recvall()
		#Final Response
		server_finished.show()
 

		# tls_version = TLSVersion.TLS_1_2

		# tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# tls_socket.connect(server)
		# tls_socket = TLSSocket(tls_socket, client=True)

		# client_hello = TLSRecord(version=tls_version) / \
				   # TLSHandshakes(handshakes=[TLSHandshake() /
											 # TLSClientHello(version=tls_version,
															# cipher_suites=configured_cipher_suites,
									# extensions=[TLSExtension() /
									# TLSExtSignatureAlgorithms()])])
		# tls_socket.sendall(client_hello)
		# server_hello = tls_socket.recvall()
		# #server_hello.show()
		
		# print("tls_socket.tls_ctx")
		# print(tls_socket.tls_ctx)


		# oldsessid=server_hello[TLSServerHello].session_id
		# client_key_exchange = TLSRecord(version=tls_version) / \
							# TLSHandshakes(handshakes=[TLSHandshake() /
														# tls_socket.tls_ctx.get_client_kex_data()])
		# p = TLS.from_records([client_key_exchange])
		# tls_socket.sendall(p)

	    # # sig = sig[:128] + chr(ord(sig[128]) ^ 0xff) + sig[129:]
# #		client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec() 
	    	# tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
								# TLSFinished()]))
# #		client_cert_verify = TLSRecord(version=tls_version) / \
# #       	                 	TLSHandshakes(handshakes=[TLSHandshake() /
# #       	                                           	TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
# #        	                                                	                sig=sig)])
		# #tls_socket.sendall( to_raw(TLSFinished(), tls_socket.tls_ctx))
	    	# #server_finished = tls_socket.recvall()

		# print("tls_socket.tls_ctx after ccs")
                # print(tls_socket.tls_ctx)
	
	    	# tls_version = TLSVersion.TLS_1_2
	
	    	# tls_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    	# tls_socket2.connect(server)
		# tls_socket2 = TLSSocket(tls_socket2, client=True)
		# # session_id=oldsessid
	    	# client_hello2 = TLSRecord(version=tls_version) / \
	                   # TLSHandshakes(handshakes=[TLSHandshake() /
	                                             # TLSClientHello(version=tls_version,
	                                                            # cipher_suites=configured_cipher_suites, 
									# session_id=oldsessid)])
	    	# tls_socket2.sendall(client_hello2)
	    	# server_hello2 = tls_socket2.recvall()
	    	# #server_hello2.show()
	
		# ## Allen Added	
		# #tls_socket2.tls_ctx.negotiated.key_exchange = TLSKexNames.ECDHE

		# print("tls_socket2.tls_ctx")
		# print(tls_socket2.tls_ctx)
		

	    	# #client_key_exchange2 = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / tls_socket2.tls_ctx.get_client_kex_data()])
	    	# client_key_exchange2 = TLSRecord(version=tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / tls_socket2.tls_ctx.get_client_kex_data()])	
		# p = TLS.from_records([client_key_exchange2])
	    	# tls_socket2.sendall(p)

	    	# client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
	    	# tls_socket2.sendall(client_ccs)
	    	# tls_socket2.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
								# TLSFinished(data=tls_socket2.tls_ctx.get_verify_data())]))
	    	# server_finished = tls_socket2.recvall()
	    	# server_finished.show()
	#except socket.error as e:
	#	print("FCS_TLSS_EXT.1.1 Test 4d failed -- ", e)
		
def FCS_TLSS_EXT_1_1_Test_4e():
	try:
		print("FCS_TLSS_EXT.1.1 Test 4e: Send a garbled packet")
		#Establish a session
		#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#sock.connect(server)
		#sock = TLSSocket(sock, client=True)
		#print("Sending Client Hello")
		#client_hello = TLSRecord(version=TLSVersion.TLS_1_1) / TLSHandshake() / TLSClientHello(version=TLSVersion.TLS_1_1,cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
		#server_hello = sock.recvall()
		#client_ccs = TLSRecord(version=TLSVersion.TLS_1_1) / TLSChangeCipherSpec()
		##sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
		#print("Sending Client Finished")
		#finish=to_raw(TLSFinished(),sock.tls_ctx)
		#The next lines alter and send a garbled packet followed by a good finish packet.
		#altered = to_raw(TLSFinished(),sock.tls_ctx)
		#altered[Raw] = "garbled packet"
		#sock.sendall(altered)

		#sock.sendall(finish)
		#server_finished = sock.recvall()
		#Final Response
		#server_finished.show()
 

    		tls_version = TLSVersion.TLS_1_2

    		tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    		tls_socket.connect(server)
		tls_socket = TLSSocket(tls_socket, client=True)
    		client_hello = TLSRecord(version=tls_version) / \
        	           TLSHandshakes(handshakes=[TLSHandshake() /
        	                                     TLSClientHello(version=tls_version,
        	                                                    cipher_suites=configured_cipher_suites,
									extensions=[TLSExtension() /
									TLSExtSignatureAlgorithms()])])
    		tls_socket.sendall(client_hello)
    		server_hello = tls_socket.recvall()
    		server_hello.show()

    		client_key_exchange = TLSRecord(version=tls_version) / \
        	                  	TLSHandshakes(handshakes=[TLSHandshake() /
        	                                            	tls_socket.tls_ctx.get_client_kex_data()])
		
		client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()

    		p = TLS.from_records([client_key_exchange, client_ccs])
    		tls_socket.sendall(p)

		#tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))

		server_finished = tls_socket.recvall()

    		tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
                                                    	tls_socket.tls_ctx.get_client_kex_data()]))
		
		tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))

		server_finished = tls_socket.recvall()
    		server_finished.show()
	except socket.error as e:
		print("FCS_TLSS_EXT.1.1 Test 4e failed -- ", e)
		
def FCS_TLSS_EXT_2_4_6():
	client_cert= os.path.join(basedir, configured_certificate_Path)
	with open(client_cert, "rb") as f:
		cert = f.read()
	
	certificate = TLSCertificate(data=cert)
	
	tls_version = TLSVersion.TLS_1_2

	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tls_socket.connect(server)
	tls_socket = TLSSocket(tls_socket, client=True)
	tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
		basedir, "etc/FCS_TLSC/TestServerRSA.key"))
				
	client_hello = TLSRecord(version=tls_version) / \
			   TLSHandshakes(handshakes=[TLSHandshake() /
										 TLSClientHello(version=tls_version,
														cipher_suites=configured_cipher_suites,
							extensions=[TLSExtension() /
							TLSExtSignatureAlgorithms()])])
	tls_socket.sendall(client_hello)
	server_hello = tls_socket.recvall()
	#server_hello.show()

	client_cert = TLSRecord(version=tls_version) / \
                      TLSHandshakes(handshakes=[TLSHandshake() / TLSCertificateList() /
                                                TLS10Certificate(certificates=certificate)])
	
	client_key_exchange = TLSRecord(version=tls_version) / \
						TLSHandshakes(handshakes=[TLSHandshake() /
													tls_socket.tls_ctx.get_client_kex_data()])

	sig = tls_socket.tls_ctx.compute_client_cert_verify()
		
	client_cert_verify = TLSRecord(version=tls_version) / \
						TLSHandshakes(handshakes=[TLSHandshake() /
												TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
																	sig=sig)])
																		
	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()																	
	
	p = TLS.from_records([client_cert, client_cert_verify, client_key_exchange, client_ccs])
		
	p.show()
	tls_socket.sendall(p)
	
	#p = TLS.from_records([client_ccs])
	#tls_socket.sendall(p)
	
	#get_verify_data = TLSRecord(version=tls_version / \
	#				TLSHandshakes(handshakes=[TLSHandshake() /
	#											TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
	
	#p = TLS.from_records([get_verify_data])
	#tls_socket.sendall(p)
	#server_finished = tls_socket.recvall()
	#server_finished.show()
	
	tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
	resp = tls_socket.recvall()
	
	print("Done")
		
def FCS_TLSS_EXT_2_4_6a():
	client_cert= os.path.join(basedir, configured_certificate_Path)
	with open(client_cert, "rb") as f:
		cert = f.read()
	
	certificate = TLSCertificate(data=cert)
	
	print("Last byte of certificate before: ")
	print(certificate)
	certificate_data_list = list(certificate.data)
	
	print()
	
	print("Changing " + certificate_data_list[50] + " to be the character z")
	
	#print("Finding Change helper ")
	#print(certificate_data_list[:50])
	
	certificate_data_list[50] = 'z'
	
	certificate_data = "".join(certificate_data_list)
	
	certificate.data = certificate_data
	
	print("Last byte of signature afer: ")
	print(certificate)

	tls_version = TLSVersion.TLS_1_2

	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tls_socket.connect(server)
	tls_socket = TLSSocket(tls_socket, client=True)
	tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
		basedir, "etc/FCS_TLSC/TestServerRSA.key"))
				
	client_hello = TLSRecord(version=tls_version) / \
			   TLSHandshakes(handshakes=[TLSHandshake() /
										 TLSClientHello(version=tls_version,
														cipher_suites=configured_cipher_suites,
							extensions=[TLSExtension() /
							TLSExtSignatureAlgorithms()])])
	tls_socket.sendall(client_hello)
	server_hello = tls_socket.recvall()
	server_hello.show()

	client_cert = TLSRecord(version=tls_version) / \
                      TLSHandshakes(handshakes=[TLSHandshake() / TLSCertificateList() /
                                                TLS10Certificate(certificates=certificate)])
	
	client_key_exchange = TLSRecord(version=tls_version) / \
						TLSHandshakes(handshakes=[TLSHandshake() /
													tls_socket.tls_ctx.get_client_kex_data()])

	sig = tls_socket.tls_ctx.compute_client_cert_verify()
		
	client_cert_verify = TLSRecord(version=tls_version) / \
						TLSHandshakes(handshakes=[TLSHandshake() /
												TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
																	sig=sig)])
																		
	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()																	
	
	p = TLS.from_records([client_cert, client_cert_verify, client_key_exchange, client_ccs])
		
	tls_socket.sendall(p)
	
	#p = TLS.from_records([client_ccs])
	#tls_socket.sendall(p)
	
	#get_verify_data = TLSRecord(version=tls_version / \
	#				TLSHandshakes(handshakes=[TLSHandshake() /
	#											TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
	
	#p = TLS.from_records([get_verify_data])
	#tls_socket.sendall(p)
	#server_finished = tls_socket.recvall()
	#server_finished.show()
	
	tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
	resp = tls_socket.recvall()
	
	print("Done")

def FCS_TLSS_EXT_2_4_6b():
	client_cert= os.path.join(basedir, "etc/FCS_TLSC/TestServerRSA.crt.der")
	with open(client_cert, "rb") as f:
		cert = f.read()
	certificate = TLSCertificate(data=cert)

	print(certificate)
	
    	tls_version = TLSVersion.TLS_1_2

    	tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	tls_socket.connect(server)
	tls_socket = TLSSocket(tls_socket, client=True)
	tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
		basedir, "etc/FCS_TLSC/TestServerRSA.key"))
				
    	client_hello = TLSRecord(version=tls_version) / \
                   TLSHandshakes(handshakes=[TLSHandshake() /
                                             TLSClientHello(version=tls_version,
                                                            cipher_suites=configured_cipher_suites,
								extensions=[TLSExtension() /
								TLSExtSignatureAlgorithms()])])
    	tls_socket.sendall(client_hello)
    	server_hello = tls_socket.recvall()
    	server_hello.show()

    	client_key_exchange = TLSRecord(version=tls_version) / \
                          	TLSHandshakes(handshakes=[TLSHandshake() /
                                                    	tls_socket.tls_ctx.get_client_kex_data()])
    	p = TLS.from_records([client_key_exchange])
    	tls_socket.sendall(p)

    	sig = tls_socket.tls_ctx.get_client_signed_handshake_hash()
	print("Last byte of signature before: " + binascii.b2a_hex(sig[-1]))
	sig = sig[0:-1] + 'z'
	print("Last byte of signature afer: " + binascii.b2a_hex(sig[-1]))
		
	client_cert_verify = TLSRecord(version=tls_version) / \
						TLSHandshakes(handshakes=[TLSHandshake() /
												TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
																		sig=sig)])
	
	print("Sending Client Cert Verify message")
	p = TLS.from_records([client_cert_verify])
		
	tls_socket.sendall(p)
	server_finished = tls_socket.recvall()
#	sig[-1]='z'
#	tr=to_raw(client_cert_verify,tls_socket.tls_ctx)
#	print("Last byte of cert verify is: " + binascii.b2a_hex(tr[Raw].load[-1]))
#	print("Altering last byte of cert verify from '" + binascii.b2a_hex(tr[Raw].load[-1]) + "' to '7a'")
#	tr[Raw].load = tr[Raw].load[0:-1]+'z'
#	print("Last byte of cert verify is: " + binascii.b2a_hex(tr[Raw].load[-1]))
#	tls_socket.sendall(tr)
#    	client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
#    	tls_socket.sendall(client_ccs)
#    	tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
#							TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
#    	server_finished = tls_socket.recvall()
#    	server_finished.show()
	
#    	tls_socket.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
#    	resp = tls_socket.recvall()
    	print("Got response from server")
    	#resp.show()
#    	print(tls_socket.tls_ctx)

	
def printhelp():
	print("\nSyntax: FCS_TLSS_test_tool.py -d <dest. address> -p <dest. port> -t <selected test>")
	print("By default, this will run all tests and connect to 127.0.0.1:4433.")
	print("To run a specific test use, -t with the following values:\n1 : successful_handshake\n2 : tls_null\n3 : FCS_TLSS_EXT_1_1_Test_3\n4 : FCS_TLSS_EXT_1_1_Test_4a\n5 : FCS_TLSS_EXT_1_1_Test_4b\n6 : FCS_TLSS_EXT_1_1_Test_4c\n7 : FCS_TLSS_EXT_1_1_Test_4d\n8 : FCS_TLSS_EXT_1_1_Test_4e\n9 : FCS_TLSS_EXT_2_4_6b\n10 : FCS_TLSS_EXT_2_4_6a\n11 : FCS_TLSS_EXT_2_4_6")

tests = {
	1 : successful_handshake,
	2 : tls_null,
	3 : FCS_TLSS_EXT_1_1_Test_3,
	4 : FCS_TLSS_EXT_1_1_Test_4a,
	5 : FCS_TLSS_EXT_1_1_Test_4b,
	6 : FCS_TLSS_EXT_1_1_Test_4c,
	7 : FCS_TLSS_EXT_1_1_Test_4d,
	8 : FCS_TLSS_EXT_1_1_Test_4e,
	9 : FCS_TLSS_EXT_2_4_6b,
	10 : FCS_TLSS_EXT_2_4_6a,
	11 : FCS_TLSS_EXT_2_4_6,
}


dest = "127.0.0.1"
port = 4433
selectedTest = 0	
if __name__ == "__main__":
	try:
		opts, args = getopt.getopt(sys.argv[1:],"hd:p:t:")
	except getopt.GetoptError:
		printhelp()
		exit()
		
	for opt, arg in opts:
		if opt == '-h':
			printhelp()
			exit()
		elif opt in ("-d"):
			dest = arg		 
		elif opt in ("-p"):
			port = arg
		elif opt in ("-t"):
			selectedTest = arg
			
	server = (dest, int(port))
	
	if selectedTest > 0:
		tests[int(selectedTest)]()
	else:
		for t in tests:
			tests[t]()		
exit()
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
