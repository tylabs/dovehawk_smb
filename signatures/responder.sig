# Dovehawk.io SMB sigs v1 2020 04 24 Copyright @tylabs 2020
# Copyright 2020 @tylabs dovehawk.io


signature responder_challenge { 
	ip-proto == tcp
	#tcp-state established,responder
	payload /.{1,6}SMB.*\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x00\x00\x00\x00\x00\x00/ 
	event "dovehawk_smb: Responder.py challenge"
	eval dovehawk_smb::responder
} 



signature responder_reply_http { 
	ip-proto == tcp 
	tcp-state established,responder
	http-reply-body /.*file.{3}RespProxySrv/ 
	event "dovehawk_smb: Responder.py usage http"
	eval dovehawk_smb::responder
} 

signature responder_af { 
	ip-proto == tcp 
	tcp-state established,originator
	payload /.*0xAF/ 
	event "dovehawk_smb: Responder.py 0xAF"
	eval dovehawk_smb::responder
} 



signature responder_date { 
	ip-proto == tcp 
	tcp-state established,responder
	http-reply-header /Server: Microsoft-IIS\/6.0/ 
	http-reply-header /Date: Wed, 12 Sep 2012 13:06:55 GMT/ 
	event "dovehawk_smb: Responder.py date"
	eval dovehawk_smb::responder
} 

signature responder_date2 { 
	ip-proto == tcp 
	tcp-state established,responder
	http-reply-header /Server: Microsoft-IIS\/7.5/ 
	http-reply-header /Date: Thu, 24 Oct 2013 22:35:46 GMT/ 
	event "dovehawk_smb: Responder.py date2"
	eval dovehawk_smb::responder
} 

signature responder_proxy { 
	#ip-proto == tcp 
	tcp-state established,responder
	payload /.*RespProxySrv/ 
	event "dovehawk_smb: Responder.py usage name"
	eval dovehawk_smb::responder
} 

signature responder_weird_hash { 
	ip-proto == tcp 
	tcp-state established,responder
	http-reply-header /X-Powered-By: ASP.NC0CD7B7802C76736E9B26FB19BEB2D36290B9FF9A46EDDA5ET/ 
	event "dovehawk_smb: Responder.py weird hash"
	eval dovehawk_smb::responder
} 

signature responder_loading_one { 
	ip-proto == tcp 
	tcp-state established,responder
	http-reply-body /.*alt='Loading' height='1' width='1|2'/
	event "dovehawk_smb: Responder.py loading one by one"
	eval dovehawk_smb::responder
} 


signature responder_smbtoolkit { 
	ip-proto == tcp 
	tcp-state established
	payload /.*TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==/
	event "dovehawk_smb: Responder.py toolkit base64"
	eval dovehawk_smb::responder
}

