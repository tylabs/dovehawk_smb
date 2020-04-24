# Dovehawk.io SMB v1.0.0 2020 04 23 Copyright @tylabs 2020
#
# Inpired and code from https://github.com/mitre-attack/car/tree/master/implementations/bzar
# under the Apache License 2.0
#
#### Run live detection:
#### zeek -i <eth0> smb
####
#### Run over a PCAP file:
####
####.  zeek -Cr pcap/20171220_smb_psexec_mimikatz_ticket_dump.pcap dovehawk_smb
####

# Detects: - files with exe or ps1 extensions uploaded over SMB
#          - remote execution over rpc
#          - responder use
#
# Optional todo: track npb/llmnr hostname spoofing using sumstats 
#
# Caveat: Note Exe's downloaded to the host will not be flagged - this module is
# intended to detect lateral movement rather than loading tools on an already
# compromised host.




module dovehawk_smb;

@load base/utils/site

@load base/utils/directions-and-hosts

@load-sigs ../signatures/responder.sig



@load base/protocols/smb

@load base/protocols/dce-rpc
@load base/frameworks/files
@load base/frameworks/notice

@load ../config

redef ignore_checksums = T;


export {
	global DHSMB_VERSION = "1.0.0";

	## The log ID.
	redef enum Log::ID += { LOG };


	global register_hit: function(hitvalue: string);

	type Info: record {
		## Timestamp of when the data was finalized.
		ts:           time             &log;

		## The top queries being performed.
		ev:  string &log;


	};
	global log_smb: event(rec: Info);


	# ATT&CK - Execution Techniques from
	# https://github.com/mitre-attack/car/tree/master/implementations/bzar
	#
	# Windows DCE-RPC functions (endpoint::operation) used for 
	# Execution on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1035 Service Execution
	#    T1047 Windows Management Instrumentation
	#    T1053 Scheduled Tasks

	const rpc_execution : set[string] = 
	{
	    # ATT&CK Technique - T1035 Service Execution
		["svcctl::CreateServiceWOW64W"],
		["svcctl::CreateServiceW"],
		["svcctl::CreateServiceA"],
		["svcctl::StartServiceW"],
		["svcctl::StartServiceA"],

	    # ATT&CK Technique - T1047 Windows Management Instrumentation
		["IWbemServices::ExecMethod"],
		["IWbemServices::ExecMethodAsync"],

	    # ATT&CK Technique - T1053 Scheduled Tasks
		["atsvc::JobAdd"],
		["ITaskSchedulerService::SchRpcRegisterTask"],
		["ITaskSchedulerService::SchRpcRun"],
		["ITaskSchedulerService::SchRpcEnableTask"],
	} &redef;


}

event zeek_init()
{
	local rec: dovehawk_smb::Info;

	print ("dovehawk_smb module started");
	Log::create_stream(dovehawk_smb::LOG, [$columns=Info, $path="dhsmb", $ev=log_smb]);

}


function annotate_conn(conn: connection, msg: string, data: string): string {

	local src_addr: addr;
	local src_port: port;
	local dst_addr: addr;
	local dst_port: port;
	local di = NO_DIRECTION;
	local hit = "ZEEK";

	src_addr = conn$id$orig_h;
	src_port = conn$id$orig_p;
	dst_addr = conn$id$resp_h;
	dst_port = conn$id$resp_p;
	
	if (conn?$uid) {
		hit += fmt("|uid:%s",conn$uid);
	}

	#need time stamp
	if (conn?$start_time) {
		hit += fmt("|ts:%f",conn$start_time);
	}
	
	hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",src_addr,src_port,dst_addr,dst_port);



	if (Site::is_local_addr(conn$id$orig_h) || Site::is_private_addr(conn$id$orig_h) ) {
		di = OUTBOUND;
	} else if (Site::is_local_addr(conn$id$resp_h) || Site::is_private_addr(conn$id$resp_h) ) {
		di = INBOUND;
	}


	if (di == OUTBOUND) {
		hit += "|d:OUTBOUND";
	} else if (di == INBOUND) {
		hit += "|d:INBOUND";
	}

	if (conn?$service) {
		hit += "|service:";
		local service = conn$service;
		local servicename: string = "";
		for ( ser in service ) {
			servicename += fmt("%s,",ser);
		}
		if (|servicename| > 0) {
			hit += cut_tail(servicename, 1);
		}
	}

	if (conn?$orig) {
		local orig = conn$orig;
		if (orig?$size) {
			hit += fmt("|orig:%s",orig$size);
		}
		if (orig?$num_pkts) {
			hit += fmt("|o_pkts:%s",orig$num_pkts);
		}
		if (orig?$num_bytes_ip) {
			hit += fmt("|o_bytes:%s",orig$num_bytes_ip);
		}
		if (orig?$state) {
			hit += fmt("|o_state:%s",orig$state);
		}
		if (orig?$l2_addr) {
			hit += fmt("|o_l2:%s",orig$l2_addr);
		}
	}

	if (conn?$resp) {
		local resp = conn$resp;
		if (resp?$size) {
			hit += fmt("|resp:%s",resp$size);
		}
		if (resp?$num_pkts) {
			hit += fmt("|r_pkts:%s",resp$num_pkts);
		}
		if (resp?$num_bytes_ip) {
			hit += fmt("|r_bytes:%s",resp$num_bytes_ip);
		}
		if (resp?$state) {
			hit += fmt("|r_state:%s",resp$state);
		}
		if (resp?$l2_addr) {
			hit += fmt("|r_l2:%s",resp$l2_addr);
		}
	}

	if (conn?$start_time) {
		hit += fmt("|start_time:%s",conn$start_time);
	}

	if (conn?$duration) {
		hit += fmt("|duration:%s",conn$duration);
	}

	hit += fmt("|event:%s",msg);


	if (conn?$ntlm) {
		local ntlm = conn$ntlm;

		if (ntlm?$username) {
			hit += fmt("|user:%s",ntlm$username);
		}
		if (ntlm?$domainname) {
			hit += fmt("|domainname:%s",ntlm$domainname);
		}
		if (ntlm?$hostname) {
			hit += fmt("|hostname:%s",ntlm$hostname);
		}
	

	}

	if (conn?$http) {
		local http = conn$http;
		if (http?$host) {
			hit += fmt("|host:%s",http$host);
		}
		if (http?$uri) {
			hit += fmt("|uri:%s",http$uri);
		}
		if (http?$method) {
			hit += fmt("|method:%s",http$method);
		}
	}

	if (conn?$ssl) {
		local ssl = conn$ssl;
		if (ssl?$server_name) {
			hit += fmt("|sni:%s",ssl$server_name);
			if (ssl?$issuer) {
				hit += fmt("|issuer:%s",ssl$issuer);
			}
		}
	}

	if (conn?$smtp) {
			local smtp = conn$smtp;
			if (smtp?$from) {
				hit += fmt("|from:%s",smtp$from);
			}
			if (smtp?$subject) {
				hit += fmt("|subject:%s",smtp$subject);
			}
			if (smtp?$rcptto) {
				hit += fmt("|to:%s",smtp$rcptto);
			}
	}

	if (conn?$dns) {
			local dns = conn$dns;
			if (dns?$qtype_name) {
				hit += fmt("|q:%s",dns$qtype_name);
			}
			if (dns?$answers) {
				hit += fmt("|answers:%s",dns$answers);
			}
	}
	

	if (|data| > 0) {
		hit += fmt("|data:%s",data);
	}
	return hit;
}

function send_event(conn: connection, msg: string, data: string) {

	local hit: string = annotate_conn(conn,msg,data);
	#print (hit);
	register_hit(hit);
}



function smb_full_path_and_file_name ( s : SMB::State ) : string
{
	local file_tree = "";
	local file_name = "";

	if (s?$current_file) {
		if ( s$current_file?$path )
			file_tree = s$current_file$path;

		if ( s$current_file?$name )
			file_name = s$current_file$name;
	}
	return fmt("%s%s", file_tree, file_name);
}


function check_name(fname: string) : bool {
	local split_name = split_string(fname, /\./);

	if (|split_name| >=1 && (split_name[|split_name|-1] == "exe" || split_name[|split_name|-1] == "ps1" || split_name[|split_name|-1] == "bat" || split_name[|split_name|-1] == "dll")) {
		return T;
	}
	return F;

}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, data_len: count) &priority=-7 
{

	local fname = dovehawk_smb::smb_full_path_and_file_name(c$smb_state);

	if (fname == "atsvc") {
		#print ("  at job");
		#print(c);
		send_event(c, "Atsvc transferred over SMB", fname);
	} else if (check_name(fname)) {
		#print ("    executable type");
		#print(c);
		send_event(c, "Executable file transferred over SMB", fname);
	}
}





event file_over_new_connection(f:fa_file, c:connection, is_orig:bool)
{
	# Check Option

	# Check if SMB Tree Path is an Admin File Share
	if ( f?$source && f$source == "SMB" && c?$smb_state )
	{

	#print("file_over_new_connection");
	#print(c$smb_state$current_file);
	####print (c$smb_state);

		# Check if SMB Write to an Admin File Share
		if ( c$smb_state?$current_file &&
		     c$smb_state$current_file?$action &&
		     c$smb_state$current_file$action == SMB::FILE_WRITE )
		{
			#print(c$smb_state$current_file);
			local fname: string = c$smb_state$current_file$name;
			if (fname == "atsvc") {
				#print ("  at job");
				#print(c);
				send_event(c, "Atsvc transferred over SMB", fname);
			} if (check_name(fname)) {
				#print ("    executable type");
				#print(c);
				send_event(c, "Executable file transferred over SMB", fname);
			}


		}
	}
}





event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=3
{
	# priority==3 ... We want to execute before writing to dce_rpc.log
	# because default Zeek script deletes 'c$dce_rpc' after writing to log

	local rpc = "";
	#print c;

	if ( c?$dce_rpc && c$dce_rpc?$endpoint && c$dce_rpc?$operation )
	{
		# Get UUID and OpNum, by Name (endpoint::operation)
		rpc = fmt("%s::%s", c$dce_rpc$endpoint, c$dce_rpc$operation);
	}
	#print rpc;

	if ( rpc in dovehawk_smb::rpc_execution )
	{
		# Looks like DCE-RPC Remote Execution
		# Raise Notice
		#print("Remote Execution");
		send_event(c, "remote execution", rpc);


		#print(rpc);
		#print(c);

	}

}



function register_hit(hitvalue: string) {
	local upload_hit_url = dovehawk_smb::APIURL;

    	local post_data: table[string] of string;
	post_data["platform"] = "normal";
	post_data["hcode"] = "ZEV";
	post_data["hvalue"] = hitvalue;
	
	
    local request: ActiveHTTP::Request = [
        $url=upload_hit_url,
	$method="POST",
	$client_data=to_json(post_data),
	$addl_curl_args = fmt("--header \"Content-Type: application/json\" --header \"Accept: application/json\"")
    ];
	print "DoveHawk.io SMB Event: " + hitvalue;
	Log::write(dovehawk_smb::LOG, [$ts=network_time(), $ev=hitvalue]);

	when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			print fmt("Event Result ===> %s", resp$body);
		} else {
			print fmt("Event FAILED ===> %s", resp);
		}
	}
	
}


function responder(state: signature_state, data: string): bool {
	send_event(state$conn, state$sig_id, data);
	return T;
}




hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) : bool  &priority=3{
	local rec = c$dns;

	if (!rec$saw_query && rec?$query && (strstr(rec$query, ".") == 0 || strstr(rec$query, ".local") > 0) && rec?$TTLs && rec$TTLs[0] == 30 sec && rec?$answers) {
		#print ("***DNS Poisoning");

		send_event(c, fmt("|DNS Poisoning: %s at %s", rec$query, rec$answers[0]), "");
		
	}

	return T;
}

