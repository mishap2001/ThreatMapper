#!/bin/bash

###############################################################
# Threat Mapper
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
MAGENTA="\e[35m"
ENDCOLOR="\e[0m"
echo -e "${RED}--------------------------------${ENDCOLOR}"
echo -e "${RED}Vulnerabilities Enumeration Tool${ENDCOLOR}"
echo -e "${RED}--------------------------------${ENDCOLOR}"
echo

function ROOT() # check if the user is root. If not, suggests to re-run as root or exit. 
{
	USER=$(whoami)
	if [ $USER != "root" ]; then

	echo -e "${RED}----------${ENDCOLOR}"
	echo -e "${RED}|Warning!| Only root is allowed to run the script.${ENDCOLOR}"
	echo -e "${RED}----------${ENDCOLOR}"
	echo "You can either run the script with sudo or become root."
	echo "Would you like to become one?"
	echo "Yes - become root and run the script again"
	echo "No - exit the script"
	echo "(Y/N)"
		read root_answer
		case $root_answer in
			y|Y)
			echo "Re-running script as root..."
			sudo  bash "$0" "$@"
			exit # exit the script that runs without root to prevent loop
			;;
			
			n|N)
			echo "Exiting script!"
			exit
			;;
		esac	
	else
		echo "Checking user..."
		sleep 2
		echo "You are root! Continuing..."
		sleep 2
		echo ""
		
	fi	
}

function SCN_TYPE() # basic scan/full scan/analysis of previos scan
{
	while true; do
	echo -e "${GREEN}-----------------${ENDCOLOR}"
	echo -e "${GREEN}Choose scan type:${ENDCOLOR}"
	echo -e "${GREEN}-----------------${ENDCOLOR}"
	echo "1. Basic - scans the network for TCP and UDP open ports (includes service version) and weak passwords."
	echo "2. Full - more in-depth scan of the network, does vulnerabilitie analysis and scans for weak passowrds."	
	echo "3. Analyze previos results"
	read type_answ
		case $type_answ in
			1) echo
			   echo "[*] Basic scan was chosen [*]"
			   echo
			   CHK # validate ip range and live hosts
			   B_SCAN # basic scan
			   HYD # hydra 
			   SUM_B # summery of found data
			   ANA_B # option to analyze results
			   ORG # organize and zip
			   break
			;;
			2) echo 
			   echo "[*] Full scan was chosen [*]"
			   echo
			   CHK # validate ip range and live hosts
			   F_SCAN # full scan
			   VULN # vulnerability analysis
			   HYD # hydra 
			   SUM_F # summery of found data
			   ANA_F # option to analyze results
			   ORG # organize and zip
			   break
			;;
			3)	
				echo "[*] Please provide the full path of the previous results"
				read path2r
				if [ -d "$path2r" ]; then
					dir_name="$path2r"
				else
					echo
					echo "[!] Directory does not exist. Try again."
					continue
				fi	
				echo
				echo "[?] Was it a basic or a full scan?"
				echo "1. Basic"
				echo "2. Full"
				read ana_type
				case $ana_type in
					1)
						ANA_B
						break 2
					;;
		            2)
						ANA_F
						break 2
					;;
					*)
						echo
						echo "[!] Invalid input. Try again."
						continue
					;;
				esac
			 ;;
			*) echo 
			   echo "[!] Invalid input. Please choose 1, 2 or 3"
			   echo
			   continue
			;;			
		esac
	done	
}

function CHK() # validation of ip range and live hosts
{
	echo -e "${GREEN}--------------------------------------------${ENDCOLOR}"
	echo -e "${GREEN}Give a name for the directory of the output:${ENDCOLOR}"
	echo -e "${GREEN}--------------------------------------------${ENDCOLOR}"
	read dir_name
	mkdir -p $dir_name
	echo
	echo -e "${GREEN}----------------------------------------------------------${ENDCOLOR}"
	echo -e "${GREEN}Please input the IP range for the scan in the next format:${ENDCOLOR}"
	echo -e "${GREEN}----------------------------------------------------------${ENDCOLOR}"
	echo
	echo "1.2.3.0-255 or 1.2.3.0/24 or 1.2.3.*"
	read IPR
	if nmap "$IPR" -sL 2>&1 | grep "Failed to resolve"; then	# checks if the ip range is valid
		echo "This is not a valid IP range. Exiting..."
		exit
	else
		nmap -sL "$IPR" | awk '{print $NF}' | grep ^[0-9] > "$dir_name/IP_range" # put the range in a file
		echo
		echo "[*]The chosen range can be found in $dir_name/IP_range"
		echo
		echo "[*]Scanning for live hosts..."
		nmap -sn "$IPR" | awk '{print $5}' | grep ^[0-9] > "$dir_name/Live_hosts" # put only ive hosts in a file
		echo
		echo "[!]Live hosts can be found in $dir_name/Live_hosts"
	fi	
}

function B_SCAN() # TCP+UDP open port and service versions
{
	scan_start=$(date)
	echo
	echo -e "${GREEN}------------------------${ENDCOLOR}"
	echo -e "${GREEN}Commencing basic scan...${ENDCOLOR}"	
	echo -e "${GREEN}------------------------${ENDCOLOR}"
	echo
	for ip in $(cat "$dir_name/Live_hosts") 
	do
		echo -e "${GREEN}[*]Scanning $ip...${ENDCOLOR}"
		echo
		echo "[*]Starting TCP port discovery" # to make the scan faster, there will be phases 
		echo "$(date)" > "$dir_name/$ip"
		echo "===TCP PORT DISCOVERY===" >> "$dir_name/$ip" 
		nmap -sS -p- "$ip" >> "$dir_name/$ip" # scans for all open TCP ports. Saves the results per IP	 
		echo
		echo "[!]Finished TCP port discovery"
		echo
		echo "[*]Starting UDP port discovery" 
		echo "===UDP PORT DISCOVERY===" >> "$dir_name/$ip"
		nmap -sU "$ip" >> "$dir_name/$ip" # scans for top 1000 open UDP ports. Combines results with TCP scan
		echo
		echo "[!]Finished UDP port discovery"
		echo
	done
	cd "$dir_name"
	for	ip in $(cat Live_hosts) 
	do
		echo "[*] Detecting services for all open ports on $ip" 
		echo
		tcp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep tcp | awk -F '/' '{print $1}' | paste -sd,)
		udp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep udp | awk -F '/' '{print $1}' | paste -sd,)
			if [ -n "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are both TCP and UDP ports
					ports="T:$tcp_ports,U:$udp_ports"
					nmap -sV -sU -sS -p"$ports" "$ip" > "${ip}_services" # Must add -sU or nmap will not scan the UDP ports
			elif [ -n "$tcp_ports" ] && [ -z "$udp_ports" ];then # If there are only TCP ports
					ports="T:$tcp_ports"
					nmap -sV -sS -p"$ports" "$ip" > "${ip}_services" 
			elif [ -z "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are only UDP ports
					ports="U:$udp_ports"
					nmap -sV -sU -p"$ports" "$ip" > "${ip}_services" # Must add -sU or nmap will not scan the UDP ports
			else 
				  echo "No open ports found on $ip, skipping..." 
				  echo
				  continue
			fi
	done
	echo
	echo "[!] Finished service detection"
	echo
	cd ..	
}	
	
function F_SCAN() # TCP+UDP open port and service versions
{
	scan_start=$(date)
	echo
	echo -e "${GREEN}------------------------${ENDCOLOR}"
	echo -e "${GREEN}Commencing full scan...${ENDCOLOR}"	
	echo -e "${GREEN}------------------------${ENDCOLOR}"
	echo
	for ip in $(cat "$dir_name/Live_hosts") 
	do
		echo -e "${GREEN}[*]Scanning $ip...${ENDCOLOR}"
		echo
		echo "[*] Starting TCP port discovery" # to make the scan faster, there will be phases
		echo "$(date)" > "$dir_name/$ip"
		echo "===TCP PORT DISCOVERY===" >> "$dir_name/$ip" 
		nmap -sS -p- "$ip" >> "$dir_name/$ip" # scans for all open TCP ports. Saves the results per IP	 
		echo
		echo "[!] Finished TCP port discovery"
		echo
		while true; do
			echo "Would you like to scan for open UDP ports?"
			echo "1. Yes (It will take a while!)"
			echo "2. Skip"
			read udp_a
			case $udp_a in
				1)
					echo "[*] Starting UDP port discovery" 
					echo
					echo "[!] It may take some time..."
					echo "===UDP PORT DISCOVERY===" >> "$dir_name/$ip"
					nmap -sU -p- "$ip" >> "$dir_name/$ip" # scans for all open UDP ports. Combines results with TCP scan
					echo
					echo "[!] Finished UDP port discovery"
				;;
				2)
					break
				;;				
			esac
		done
		sleep 1
		echo
		echo "[*] Results are saved as $ip"
	done
	cd "$dir_name"
	for	ip in $(cat Live_hosts) 
	do
		echo "[*] Detecting services for all open ports on $ip" 
		echo
		tcp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep tcp | awk -F '/' '{print $1}' | paste -sd,)
		udp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep udp | awk -F '/' '{print $1}' | paste -sd,)
			if [ -n "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are both TCP and UDP ports
					ports="T:$tcp_ports,U:$udp_ports"
					nmap -sV -sU -sS -p"$ports" "$ip" > "${ip}_services" # Must add -sU or nmap will not scan the UDP ports
			elif [ -n "$tcp_ports" ] && [ -z "$udp_ports" ];then # If there are only TCP ports
					ports="T:$tcp_ports"
					nmap -sV -sS -p"$ports" "$ip" > "${ip}_services" 
			elif [ -z "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are only UDP ports
					ports="U:$udp_ports"
					nmap -sV -sU -p"$ports" "$ip" > "${ip}_services" # Must add -sU or nmap will not scan the UDP ports
			else 
				  echo "No open ports found on $ip, skipping..." 
				  echo
				  continue
			fi
	done
	echo
	echo "[!] Finished service detection"
	echo
	cd ..	
}

function HYD() # brute force ssh, ftp, rdp and telnet.
{	
	cd "$dir_name"
	echo
	echo -e "${GREEN}To search for weak credentials please answer the following:${ENDCOLOR}"
	echo
	echo "Use the default username list or use a custom one?"
	echo "1. Default"
	echo "2. Custom"
	echo
	read usrl 	#default/custom username list
	case $usrl in
	
		1) echo "Using default username list..."
		   echo
		   userlist=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt # username list path
		;;
		2) echo "Please provide full path to the username list"
		   echo
		   read ulist
		   if [ -f "$ulist" ]; then
			  userlist="$ulist"
		   else
			  echo "[!] The file was not found. Using Default list."
			  echo
			  userlist=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt # username list path
		   fi  
		;;
		*) echo "[!] Invalid choice. Using Default list."
		      userlist=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt # username list path
		;;
	esac
	echo "Use the default password list or use a custom one?"
	echo "1. Default"
	echo "2. Custom"
	echo
	read dcpl 	#default/custom password list
	case $dcpl in
	
		1) echo "Using default password list..."
		   echo
		   passlist=/usr/share/seclists/Passwords/Common-Credentials/2024-197_most_used_passwords.txt # password list path
		;;
		
		2) echo "Please provide full path to the password list"
		   echo
		   read plist
		   if [ -f "$plist" ]; then
			  passlist="$plist"
		   else
			  echo "[!] The file was not found. Using Default list."
			  echo
			  passlist=/usr/share/seclists/Passwords/Common-Credentials/2024-197_most_used_passwords.txt # password list path
		   fi  
		;;
		 
		*) echo "[!] Invalid choice. Using Default list."
		   echo
		      passlist=/usr/share/seclists/Passwords/Common-Credentials/2024-197_most_used_passwords.txt # password list path
		;;
	esac
	
	for	ip in $(cat Live_hosts)
	do
		targets=$(cat "${ip}_services" | grep open | grep -w '21/tcp\|22/tcp\|23/tcp\|3389/tcp' | awk '{print $3, "'$ip'"}' | sed 's/ /:\/\//')
		# target is <service>://<ip>
		for target in $targets
		do
		t_service=$(echo "$target" | cut -d: -f1)
		
			case "$t_service" in # change thread speed pet service because of timeout settings, for minimal speed change
				ssh)
					threads=4
				;;
				ftp)
					threads=16
				;;
				telnet)
					threads=8
				;;
				rdp)
					threads=4
				;;	
			esac
			# all args inside hydra	
			echo "Brute forcing $ip"	
			echo
			hydra -t "$threads" -L "$userlist" -P "$passlist" "$target" -o "${ip}_weak_passwords.txt"	
					
		 done
	done	
	echo "[!] Finished Brute forcing."
	echo "[*] Results are saved as IP_weak_passwords.txt for every scanned host."
	echo
	cd ..
}

function VULN() # Check for vulnerabilities
{
	cd "$dir_name"
	echo
	if [ ! -f /usr/share/nmap/scripts/vulners/vulners.nse ] # check if vulners.nse script exists, if not - get it
	then
		echo "Getting script for vulnerability check..."
		git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
		nmap --script-updatedb
	fi	
	for	ip in $(cat Live_hosts) # the scan will be only for open ports to make it faster, and then classify the data per vulnerability rate
	do
		echo "[*] Scanning for vulnerabilities in $ip" 
		echo
		tcp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep tcp | awk -F '/' '{print $1}' | paste -sd,)
		udp_ports=$(cat "$ip" | grep open | awk '{print $1}' | grep udp | awk -F '/' '{print $1}' | paste -sd,)
			if [ -n "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are both TCP and UDP
					ports="T:$tcp_ports,U:$udp_ports"
					nmap -sV -sU -sS -p"$ports" "$ip" --script=vulners/vulners.nse > "${ip}_vuln" # Must add -sU or nmap will not scan the UDP ports
					grep CVE ${ip}_vuln | awk '$3 < 4 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_low"
					grep CVE ${ip}_vuln | awk '$3 > 3.9 && $3 < 7 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_medium"
					grep CVE ${ip}_vuln | awk '$3 > 6.9 && $3 < 9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_high"
					grep CVE ${ip}_vuln | awk '$3 > 8.9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_critical"
			elif [ -n "$tcp_ports" ] && [ -z "$udp_ports" ];then # If there are only TCP ports
					ports="T:$tcp_ports"
					nmap -sV -sS -p"$ports" "$ip" --script=vulners/vulners.nse > "${ip}_vuln"
					grep CVE ${ip}_vuln | awk '$3 < 4 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_low"
					grep CVE ${ip}_vuln | awk '$3 > 3.9 && $3 < 7 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_medium"
					grep CVE ${ip}_vuln | awk '$3 > 6.9 && $3 < 9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_high"
					grep CVE ${ip}_vuln | awk '$3 > 8.9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_critical"
			elif [ -z "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are only UDP ports
					ports="U:$udp_ports"
					nmap -sV -sU -p"$ports" "$ip" --script=vulners/vulners.nse > "${ip}_vuln" # Must add -sU or nmap will not scan the UDP ports
					grep CVE ${ip}_vuln | awk '$3 < 4 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_low"
					grep CVE ${ip}_vuln | awk '$3 > 3.9 && $3 < 7 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_medium"
					grep CVE ${ip}_vuln | awk '$3 > 6.9 && $3 < 9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_high"
					grep CVE ${ip}_vuln | awk '$3 > 8.9 { print }' | awk '{print $2, $3, $4, $5}' | sort | uniq > "${ip}_vuln_critical"
			else 
				  echo "No open ports found on $ip, skipping..." 
				  echo
				  continue
			fi
	done
	cd ..
}	

function SUM_B() # summary for the found information - basic scan
{
	cd "$dir_name"
	{
		echo "${GREEN}===GENERAL INFORMATION===${ENDCOLOR}"
		echo
		echo "Scan started at - $scan_start"
		echo "Scan finished at - $(date)"
		echo "Selected range - $IPR"
	
		if [ -f Live_hosts ]; then
			echo "Number of live hosts - $(cat Live_hosts | wc -l)"
		else
			echo "There are no live hosts."
		fi
		echo 
		if [ -f Live_hosts ]; then
			for ip in $(cat Live_hosts)
			do
			echo -e "${GREEN}===SUMMARY FOR ${ip}===${ENDCOLOR}"
			echo
			echo "Number of open TCP ports - $(grep -H tcp $ip | grep open | wc -l)"
			echo "Number of open UDP ports - $(grep -H udp $ip | grep open | wc -l)"
			echo "Number of weak passwords found - $(cat ${ip}_weak_passwords.txt | grep -c host)"
		done
		fi	
	} >> summary.txt
	cat summary.txt
	cd ..
}

function SUM_F() # summary for the found information - full scan
{
	cd "$dir_name"
	{
		echo -e "${GREEN}===GENERAL INFORMATION===${ENDCOLOR}"
		echo
		echo "Scan started at - $scan_start"
		echo "Scan finished at - $(date)"
		echo "Selected range - $IPR"
	
		if [ -f Live_hosts ]; then
			echo "Number of live hosts - $(cat Live_hosts | wc -l)"
		else
			echo "There are no live hosts."
		fi
		echo 
		if [ -f Live_hosts ]; then
			for ip in $(cat Live_hosts)
			do
			echo -e "${GREEN}===SUMMARY FOR ${ip}===${ENDCOLOR}"
			echo
			echo "Number of open TCP ports - $(grep -H tcp $ip | grep open | wc -l)"
			if grep -q -H udp $ip; then
			echo "Number of open UDP ports - $(grep -H udp $ip | grep open | wc -l)"
			fi
			echo "Number of weak passwords found - $(cat ${ip}_weak_passwords.txt | grep -c host)"
			echo "Number of vulnerabilities - $(cat ${ip}_vuln | grep -v POSTGRESQL | wc -l)"
			done
		fi	
	} >> summary.txt
	cat summary.txt
	cd ..
}

function ANA_B() # allow the user to search inside the results
{
	cd "$dir_name"
	while true; do	
	echo "[?] Would you like to analyze the results? (Y/N)" 
	echo
	read res_an
	case $res_an in			
		y|Y)
		while true; do
			echo -e "${GREEN}--------------------------------------------------------------------${ENDCOLOR}"
			echo -e "${GREEN}Do you want to analyze a specific host or all the scanned addresses?${ENDCOLOR}"
			echo -e "${GREEN}--------------------------------------------------------------------${ENDCOLOR}"
			echo "1. Specific host"
			echo "2. All scanned addresses"
			echo
			read who
			case $who in				
				1)
					echo
					echo "[*] What is the IP address?"
					read what_ip
					if [ -f $what_ip ] # checks if there is a file with the name of selected ip
					then
						ip_a=${what_ip}
					else
						echo
						echo -e "${RED}The selected address was not scanned. Try again${ENDCOLOR}"
						echo
						continue
					fi		
					break
				;;
				2)
					echo
					ip_a=ALL
					echo "[*] Proceeding..."
					break	
				;;				
				*)
					echo
					echo -e "${RED}Invalid input. Try again.${ENDCOLOR}"
					continue
				;;
			esac	
		done			
		while true; do
			echo
			echo -e "${GREEN}--------------------------------------------------------------------------------------${ENDCOLOR}"
			echo -e "${GREEN}-------------------------------${ENDCOLOR}"
			echo -e "${GREEN}What would you like to analyze?${ENDCOLOR}"
			echo -e "${GREEN}-------------------------------${ENDCOLOR}"
			echo
			echo "[1] Open TCP ports                           [5] UDP service version "
			echo
			echo "[2] Open UDP ports                           [6] TCP + UDP service versions (combined)"
			echo
			echo "[3] Open TCP + UDP ports (combined)          [7] Weak Passwords"
			echo
			echo "[4] TCP service version                      [8] Everything"
			echo		
			echo -e "${GREEN}--------------------------------------------------------------------------------------${ENDCOLOR}"
			echo
			read menu_an
			case $menu_an in				
				1)
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN TCP PORTS===${ENDCOLOR}"
						grep -H tcp $ip_a | grep --color=never open
						done
						ip_a=ALL # added it in the end of each option so the ip_a=* loop will not break
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN TCP PORTS===${ENDCOLOR}"
						grep -H tcp $ip_a | grep --color=never open
					fi
				;;				
				2)
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN UDP PORTS===${ENDCOLOR}"
						grep -H udp $ip_a | grep --color=never open
						done
						ip_a=ALL 
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN UDP PORTS===${ENDCOLOR}"
						grep -H udp $ip_a | grep --color=never open
					fi
				;;				
				3)
					echo -e "${GREEN}===OPEN TCP + UDP PORTS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
					fi
				;;				
				4)
					echo -e "${GREEN}===TCP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
					fi
				;;				
				5)
					echo -e "${GREEN}===UDP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
					fi
				;;				
				6)
					echo -e "${GREEN}===TCP + UDP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
					fi
				;;				
				7)
					echo -e "${GREEN}===WEAK PASSWORDS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
					fi	
				;;				
				8)
					echo -e "${GREEN}===OPEN TCP + UDP PORTS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
					fi
					echo
					echo -e "${GREEN}===TCP + UDP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
					fi
					echo
					echo -e "${GREEN}===WEAK PASSWORDS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
					fi							
			esac			
			echo
			echo "[*] Do you want to analyze anything else? (Y/N)"
			read anyelse
			case $anyelse in				
				y|Y)
					continue
				;;				
				n|N)
					break 2
				;;				
				*)
					echo -e "${RED}Invalid choice, continuing... ${ENDCOLOR}"
					break
				;;
			esac
		done				
		;;		
		n|N)
			cd ..
			return
		;;		
		*)
			echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
			continue			
		;;	
	esac
	done	
	cd ..	
}

function ANA_F() # allow the user to search inside the results
{	
	cd "$dir_name"
	while true; do	
	echo "[?] Would you like to analyze the results? (Y/N)" 
	echo
	read res_an
	case $res_an in			
		y|Y)
		while true; do
			echo -e "${GREEN}--------------------------------------------------------------------${ENDCOLOR}"
			echo -e "${GREEN}Do you want to analyze a specific host or all the scanned addresses?${ENDCOLOR}"
			echo -e "${GREEN}--------------------------------------------------------------------${ENDCOLOR}"
			echo "1. Specific host"
			echo "2. All scanned addresses"
			echo
			read who
			case $who in				
				1)
					echo
					echo "[*] What is the IP address?"
					read what_ip
					if [ -f $what_ip ] # checks if there is a file with the name of selected ip
					then
						ip_a=${what_ip}
					else
						echo
						echo -e "${RED}The selected address was not scanned. Try again${ENDCOLOR}"
						echo
						continue
					fi		
					break
				;;				
				2)
					echo
					ip_a=ALL
					echo "[*] Proceeding..."
					break	
				;;				
				*)
					echo
					echo -e "${RED}Invalid input. Try again.${ENDCOLOR}"
					continue
				;;
			esac	
		done			
		while true; do
			echo
			echo -e "${GREEN}--------------------------------------------------------------------------------------${ENDCOLOR}"
			echo -e "${GREEN}-------------------------------${ENDCOLOR}"
			echo -e "${GREEN}What would you like to analyze?${ENDCOLOR}"
			echo -e "${GREEN}-------------------------------${ENDCOLOR}"
			echo
			echo "[1] Open TCP ports                           [5] UDP service version "
			echo
			echo "[2] Open UDP ports                           [6] TCP + UDP service versions (combined)"
			echo
			echo "[3] Open TCP + UDP ports (combined)          [7] Weak Passwords"
			echo
			echo "[4] TCP service version                      [8] Vulnerabilities"
			echo		
			echo -e "${GREEN}--------------------------------------------------------------------------------------${ENDCOLOR}"
			echo
			read menu_an
			case $menu_an in				
				1)
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN TCP PORTS===${ENDCOLOR}"
						grep -H tcp $ip_a | grep --color=never open
						done
						ip_a=ALL # added it in the end of each option so the ip_a=* loop will not break
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN TCP PORTS===${ENDCOLOR}"
						grep -H tcp $ip_a | grep --color=never open
					fi
				;;				
				2)
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN UDP PORTS===${ENDCOLOR}"
						grep -H udp $ip_a | grep --color=never open
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "${GREEN}===OPEN UDP PORTS===${ENDCOLOR}"
						grep -H udp $ip_a | grep --color=never open
					fi
				;;				
				3)
					echo -e "${GREEN}===OPEN TCP + UDP PORTS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						grep -H tcp $ip_a | grep --color=never open
						echo -e "===UDP==="
						grep -H udp $ip_a | grep --color=never open	
					fi
				;;				
				4)
					echo -e "${GREEN}===TCP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
					fi
				;;				
				5)
					echo -e "${GREEN}===UDP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
					fi
				;;				
				6)
					echo -e "${GREEN}===TCP + UDP SERVICE VERSIONS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						echo -e "===TCP==="
						cat ${ip_a}_services | grep open| grep tcp | awk '{$2=""; print}'
						echo -e "===UDP==="
						cat ${ip_a}_services | grep open| grep udp | awk '{$2=""; print}'
					fi
				;;				
				7)
					echo -e "${GREEN}===WEAK PASSWORDS===${ENDCOLOR}"
					if [ "$ip_a" = "ALL" ]; then
					for ip in $(cat Live_hosts); do
						ip_a=$ip
						echo		
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
						done
						ip_a=ALL
					else
						ip_a=$what_ip
						echo "[*] IP - ${ip_a}"
						if [ -f ${ip_a}_weak_passwords.txt ]
					then
						cat ${ip_a}_weak_passwords.txt | grep host
					else
						echo "[*] No weak passwords found"
					fi
					fi	
				;;				
				8)
					while true; do
					echo "Choose a filter:"
					echo "----------------"
					echo -e "[1] ${GREEN}CVSS - low (<4)${ENDCOLOR}" # low
					echo -e "[2] ${YELLOW}CVSS - medium (4-6.9)${ENDCOLOR}"
					echo -e "[3] ${RED}CVSS - high (7-8.9)${ENDCOLOR}"
					echo -e "[4] ${MAGENTA}CVSS - critical (9<)${ENDCOLOR}"
					echo "[5] No filter"
					echo
					read filter
					echo
					echo
					case $filter in	
						1)	
							while true; do
						    echo -e "${GREEN}----------${ENDCOLOR}"
							echo -e "${GREEN}CVSS - LOW${ENDCOLOR}"
							echo -e "${GREEN}----------${ENDCOLOR}"
							echo "[*] For more information press the link"
							if [ "$ip_a" = "ALL" ]; then
								for ip in $(cat Live_hosts); do
									ip_a=$ip
							echo		
							echo "[*] IP - ${ip_a}"
							cat ${ip_a}_vuln_low | grep -v POSTGRESQL
							echo "TOTAL CVSS LOW - $(cat ${ip_a}_vuln_low | grep -v POSTGRESQL | wc -l)"
								done
								ip_a=ALL
							else
								ip_a=$what_ip
								echo "[*] IP - ${ip_a}"
								cat ${ip_a}_vuln_low | grep -v POSTGRESQL
								echo "TOTAL CVSS LOW - $(cat ${ip_a}_vuln_low | grep -v POSTGRESQL | wc -l)"	
							fi
							echo
							echo "Would you like to apply another filter or exit to menu?"
							echo "1. Another filter"
							echo "2. Exit to menu"
							read filter_1
							echo
							case $filter_1 in
								1) break
								 ;;								
								2) break 2
								 ;;								
								*) echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							       continue
							    ;;
							esac
							done
							;;																		
						2)
							while true; do
							echo -e "${YELLOW}-------------${ENDCOLOR}"
							echo -e "${YELLOW}CVSS - MEDIUM${ENDCOLOR}"
							echo -e "${YELLOW}-------------${ENDCOLOR}"
							echo
							echo "[*] For more information press the link"
							if [ "$ip_a" = "ALL" ]; then
								for ip in $(cat Live_hosts); do
									ip_a=$ip
							echo		
							echo "[*] IP - ${ip_a}"
							cat ${ip_a}_vuln_medium | grep -v POSTGRESQL
							echo "TOTAL CVSS MEDIUM - $(cat ${ip_a}_vuln_medium | grep -v POSTGRESQL | wc -l)"
								done
								ip_a=ALL
							else
								ip_a=$what_ip
								echo "[*] IP - ${ip_a}"
								cat ${ip_a}_vuln_medium | grep -v POSTGRESQL
								echo "TOTAL CVSS MEDIUM - $(cat ${ip_a}_vuln_medium | grep -v POSTGRESQL | wc -l)"	
							fi
							echo
							echo "Would you like to apply another filter or exit to menu?"
							echo "1. Another filter"
							echo "2. Exit to menu"
							read filter_2
							echo
							case $filter_2 in
								1) break
								 ;;
								2) break 2
								 ;;								
								*) echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							       continue
							    ;;
							esac
							done
						;;						
						3)
							while true; do
							echo -e "${RED}-----------${ENDCOLOR}"
							echo -e "${RED}CVSS - HIGH${ENDCOLOR}"
							echo -e "${RED}-----------${ENDCOLOR}"
							echo
							echo "[*] For more information press the link"
							if [ "$ip_a" = "ALL" ]; then
								for ip in $(cat Live_hosts); do
									ip_a=$ip
							echo		
							echo "[*] IP - ${ip_a}"
							cat ${ip_a}_vuln_high | grep -v POSTGRESQL
							echo "TOTAL CVSS HIGH - $(cat ${ip_a}_vuln_high | grep -v POSTGRESQL | wc -l)"
								done
								ip_a=ALL
							else
								ip_a=$what_ip
								echo "[*] IP - ${ip_a}"
								cat ${ip_a}_vuln_high | grep -v POSTGRESQL
								echo "TOTAL CVSS HIGH - $(cat ${ip_a}_vuln_high | grep -v POSTGRESQL | wc -l)"	
							fi
							echo
							echo "Would you like to apply another filter or exit to menu?"
							echo "1. Another filter"
							echo "2. Exit to menu"
							read filter_3
							echo
							case $filter_3 in
								1) break
								 ;;								
								2) break 2
								 ;;								
								*) echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							       continue
							    ;;
							esac
							done
						;;						
						4)
							while true; do
							echo -e "${MAGENTA}---------------${ENDCOLOR}"
							echo -e "${MAGENTA}CVSS - CRITICAL${ENDCOLOR}"
							echo -e "${MAGENTA}---------------${ENDCOLOR}"
							echo
							echo "[*] For more information press the link"
							if [ "$ip_a" = "ALL" ]; then
								for ip in $(cat Live_hosts); do
									ip_a=$ip
							echo		
							echo "[*] IP - ${ip_a}"
							cat ${ip_a}_vuln_critical | grep -v POSTGRESQL
							echo "TOTAL CVSS CRITICAL - $(cat ${ip_a}_vuln_critical | grep -v POSTGRESQL | wc -l)"
								done
								ip_a=ALL
							else
								ip_a=$what_ip
								echo "[*] IP - ${ip_a}"
								cat ${ip_a}_vuln_critical | grep -v POSTGRESQL
								echo "TOTAL CVSS CRITICAL - $(cat ${ip_a}_vuln_critical | grep -v POSTGRESQL | wc -l)"	
							fi
							echo
							echo "Would you like to apply another filter or exit to menu?"
							echo "1. Another filter"
							echo "2. Exit to menu"
							read filter_4
							echo
							case $filter_4 in
								1) break
								 ;;								
								2) break 2
								 ;;								
								*) echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							       continue
							    ;;
							esac
							done
						;;						
						5)
							while true; do
							echo "---------"
							echo "NO FILTER"
							echo "---------"
							echo
							echo "[*] For more information press the link"
							if [ "$ip_a" = "ALL" ]; then
								for ip in $(cat Live_hosts); do
									ip_a=$ip
							echo		
							echo "[*] IP - ${ip_a}"
							cat ${ip_a}_vuln | grep -v POSTGRESQL
							echo "TOTAL CVSS - $(cat ${ip_a}_vuln | grep -v POSTGRESQL | wc -l)"
								done
								ip_a=ALL
							else
								ip_a=$what_ip
								echo "[*] IP - ${ip_a}"
								cat ${ip_a}_vuln | grep -v POSTGRESQL
								echo "TOTAL CVSS - $(cat ${ip_a}_vuln | grep -v POSTGRESQL | wc -l)"	
							fi
							echo
							echo "Would you like to apply a filter or exit to menu?"
							echo "1. Filter"
							echo "2. Exit to menu"
							read filter_5
							echo
							case $filter_5 in
								1) break
								 ;;								
								2) break 2
								 ;;								
								*) echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							       continue
							    ;;
							esac
							done
							ip_a=ALL							
						;;						
						*)
							echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
							continue
						;;
					esac
					done		
			esac			
			echo
			echo "[*] Do you want to analyze anything else? (Y/N)"
			read anyelse
			case $anyelse in				
				y|Y)
					continue
				;;				
				n|N)
					break 2
				;;				
				*)
					echo -e "${RED}Invalid choice, continuing... ${ENDCOLOR}"
					break
				;;
			esac
		done				
		;;		
		n|N)
			cd ..
			return
		;;		
		*)
			echo "${RED}Invalid input. Try again. ${ENDCOLOR}" 
			continue			
		;;	
	esac
	done	
	cd ..	
}

function ORG() # Organize files and create a zip file
{
    cd "$dir_name"
    for ip in $(cat Live_hosts)
    do
        echo "[*] Orgnizing files..."
        mkdir -p "${ip}_res"
        if [ -f "$ip" ]; then
            mv "$ip" "${ip}_res/"
        fi
        
        if [ -f "${ip}_weak_passwords.txt" ]
        then
            mv "${ip}_weak_passwords.txt" "${ip}_res/"
        fi
            
        if [ -f "${ip}_services" ]
        then
            mv "${ip}_services" "${ip}_res/"
        fi
        
        if [ -f "${ip}_vuln" ]
        then
            mv "${ip}_vuln" "${ip}_res/"
        fi
        
        if [ -f "${ip}_vuln_low" ]
        then
            mv "${ip}_vuln_low" "${ip}_res/"
        fi
        
        if [ -f "${ip}_vuln_medium" ]
        then
            mv "${ip}_vuln_medium" "${ip}_res/"
        fi
        
        if [ -f "${ip}_vuln_high" ]
        then
            mv "${ip}_vuln_high" "${ip}_res/"
        fi
        
        if [ -f "${ip}_vuln_critical" ]
        then
            mv "${ip}_vuln_critical" "${ip}_res/"
        fi
     done        
     echo "[!]Finished organizing"
     echo
     echo -e "${GREEN}Each IP scanned got a folder containing the results${ENDCOLOR}"
	 cd ..
	 echo "Creating ZIP archive..."
	 echo
	 zip -r "${dir_name}.zip" "$dir_name"
	 echo -e "${GREEN}ZIP archive created${ENDCOLOR}"
	 echo
	 echo "======="
	 echo "GOODBYE"
	 echo "======="
}


ROOT
SCN_TYPE




















