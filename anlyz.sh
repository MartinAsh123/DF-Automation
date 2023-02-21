#!/bin/bash

#Author: Martin

#Date: 21/02/2023

#Description

#Analyzes mem/hdd files and carves them if needed (hdd)

#Usage: anlyz.sh <func> <file>

function HDD #the HDD func

{

    echo "[>>] Analyzing and extracting the file $1..." 
    
    # 3 - way extractor to not miss any little bit of information // 2>/dev/null to minimize the output and not flood the terminal with unnecessary information.
	
    binwalk -eq $1 --directory=$1.bw 2>/dev/null

    bulk_extractor $1 -o $1.be 2>/dev/null

    foremost $1 -t all -o $1.fm 2>/dev/null

    mkdir $1.ext 2>/dev/null

    strings $1 2>/dev/null > $1.str #strings to not miss any readable info on the raw file
    
    for i in $(echo bw,be,fm,str | tr ',' '\n')
    
    do

       mv $1.$i $1.ext 2>/dev/null
       
    done

    echo "Status report! " | tee ext.sum  #Report about some info of the extraction and analyzing | tee to show on terminal + save
    
    for i in $(echo bw,be,fm | tr ',' '\n')
    
    do
    
       echo "The number of files found in $1.$i is $(expr $(ls -lr $1.ext/$1.$i | wc -l ) -1)"
       
    done
    
    echo "The number of lines found in $1.str is: $(wc -l $1.ext/$1.str) and the number of words is: $(wc -w $1.ext/$1.str)"
    
    echo "Here are all of the url's and ip addresses in the file!"
    
    cat $1.ext/$1.str | egrep -o "([0-9]{1,3}[.]){3}[0-9]{1,3}\|[http.]?[://]?\S+")
 
} 

function MEM #the mem func

{
	
    echo "pslist,pstree,psscan,dlllist,privs,modules,driverscan,connscan,hivescan" > volcom.txt
    
    sed -Ei 's/,/\n/g' volcom.txt
    
	echo "[>>]Analyzing The file $1..."
	
	figlet "_-Imageinfo-_" > mem.ext
	
	./vol -f $1 imageinfo 2>/dev/null >> mem.ext
	
	OS=$(grep -i profile mem.ext | awk '{print $4}' | cut -d ',' -f 1) #an option of dynamic os to work with all sorts of mem files
	
    for i in $(cat volcom.txt)
	
	do

	   figlet $i >> mem.ext
	      
	   ./vol -f $1 --profile=$OS $i 2>/dev/null >> mem.ext
	
    done
    
	echo "Analyzer mem status Report!" | tee  mem.sum #Report about some info of the extraction and analyzing | tee to show on terminal + save
	
	for i in $(cat volcom.txt)
	
	do
	
       echo "There are $(expr $(./vol -f $1 --profile=$OS $i 2>/dev/null  | wc -l) - 2) lines at the $i section! " | tee -a mem.sum
       
    done

    echo "There are $(./vol -f $1 --profile=$OS connscan 2>/dev/null  | egrep -o "([0-9]{1,3}[.]){3}[0-9]{1,3}" | wc -l) IPv4's found in the Connscan! " | tee -a mem.sum

    echo "Full info is located in the - mem.info file! for more details check it out! "

    echo " To see the full status report check the mem.analyzer file!"

}
echo "We are woking on $2! "

if [ $1 == "mem"  ]

   then 

       MEM $2

   elif [ $1 == "hdd" ] 

   then 

        HDD $2

   else

        echo "Wrong option! "

fi

exit 0
