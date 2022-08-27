#!/bin/bash

#Author: Martin
#Date: 29/07/2022

#Description
#Analyzes mem/hdd files and carves them if needed (hdd)

#Usage: anlyz.sh <func> <file>

function HDD #the HDD func
{
	echo "[>>] Analyzing and extracting the file $1..." # 3 - way extractor to not miss any little bit of information // 2>/dev/null to minimize the output and not flood the terminal with unnecessary information.
binwalk -eq $1 --directory=$1.file1 2>/dev/null
bulk_extractor $1 -o $1.file2 2>/dev/null
foremost $1 -t all -o $1.file3 2>/dev/null
mkdir $1.filemaster 2>/dev/null
strings $1 2>/dev/null > $1.file4 #strings to not miss any readable info on the raw file
mv $1.file* $1.filemaster 2>/dev/null #filemaster where all of the above will be moved to
echo "Status report! " | tee ext.sum  #Report about some info of the extraction and analyzing | tee to show on terminal + save
echo "The items found in file 1 are $(ls -r $1.filemaster/$1.file1/_$1.extracted | grep .jpg | wc -w) JPG files and $(ls -r $1.filemaster/$1.file1/_$1.extracted | grep .zip | wc -w) zip files! " | tee -a ext.sum
echo "The items found in file 2 are $(ls -r $1.filemaster/$1.file2/jpeg_carved/* | wc -w ) JPG files and $(ls -r $1.filemaster/$1.file2/zip/* | wc -w) zip files! " | tee -a ext.sum
echo "The items found in file 3 are $(ls -r $1.filemaster/$1.file3/jpg/* | wc -w ) JPG files and $(ls -r $1.filemaster/$1.file3/zip/* | wc -w) zip files! " | tee -a  ext.sum
} 

function MEM #the mem func
{
	echo "[>>]Analyzing The file $1..."
	#5 commands to give info about to mem file
	figlet "_-Imageinfo-_" > mem.ext
	./vol -f $1 imageinfo 2>/dev/null >> mem.ext
	OS=$(grep -i profile mem.ext | awk '{print $4}' | cut -d ',' -f 1) #an option of dynamic os to work with all sorts of mem files
	while read i
	do
	figlet $i >> mem.ext
	./vol -f $1 --profile=$OS $i 2>/dev/null >> mem.ext
done < volcom.txt #This file contains the following commands : pslist , pstree , psscan , dlllist , privs , modules , driverscan , connscan , hivescan .
	echo "Analyzer mem status Report! " | tee  mem.sum #Report about some info of the extraction and analyzing | tee to show on terminal + save
echo "There are $(expr $(./vol -f $1 --profile=$OS pslist 2>/dev/null  | wc -l) - 2) items in the Pslist! " | tee -a mem.sum
echo "There are $(expr $(./vol -f $1 --profile=$OS pstree 2>/dev/null  | wc -l) - 2) items in the Pstree! " | tee -a mem.sum
echo "There are $(expr $(./vol -f $1 --profile=$OS modules 2>/dev/null  | wc -l) - 2) items in the Modules! " | tee -a mem.sum
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
