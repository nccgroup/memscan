# memscan
Searches for strings, regex, credit card numbers of magnetic stripe card tracks in a process's memory space  

Memory/Process Scanner  
Written by Matt Lewis, NCC Group 2014  
Updated by Tom Watson, NCC Group 2015  
Thanks to Jesse Bullock for lots of great ideas  

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Matt Lewis and Tom Watson, matt [dot] lewis [at] nccgroup [dot] com & tom [dot] watson [at] nccgroup [dot] com

http://www.github.com/nccgroup/memscan

Released under AGPL, see LICENSE for more information

Synopsis - keeps scanning a process memory space for a search string (unicode and ascii), regex pattern, credit card data or magnetic stripe data then if found, spits these out either to stdout, a file or a socket to a remote listener

Useful for memory scraping a process, a post-exploitation POC or instrumentation tool to be used during fuzzing.  

TODO - Lots of duplicated code could be refactored out  

Code adapted from http://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory  
Original code licensed under CPOL: http://www.codeproject.com/info/cpol10.aspx  

# Usage

memscan  
    -string -s [pid] [Remote IP] [Remote Port] [delay] [width] [search term]    
    -string -f [pid] [filename] [delay] [width] [search term]  
    -string -o [pid] [delay] [width] [search term]  
    -regex -s [pid] [Remote IP] [Remote Port] [delay] [width] [regex]  
    -regex -f [pid] [filename] [delay] [width] [regex]  
    -regex -o [pid] [delay] [width] [regex]  
    -ccdata -s [pid] [Remote IP] [Remote Port] [delay]  
    -ccdata -f [pid] [filename] [delay]  
    -ccdata -o [pid] [delay]  
    -msdata -s [pid] [Remote IP] [Remote Port] [delay]  
    -msdata -f [pid] [filename] [delay]  
    -msdata -o [pid] [delay]  
    -proclist

Flag Definitions:  
    -string         search for string  
    -regex          search for regex pattern  
    -ccdata         search for credit card data  
    -msdata         search for magenetic stripe data  
    -s              write output to socket  
    -f              write output to a file  
    -o              write output to terminal  
    delay           time to wait between each memchunk scan  
    width           amount of data to display before and after search term  
    string          to look for in memory (spaces allowed)  
    regex           to look for in memory (e.g. 3[47][0-9]{13})
