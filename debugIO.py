#!/usr/bin/python3

import sys
from colorama import Fore

def DbgError(str, End="\n", File=sys.stdout): print(Fore.CYAN + "[!] " + Fore.RED + str + Fore.WHITE, end=End, file=File)

def DbgOut(str, End="\n", File=sys.stdout): print(Fore.CYAN + "[*] " + Fore.WHITE + str, end=End, file=File)

def DbgSuccess(str, End="\n", File=sys.stdout): print(Fore.CYAN + "[*] " + Fore.GREEN + str + Fore.WHITE, end=End, file=File)

def DbgIn(str, File=sys.stdout): return input(Fore.CYAN + "[?] " + Fore.WHITE + str, file=File)

def DbgTip(str, End="\n", File=sys.stdout): print(Fore.CYAN + "[?] " + Fore.WHITE + str, end=End, file=File)


def highlighter(inStr, pallette, defaultBrush=Fore.WHITE):

    inStr = defaultBrush + inStr
    for brush in pallette:
        for char in pallette[brush]: inStr = inStr.replace(char, brush + char + defaultBrush)
    return inStr + Fore.WHITE


def fmtHex(hexArr, fmt='{hexByte} '):
    
    retStr = ''
    for byte in hexArr:
        byteStr = hex(byte)[2:].rjust(2, "0")
        retStr += fmt.format(hexByte = byteStr)

    return retStr

