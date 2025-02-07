#!/usr/bin/python3

import fileinput
import argparse
import sys
import os

base = 16

prefixes = ["0x", "0b", "0o"]

# hex strings are input raw hex
# is output

def hexOut(args, byteorder):
    
    if len(args) < 1:
        print("Usage: hexify.py [FILE...]", file=sys.stderr)
        return 2 

    input_lines = fileinput.input(args[-1])

    for output_line in input_lines:

        index = len(output_line) - len(output_line.lstrip())
        prefix = output_line[index:index + 2]

        if prefix in prefixes: base = 0
        else: base = 16
        
        try:

            outBytes = []
            for x in output_line.split():
                
                num = int(x, base)
                ext = 7 if num != 0 else 8

                outBytes += [num.to_bytes((num.bit_length() + ext) // 8, byteorder)]

            outBytes = b''.join(outBytes)
            # print(outBytes, file=sys.stderr)
            sys.stdout.buffer.write(outBytes)

        except: print("[!] error parsing line...", file=sys.stderr)
        
        sys.stdout.flush()

# hex

def hexIn(args, prefix):

    fmtHex = lambda char: hex(ord(char))[2:].rjust(2, "0")    
    if prefix: fmtHex = lambda char: "0x" + hex(ord(char))[2:].rjust(2, "0")

    if len(args) < 1:
        print("Usage: hexify.py [FILE...]", file=sys.stderr)

    input_lines = fileinput.input(args[-1])

    for output_line in input_lines:

        try: sys.stdout.write(' '.join(fmtHex(char) for char in output_line) + '\n')
        except: print("[!] error parsing ling...", file=sys.stderr)

        sys.stdout.flush()

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(add_help=False)
   
    parser.add_argument("-b", "--byteorder", default="big", type=str)
    parser.add_argument("-m", "--mode", default="output", type=str)
    parser.add_argument("-p", "--prefix", action="store_true")

    args, unknown = parser.parse_known_args()

    if args.mode == "output":
        try:
            sys.exit(hexOut(sys.argv[1:], args.byteorder))
        except KeyboardInterrupt: sys.exit()

    elif args.mode == "input":
        try:
            sys.exit(hexIn(sys.argv[1:], args.prefix))
        except KeyboardInterrupt: sys.exit()
