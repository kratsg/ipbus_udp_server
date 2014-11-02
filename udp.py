from __future__ import print_function

import socket
import struct
from config import *
import textwrap

'''
================================================
                    HELPERS
================================================
'''
def errStrOnFalsey(booly):
  global UNICODE
  return "" if booly else UNICODE['error']

def hexToBin(hex_val, numBits=8):
  return ' '.join(chunks(bin(int(hex_val, 16))[2:].zfill(numBits), 8))

# used by decodePacketHeader and decodeTransactionHeader 
def reportHexVal(hex_val, flagError=True, parseFunction=None, numBits=8):
  if parseFunction is None:
    parseFunction_out = ''
  else:
    parseFunction_out = parseFunction(hex_val)
  return "{}\t{}\t{:<16}\t{}".format(errStrOnFalsey(flagError), hex_val, hexToBin(hex_val, numBits=numBits), parseFunction_out)

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def printBreakdown(**kwargs):
    global PRINT_LENGTH, COLORS
    outStr = []
    dumpStr = "|{{:<{:d}}}|".format(PRINT_LENGTH-2)

    words = kwargs.get('words', [])
    indentLevel = kwargs.get('indentLevel', 0)  # default to 0
    addr = kwargs.get('addr', ('127.0.0.1',8000))  # default address and port
    inbound = kwargs.get('inbound', True)  # assume inbound

    outStr.append("="*PRINT_LENGTH)
    outStr.append(dumpStr.format("{0:s}{1:s} Message{0:s}".format("-"*(PRINT_LENGTH/2 - 9), "Inbound " if inbound else "Outbound")))
    # print inbound or outbound
    outStr.append(dumpStr.format("    From: {:s}".format(addr)))
    outStr.append(dumpStr.format("    Data"))
    for i, word in enumerate(words):
      outStr.append(dumpStr.format("     |- Word {:d}    {:s}".format(i, word)))
    outStr.append(dumpStr.format("     ---------------------"))
    outStr.append("="*PRINT_LENGTH)
    print(("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(outStr))
    return True

def printPacketDetails(packet, indentLevel=0):
  print(("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(packet['str']))
  return True

def printPacketsBreakdown(packets, indentLevel=0):
  outStr = []
  for i,v in enumerate(packets):
    binNumber = ' '.join(chunks(bin(int(v, 16))[2:].zfill(32), 8))
    outStr.append("Word {:d} = {:s}".format(i, v))
    outStr.append("\t{:s}".format(binNumber))
  print(("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(outStr))
  return True

'''
================================================
                    ENDIANS
================================================
'''
def raiseEndianWarning():
  global FLAG_LITTLE_ENDIAN, UNICODE, PRINT_LENGTH
  wrapper = textwrap.TextWrapper(subsequent_indent="{}\t".format(UNICODE['warning']), width=PRINT_LENGTH)
  if FLAG_LITTLE_ENDIAN is True:
    sentence = (COLORS.WARNING+"{} Warning: byte-order Little endian was detected! Will implicitly flip all words when decoding and flip back when encoding."+COLORS.END).format(UNICODE['warning'])
    print(wrapper.fill(sentence))

def checkEndian(packet_header):
  global FLAG_LITTLE_ENDIAN, PACKET_HEADER_FORMAT
  start, end = PACKET_HEADER_FORMAT['byte-order_qualifier']
  FLAG_LITTLE_ENDIAN = bool(packet_header[start:end] is not 'f')
  raiseEndianWarning()

# flip the word if globally required, can be overrided with `flip`
def flipEndian(word, flipOverride=False):
  global FLAG_LITTLE_ENDIAN, UNICODE

  if flipOverride:
    print("{} Overriden: Flipping endian-ness of word".format(UNICODE['warning']))

  if FLAG_LITTLE_ENDIAN is None and not flipOverride:
    ValueError('FLAG_LITTLE_ENDIAN is unset. Run checkEndian() on the packet header')
    return word
  elif FLAG_LITTLE_ENDIAN is True or flipOverride:
    return ''.join(list(chunks(word, 2))[::-1])
  else:
    # do nothing, no flip needed
    return word

'''
================================================
                    DECODERS
================================================
'''
def decodePacketType(val):
  global PACKET_TYPE_VALUES
  hex_val = val['packet_type'] if 'packet_type' in val else val
  return PACKET_TYPE_VALUES.get(hex_val, 'reserved')

def decodeTransactionType(val):
  global TRANSACTION_TYPE_VALUES
  hex_val = val['type_id'] if 'type_id' in val else val
  return TRANSACTION_TYPE_VALUES.get(hex_val, '?')

def decodeTransactionInfoCode(val):
  global TRANSACTION_INFO_CODE_VALUES
  hex_val = val['info_code'] if 'info_code' in val else val
  return TRANSACTION_INFO_CODE_VALUES.get(hex_val, 'reserved')

def decodePacketHeader(word):
    global REQUIRE_PROTOCOL_VERSION, PACKET_HEADER_FORMAT
    word = flipEndian(word)
    parsedWord = {}
    for k,v in PACKET_HEADER_FORMAT.iteritems():
      parsedWord[k] = word[v[0]:v[1]]

    outStr = []
    outStr.append("(4b)  Protocol Version")
    outStr.append(reportHexVal(parsedWord['protocol_version'], flagError=(parsedWord['protocol_version']==REQUIRE_PROTOCOL_VERSION), numBits=4))
    outStr.append("(4b)  Reserved")
    outStr.append(reportHexVal(parsedWord['reserved'], flagError=(parsedWord['reserved']=='0'), numBits=4))
    outStr.append("(16b) Packet ID")
    outStr.append(reportHexVal(parsedWord['packet_id'], numBits=16))
    outStr.append("(4b)  Byte-order qualifier")
    outStr.append(reportHexVal(parsedWord['byte-order_qualifier'], parseFunction=(lambda x: 'big endian-ness' if x == 'f' else 'little endian-ness'), numBits=4))
    outStr.append("(4b)  Packet Type")
    outStr.append(reportHexVal(parsedWord['packet_type'], flagError=(parsedWord['packet_type']!='3'), parseFunction=decodePacketType, numBits=4))
    parsedWord['str'] = outStr
    return parsedWord

def decodeTransactionHeader(word, checkOutboundRequest=True):
    global REQUIRE_PROTOCOL_VERSION, TRANSACTION_HEADER_FORMAT
    word = flipEndian(word)
    parsedWord = {}
    for k,v in TRANSACTION_HEADER_FORMAT.iteritems():
      parsedWord[k] = word[v[0]:v[1]]

    outStr = []
    outStr.append("(4b)  Protocol Version")
    outStr.append(reportHexVal(parsedWord['protocol_version'], flagError=(parsedWord['protocol_version']==REQUIRE_PROTOCOL_VERSION), numBits=4))
    outStr.append("(12b) Transaction ID")
    outStr.append(reportHexVal(parsedWord['transaction_id'], numBits=12))
    outStr.append("(8b)  Words")
    outStr.append(reportHexVal(parsedWord['words'], parseFunction=(lambda x: "N={} 32-bit words in addressable memory space".format(int(x, 16))), numBits=8))
    outStr.append("(4b)  Type ID")
    outStr.append(reportHexVal(parsedWord['type_id'], parseFunction=decodeTransactionType, numBits=4))
    outStr.append("(4b)  Info Code")
    outStr.append(reportHexVal(parsedWord['info_code'], flagError=(parsedWord['info_code']=='f' or not checkOutboundRequest), parseFunction=decodeTransactionInfoCode, numBits=4))
    parsedWord['str'] = outStr
    return parsedWord

'''
================================================
                    ENCODERS
================================================
'''

def encodeWord(WORD_FORMAT, **kwargs):
  ''' Given a WORD_FORMAT (such as PACKET_HEADER_FORMAT)
       return the word in appropriate format (little or big endian)
       based on the format defined with the ordering
   - Precendence of setting value in a word is by:
         - kwargs['key']
         - word['key']
         - '0' (default!)
    If no kwargs are set other than kwargs['word'], then a copy of kwargs['word'] is used.
  '''

  global WORD_LENGTH
  word = kwargs.get('word', {})
  outbound_word = ['']*WORD_LENGTH*2  # put in hex
  for k,v in WORD_FORMAT.iteritems():
    outbound_word[v[0]:v[1]] = kwargs.get(k, word.get(k, '0'))
  return flipEndian(''.join(outbound_word))

'''
================================================
                 ACTUAL SCRIPT
================================================
'''
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

def controlHandler(words):
  parsed_transactionData = decodeTransactionHeader(words[0])
  print("Transaction Details")
  printPacketDetails(parsed_transactionData, indentLevel=1)
 
  print("Responding to Control Request")
  responsePackets = []
  responsePackets.append(encodeWord(TRANSACTION_HEADER_FORMAT, word=parsed_transactionData, info_code='0'))
  return responsePackets
 
def statusHandler(words):
  pass

def resendHandler(words):
  pass

packetTypeHandler = {'control (r/w)': controlHandler,
                     'status': statusHandler,
                     're-send': resendHandler}

while True:
    # listen for data, buffer size is 1024 bytes
    data, addr = sock.recvfrom(1024)
    # encode it in hex
    data = data.encode("hex")
    words = list(chunks(data,8))
    printBreakdown(words=words)

    # Step 0: determine endian-ness using packet header
    checkEndian(words[0])
    
    packetHeader = decodePacketHeader(words[0])
    print("Packet Header")
    printPacketDetails(packetHeader, indentLevel=1)

    packetType = decodePacketType(packetHeader)
    print("Handling Packet Type:", packetType)
    handler = packetTypeHandler.get(packetType, lambda: print("ValueError: unknown type"))
    responsePackets = handler(words[1:])  # return a list of response words

    # printPacketsBreakdown(words, indentLevel=1)

    responsePackets.insert(0, encodeWord(PACKET_HEADER_FORMAT, word=packetHeader))
    printBreakdown(words=responsePackets, inbound=False, addr=(UDP_IP, UDP_PORT))

    print("Sending", end="")
    sock.sendto((''.join(responsePackets)).decode("hex"), addr)
    print("... sent!")

