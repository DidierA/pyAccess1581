#!/usr/bin/env python
# coding: utf8

'''
    Copyright (C) 2019  Henning Pingel

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

'''

import ast
import re
import bitstring
import binascii
import hashlib
from access1581.arduinointerface import *
from access1581.diskformats import *

class IBMDoubleDensityFloppyDiskImager:
    '''
    loops over all 80 tracks using both heads
    and collects all the sector data of all tracks
    to store it into an image file
    '''
    def __init__( self, diskFormat, imagename, retries, serialDevice, storeBitstream = False, stopOnError=False):
        print ("pyAccess1581 - Copyright (C) 2019  Henning Pingel")
        print ("Reusing: Arduino Amiga Floppy Disk Reader/Writer Firmware - Copyright (C) 2019  Robert Smith")
        print ("Selected disk format is " + diskFormat.name + ", we expect " + str(diskFormat.expectedSectorsPerTrack) + " sectors per track")
        print ("Target image file is: " + imagename)
        print ("Serial device is: " + serialDevice)

        image = b''
        trackData = {}
        rawTracks = {}
        trackLength = diskFormat.expectedSectorsPerTrack * diskFormat.sectorSize
        if serialDevice == "simulated":
            with open('raw_debug_image_d81.py', 'r') as f:
                rawTrackData = ast.literal_eval(f.read())
            self.arduino = ArduinoSimulator(diskFormat, rawTrackData)
        else:
            self.arduino = ArduinoFloppyControlInterface(serialDevice, diskFormat)
        self.arduino.openSerialConnection()

        vldtr = self._getSingleTrackSectorListValidator( retries, diskFormat, storeBitstream, stopOnError )
        for trackno in diskFormat.trackRange:
            trackData[ trackno ] = {}
            rawTracks[ trackno ] = {}
            for headno in diskFormat.headRange:
                trackDataTmp = vldtr.processTrack( trackno, headno )
                if not len(trackDataTmp) == trackLength:
                    print ("ERROR track should have " + str(trackLength) + " bytes but has " + str(len(trackDataTmp)))
                trackData[ trackno ][ headno ] = trackDataTmp
                image += trackData[ trackno ][ headno ]
                if storeBitstream is True:
                    rawTracks[trackno][headno] = vldtr.getDecompressedBitstream()
        print ("Writing image to file " + imagename)
        with open(imagename, 'wb') as f:
            f.write( image)
        result = hashlib.md5(image)
        print("MD5   : " + result.hexdigest())
        result = hashlib.sha1(image)
        print("SHA1  : " + result.hexdigest())
        result = hashlib.sha256(image)
        print("SHA256: " + result.hexdigest())

        if storeBitstream is True:
            print ("Storing bitstream on disk")
            with open('raw_debug_image_d81.py', "w") as f:
                f.write(repr(rawTracks))
        vldtr.printSerialStats()
    
    def _getSingleTrackSectorListValidator(self,retries, diskFormat, storeBitstream, stopOnError):
        if issubclass(diskFormat.__class__, diskFormatAmiga):
            return SingleAmigaTrackSectorListValidator(retries, diskFormat, self.arduino, storeBitstream, stopOnError)
        else:
            return SingleIBMTrackSectorListValidator( retries, diskFormat, self.arduino, storeBitstream, stopOnError)

class SingleTrackSectorListValidator:
    '''
    asks track reader to read a specific track from disk (processTrack). gets
    structured data of all found sectors of one track. validates crc values and
    manages optional read retries.
    '''
    def __init__(self, retries, diskFormat, arduinoInterface, storeBitstream = False, stopOnError = False):
        self.maxRetries = retries
        self.diskFormat = diskFormat
        self.minSectorNumber = 1
        self.validSectorData = {}
        self.storeBitstream = storeBitstream
        self.decompressedBitstream = ""
        self.arduino = arduinoInterface
        self.trackParser = SingleIBMTrackSectorParser(self.diskFormat, self.arduino) # should be defined by subclass
        self.stopOnError = stopOnError
        self.printSectorDebugInfo = False

    def printSerialStats(self):
        self.trackParser.printSerialStats()

    def processTrack(self, trackno, headno):
        trackData = b''
        self.validSectorData = {}
        self.retries = self.maxRetries
        while self.retries > 0:
            if self.retries < self.maxRetries:
                print ("  Repeat track read - attempt " + str( self.maxRetries - self.retries +1 ) + " of " + str(self.maxRetries) )
            self.addValidSectors( self.trackParser.detectSectors(trackno, headno), trackno, headno, (self.retries == 1))
            #also make raw stream accessible for debug or other purposes
            self.decompressedBitstream = self.trackParser.getDecompressedBitstream()
            # print(self.decompressedBitstream)
            vsc = len(self.validSectorData)
            print (f"Reading track: {trackno:2d}, head: {headno}. Number of valid sectors found: {vsc}/{self.diskFormat.expectedSectorsPerTrack}")
            # print(f"len: {len(self.decompressedBitstream)}") # DEBUG
            if vsc == self.diskFormat.expectedSectorsPerTrack:
                self.retries = 0
            else:
                self.retries = self.retries -1
                # reposition the drive's head before trying again
                self.arduino.sendCommand("rewind")

        if len(self.validSectorData) == self.diskFormat.expectedSectorsPerTrack:
            for sectorno in sorted(self.validSectorData):
                if not len(self.validSectorData[sectorno]) == self.diskFormat.sectorSize * 2:
                    print("  Invalid sector data length." + str(len(self.validSectorData[sectorno])) )
                #print ("Adding sector no " + str(sectorno))
                trackData += binascii.unhexlify(self.validSectorData[sectorno])
        elif len(self.validSectorData) == 0:
            trackData = bytes(chr(0) * self.diskFormat.sectorSize * self.diskFormat.expectedSectorsPerTrack ,'utf-8')
            #print ("bytes: " + str(len(trackData)))
            print("  Notice: Filled up empty track with zeros.")
        else:
            print("  Not enough sectors found.")
        return trackData

    def getFirstSectorOffset(self):
        return self.trackParser.getFirstSectorOffset()

    def getDecompressedBitstream(self):
        return self.decompressedBitstream

    def getCRC(self, data):
        '''
        to calculate crc, we can either use binascii.crc_hqx(data, value) or crcmod
        where we have to import crcmod.predefined and install another module via pip

        the following code works fine with crcmod:
        xmodem_crc_func = crcmod.predefined.mkCrcFun('crc-ccitt-false')
        return hex(xmodem_crc_func( binascii.unhexlify(data)))[2:].zfill(4)
        '''
        return hex(binascii.crc_hqx(binascii.unhexlify(data), 0xffff))[2:].zfill(4)

    def isValidCRC(self, sectorprops):
        crc_data_check   = sectorprops["crc_data"] == self.getCRC( sectorprops["datameta"] + sectorprops["data"] )
        crc_header_check = sectorprops["crc_header"] == self.getCRC( sectorprops["headermeta"])
        return (crc_header_check and crc_data_check)

    def handleError(self, msg, sectorprops):
        if self.stopOnError is True:
            crcCheck = self.isValidCRC(sectorprops)
            self.printSectorDebugOutput(sectorprops, crcCheck)
            raise Exception( "  Error: " + msg )
        else:
            print ("  Error: " + msg)
            self.printSectorDebugInfo = True

    def addValidSectors(self, sectors, t, h, lastChance):
        self.printSectorDebugInfo = False
        printDebug = False
        for sectorprops in sectors:
            isSameTrack = True if sectorprops['trackno'] == t else False
            isSameHead  = True if sectorprops['sideno'] == h else False

            if isSameTrack is False:
                self.handleError( "Wrong track number: " + str(sectorprops["trackno"]), sectorprops )
            if isSameHead is False:
                self.handleError( "Wrong head/side number: "+ str(sectorprops["sideno"]) + " Please check that you chose the right disk format (swapsides?).",sectorprops )
            if int(sectorprops["sectorno"]) < self.minSectorNumber or \
                int(sectorprops["sectorno"]) > self.diskFormat.expectedSectorsPerTrack:
                self.handleError( "Sector number is out of expected bounds: "+ str(sectorprops["sectorno"]),sectorprops )

            crcCheck = self.isValidCRC(sectorprops)
            if not sectorprops["sectorno"] in self.validSectorData:
                if not sectorprops["sectorlength"] == 2:
                    self.handleError("Detected a non-512 byte sector length!",sectorprops)
                if crcCheck is False and lastChance is True:
                    print (f'  Invalid CRC for sector found, but adding sector data anyway: Head {h}, Track {t}, sector #{sectorprops["sectorno"]}')
                    self.printSectorDebugInfo = True
                if crcCheck is True or lastChance is True:
                    self.validSectorData[ sectorprops["sectorno"] ] = sectorprops["data"]
            #self.printSectorDebugInfo = True

            if self.printSectorDebugInfo is True:
                self.printSectorDebugOutput(sectorprops, crcCheck)

    def printSectorDebugOutput(self, sectorprops, crcCheck):
        infostring =""
        for prop in sectorprops:
            if prop != "datameta" and prop != "data" and prop != "headermeta":
                infostring += prop + ":" + str(sectorprops[prop]) + ", "
        infostring += "CRC check "
        infostring += "FAILED" if crcCheck is False else "SUCCESSFUL"
        print ("  DEBUGINFO - Sector properties: "+ infostring)

class SingleIBMTrackSectorListValidator(SingleTrackSectorListValidator):
    def __init__(self, retries, diskFormat, arduinoInterface, storeBitstream = False, stopOnError = False):
        super().__init__(retries, diskFormat, arduinoInterface, storeBitstream, stopOnError)
        self.trackParser = SingleIBMTrackSectorParser(self.diskFormat, self.arduino)
    
class SingleIBMTrackSectorParser:
    '''
    reads the requested track from the disk parses the data into complete
    sectors. discards incomplete sectors and returns data structure with all
    complete sectors of the track without doing crc validation yet.
    '''
    def __init__(self, diskFormat, arduinoFloppyControlInterface):
        self.diskFormat = diskFormat
        self.arduino = arduinoFloppyControlInterface
        self.sectorDataBitSize = self.diskFormat.sectorSize * 16
        self.decompressedBitstream = ""
        self.sectorStartMarkerLength = len(self.diskFormat.sectorStartMarker)
        self.firstSectorOffset = -1

    def detectSectors(self, trackno, headno):
        self.firstSectorOffset = -1
        cnt = 0
        sectors = []
        if self.diskFormat.swapsides is False:
            headno = 1 if headno == 0 else 0
        self.decompressedBitstream = self.arduino.getDecompressedBitstream(trackno, headno)
        (sectorMarkers, dataMarkers) = self.getMarkers()
        for sectorStart in sectorMarkers:
            if len(dataMarkers) <= cnt:
                pass
            elif dataMarkers[cnt] <= sectorStart:
                print ("Datamarker is being ignored. " + str( dataMarkers[cnt] ) + " " + str(sectorStart))
            else:
                sectors.append(self.parseSingleSector(sectorStart, dataMarkers[cnt]))
            cnt += 1
        return sectors

    def getDecompressedBitstream(self):
        return self.decompressedBitstream

    # MFM bit coding: 1 => 01, 0 =>  (10 if previous bit was 0, 00 otherwise).
    # So to decode, just keep every other bit:
    # 0100 will become 10, and so on. 
    def mfmDecode(self, stream):
        result = ""
        keep = False
        for char in stream:
            if keep is True:
                result += char
            keep = not keep
        return result

    def convertBitstreamBytes( self, data, flagHexInt ):
        if data == "":
            return ""
        ba = bitstring.BitArray('0b'+data )
        return ba.hex if flagHexInt is True else ba.int

    def grabSectorChunkHex( self, start, length):
        return self.convertBitstreamBytes( self.mfmDecode( self.currentSectorBitstream[ start: start+length ]), True)

    def grabSectorChunkInt( self, start, length):
        sfrom = start*8
        sto = sfrom + length*8
        return self.convertBitstreamBytes( self.mfmDecode( self.currentSectorBitstream[ sfrom: sto ]), False)

    def getMarkers(self):
        sectorMarkers = []
        dataMarkers = []
        dataMarkersTmp = []
        rawSectors = re.split( self.diskFormat.sectorStartMarker, self.decompressedBitstream)
        if len(rawSectors) > 0:
            self.firstSectorOffset = len( rawSectors[0] )
            del rawSectors[-1] #delete last entry
            previousBits = 0
            for rawSector in rawSectors:
                previousBits += len( rawSector ) + self.sectorStartMarkerLength
                sectorMarkers.append( previousBits )
        if len(sectorMarkers) > 0:
            dataMarkerMatchesIterator = re.finditer( self.diskFormat.sectorDataStartMarker, self.decompressedBitstream)
            for dataMarker in dataMarkerMatchesIterator:
                (startPosDataMarker, endPosDataMarker) = (dataMarker.span() )
                if endPosDataMarker >= sectorMarkers[0] + self.diskFormat.legalOffsetRangeLowerBorder:
                    dataMarkersTmp.append(endPosDataMarker)
                #else:
                #    print("Notice: Ignoring datamarker - is in front of first sector marker")
            cnt = 0
            for dataMarker in dataMarkersTmp:
                offset = dataMarker - sectorMarkers[cnt]
                if not offset in self.diskFormat.legalOffsetRange:
                    print ("getMarkers / Unusual offset found: "+str(offset))
                #now we check if the sector's data might be cut off at the end
                #of the chunk of the track we have, the added 32 represents
                #the length of the CRC checksum of the sector data
                overshoot = dataMarker + self.sectorDataBitSize + 32
                if overshoot <= len( self.decompressedBitstream ):
                    dataMarkers.append( dataMarker )
                    cnt+=1
                else:
                    #print("Removing sector marker because it overshot the bitstream")
                    sectorMarkers.remove(sectorMarkers[cnt])
        # print (sectorMarkers)
        # print (dataMarkers)
        return (sectorMarkers, dataMarkers)

    def getFirstSectorOffset(self):
        if self.firstSectorOffset == -1:
            raise Exception("Don't call getFirstSectorOffset before parsing the track")
        return self.firstSectorOffset

    def parseSingleSector(self, sectorStart, dataMarker):
        prelude = 4 * 16 # a1a1a1fe or a1a1a1fb
        dataMarker = prelude + dataMarker - sectorStart
        self.currentSectorBitstream = self.decompressedBitstream[sectorStart - prelude : sectorStart + self.sectorDataBitSize + 32 + dataMarker]
        #rawMfmDecoded = self.mfmDecode( self.currentSectorBitstream)
        #rdl = len(rawMfmDecoded)
        #rawstream = self.convertBitstreamBytes( rawMfmDecoded[0:int(rdl/4)*4], True)

        return {
            "headermeta"   : self.grabSectorChunkHex(  0, 128),#complete raw header data for crc check
            "trackno"      : self.grabSectorChunkInt(  8,  2),
            "sideno"       : self.grabSectorChunkInt( 10,  2),
            "sectorno"     : self.grabSectorChunkInt( 12,  2),
            "sectorlength" : self.grabSectorChunkInt( 15,  1),
            "crc_header"   : self.grabSectorChunkHex( 128, 32),
            "datameta"     : self.grabSectorChunkHex( dataMarker - prelude, prelude), #a1a1a1fb
            "data"         : self.grabSectorChunkHex( dataMarker, self.sectorDataBitSize),
            "crc_data"     : self.grabSectorChunkHex( dataMarker + self.sectorDataBitSize, 32)
        }

    def printSerialStats(self):
        (tdtr,tdtc,tdtd) = self.arduino.getStats()
        print ( "Total duration of all track reads   : " + tdtr + " seconds")
        print ( "Total duration other serial commands: " + tdtc + " seconds")
        print ( "Total duration of all decompressions: " + tdtd + " seconds")

class SingleAmigaTrackSectorListValidator(SingleTrackSectorListValidator):
    def __init__(self, retries, diskFormat, arduinoInterface, storeBitstream = False, stopOnError = False):
        super().__init__(retries, diskFormat, arduinoInterface, storeBitstream, stopOnError)
        self.minSectorNumber = 0
        self.trackParser = SingleAmigaTrackSectorParser(self.diskFormat, self.arduino)

    def isValidCRC(self,sectorprops):
        return sectorprops['crc_data']==sectorprops['computed_crc_data'] and sectorprops['crc_header']==sectorprops['computed_crc_header']

    def printSectorDebugOutput(self, sectorprops, crcCheck):
        # Content of a sector:
        # trackno => track number (0-82)
        # sideno => side number [0-1]
        # sectorno => sector number
        # crc_header => header checksum (read on disk)
        # computed_crc_header => header checksum (computed)
        # crc_data => data checksum (read from disk)
        # computed_crc_data => data checksum (computed)
        # data => data contents
        infostring =""
        for prop in sectorprops:
            if prop != "data":
                infostring += prop + ":" + str(sectorprops[prop]) + ", "
        infostring += "CRC check "
        infostring += "FAILED" if crcCheck is False else "SUCCESSFUL"
        print ("  DEBUGINFO - Sector properties: "+ infostring)
    
    def addValidSectors(self, sectors, t, h, lastChance):
        self.printSectorDebugInfo = False
        printDebug = False
        for sectorprops in sectors:
            isSameTrack = True if sectorprops['trackno'] == t else False
            isSameHead  = True if sectorprops['sideno'] == h else False

            if isSameTrack is False:
                self.handleError( "Wrong track number: " + str(sectorprops["trackno"]), sectorprops )
            if isSameHead is False:
                self.handleError( "Wrong head/side number: "+ str(sectorprops["sideno"]) + " Please check that you chose the right disk format (swapsides?).",sectorprops )
            if int(sectorprops["sectorno"]) < self.minSectorNumber or \
                int(sectorprops["sectorno"]) >= self.diskFormat.expectedSectorsPerTrack:
                self.handleError( "Sector number is out of expected bounds: "+ str(sectorprops["sectorno"]),sectorprops )

            crcCheck = self.isValidCRC(sectorprops)
            if not sectorprops["sectorno"] in self.validSectorData:
                if crcCheck is False and lastChance is True:
                    print (f'  Invalid CRC for sector found, but adding sector data anyway: Head {h}, Track {t}, sector #{sectorprops["sectorno"]}')
                    self.printSectorDebugInfo = True
                if crcCheck is True or lastChance is True:
                    self.validSectorData[ sectorprops["sectorno"] ] = sectorprops["data"]
            #self.printSectorDebugInfo = True # DEBUG

            if self.printSectorDebugInfo is True:
                self.printSectorDebugOutput(sectorprops, crcCheck)

class SingleAmigaTrackSectorParser(SingleIBMTrackSectorParser):
    def amigaMFMDecode(self, stream: str, *argv) -> bitstring.BitArray:
        '''
        Decodes AMIGA MFM as described here : http://lclevy.free.fr/adflib/adf_info.html#p24
        data is stored in two halves, odd bits first, and even bits after.
        input: stream: str containing the encoded track data
        optional arg: checksum (of type bitsting.BitArray). If present, will be xored with the checksum of the decoded data.
        returns ( decodeData, checksum)
        '''

        assert len(stream) % 4 == 0 , 'stream must be even'
        data_size=int(len(stream)/2)

        # checksum=bitstring.BitArray('0b' + '0'*32)
        odd = bitstring.BitArray('0b' + stream[0:data_size])
        even = bitstring.BitArray('0b' + stream[data_size:])
        mask = bitstring.BitArray('0b' + '01' * int(data_size/2))

        # calculate checksum. derived from the method used ADFWriter.cpp :
        # https://github.com/RobSmithDev/ArduinoFloppyDiskReader/blob/master/ArduinoFloppyReader/lib/ADFWriter.cpp
        if (len(argv)>0):
            checksum=argv[0]
            for i in range(0,data_size,32): # divide in longs (=4 bytes)
                checksum ^= odd[i:i+32]
                checksum ^= even[i:i+32]

            checksum &= mask[0:32]

        # decode data
        odd &= mask 
        odd <<= 1 # shift left
        even &= mask 
        decoded = odd | even

        return decoded

    def getMarkers(self):
        '''
        searches sector starts in the read data
        returns offsets of the sector info and data in the bitstream. 
        '''
        sectorMarkers = []
        dataMarkers = []
        rawSectors = re.split( self.diskFormat.sectorStartMarker, self.decompressedBitstream)
        if len(rawSectors) > 0:
            self.firstSectorOffset = len( rawSectors[0] )
            del rawSectors[-1] #delete last entry
            previousBits = 0
            for rawSector in rawSectors:
                previousBits += len( rawSector ) + self.sectorStartMarkerLength
                # check if we have enough data
                if len(self.decompressedBitstream[previousBits-8:]) < 544*2*8:
                    break
                sectorMarkers.append( previousBits )
                dataMarkers.append(previousBits+28*8*2) # start of data offset
        
        #print (sectorMarkers) # DEBUG
        #print (dataMarkers) # DEBUG
        return (sectorMarkers, dataMarkers)
    
    def parseSingleSector(self, sectorStart, dataMarker):
        '''
        Reads a single sector        
        Returns the sector's contents in a dict
        '''
        offset=sectorStart
        sector= {}
        # dict: content of a sector
        # trackno => track number (0-79)
        # sideno => side number [0-1]
        # sectorno => sector number
        # crc_header => header checksum (read on disk)
        # computed_crc_header => header checksum (computed)
        # crc_data => data checksum (read from disk)
        # computed_crc_data => data checksum (computed)
        # data => data contents
        
        # following is according to http://lclevy.free.fr/adflib/adf_info.html#p23

        # We compute and store checksums while decoding data.
        # Checksum validity will be checked later
        current_checksum=bitstring.BitArray(int=0,length=32)

        # Header info: long (4 bytes) at offset 0x08
        info=self.amigaMFMDecode(self.decompressedBitstream[offset:offset+64], current_checksum) # 64 bits MFM encoded => 32 bits of sector header info

        check,track_no,sector_no,sectors_left=info.unpack('uint:8,'*3+'uint:8')
        # track_no on disk is 0 to 159 for (0,side 0) to (79,side 1)
        sector['sideno']=track_no % 2
        sector['trackno']= int(track_no / 2)
        sector['sectorno']=sector_no
        
        # assert(check == 255), 'invalid info'
        # assert(sector_no+sectors_left==11), 'invalid info'
        
        offset+=4*8*2 # 4 bytes * 8bits *2(1 bit is 2 mfm encoded)

        # Sector label: 4 longs at offset 0x10 (usually full of zeroes)
        label=self.amigaMFMDecode(self.decompressedBitstream[offset:offset+(32*8)], current_checksum)
        sector['computed_crc_header']= current_checksum.hex

        offset+= 4*4*8*2 # 4 longs = 4*4 bytes

        # Header checksum: long at offset 0x30
        header_checksum=self.amigaMFMDecode(self.decompressedBitstream[offset:offset+(32*2)])
        sector['crc_header']=header_checksum.hex

        offset +=4*8*2 

        # Data checksum: long at offset 0x38
        data_checksum=self.amigaMFMDecode(self.decompressedBitstream[offset:offset+(32*2)])
        sector['crc_data']=data_checksum.hex
        
        offset +=4*8*2

        current_checksum=bitstring.BitArray(int=0,length=32)
        # Data: 512 bytes at offset 0x40
        data=self.amigaMFMDecode(self.decompressedBitstream[offset:offset+(512*8*2)],current_checksum)
        sector['data']=data.hex
        sector['computed_crc_data']=current_checksum.hex

        offset += 512*8*2

        return sector 
