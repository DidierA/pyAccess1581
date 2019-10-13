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

    CREDITS

    The class ArduinoFloppyControlInterface implements the interface that
    Robert Smith created for the Arduino Amiga Floppy disk reader/writer.
    Robert Smith has released his project under GPL V3. For more information,
    please visit http://amiga.robsmithdev.co.uk/

'''

from serial import Serial
import sys, re, time, platform, hashlib, os, binascii, ast, bitstring
from optparse import OptionParser

def main():
    try:
        starttime = time.time()
        launcher()
        duration = int((time.time() - starttime)*100)/100
        print  ("Estimated total duration            : " + str(duration) + " seconds")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise

class launcher:

    def __init__(self):
        #my default serial device addresses
        self.serialDeviceAddresses = {
            'Linux' : '/dev/ttyUSB0',
            'Windows' : 'COM5'
        }
        self.diskFormatTypes = {
            "cbm1581" : diskFormat1581,
            "ibmdos"  : diskFormatDOS
        }
        self.defaultDisktype = 'cbm1581'
        self.defaultOutputImageName = \
            'image_' + self.defaultDisktype + '.' + \
            self.diskFormatTypes[self.defaultDisktype]().imageExtension
        self.defaultRetries = 5

        parser = OptionParser("usage: %prog [options] arg")
        parser.add_option("-d", "--disktype",
            dest="disktype",
            help=self.getDocDiskType(),
            default=self.defaultDisktype
        )
        parser.add_option("-o", "--output",
            dest="outputImage",
            help="file path/name of image file to write to, default is "+self.defaultOutputImageName,
            default=self.defaultOutputImageName
        )
        parser.add_option("-s", "--serialdevice",
            dest="serialDeviceName",
            help="device name of the serial device, for example /dev/ttyUSB0 (use value 'simulated' to test functionality)",
            default=self.serialDeviceAddresses[ platform.system() ]
        )
        parser.add_option("-r", "--retries", dest="retries",
            help="number of retries to read disk track again after invalid CRC check, default: "+
            str(self.defaultRetries)+" retries",
            default=self.defaultRetries
        )
        (options, args) = parser.parse_args()

        if options.serialDeviceName != "simulated" and platform.system() != "Windows" and not os.path.exists(options.serialDeviceName):
            raise Exception( "Serial device does not exist: " + options.serialDeviceName )

        if not options.disktype in self.diskFormatTypes.keys():
            raise Exception("Error: disk format " + options.disktype +  " is unknown")
        diskFormat = self.diskFormatTypes[ options.disktype ]()
        options.storeBitstream = False #tmp debug
        IBMDoubleDensityFloppyDiskImager( diskFormat, options.outputImage, options.retries, options.serialDeviceName, options.storeBitstream )

    def getDocDiskType(self):
        dft = ''
        for type in self.diskFormatTypes.keys():
            defa = "" if type != self.defaultDisktype else " [default]"
            dft += type + defa + ", "
        dft = dft[0:len(dft)-2]
        return "type of DD disk in floppy drive: " + dft

class diskFormatRoot:
    def __init__(self):
        self.name                   = 'root'
        self.trackRange             = range(0,80) #0-79
        self.headRange              = range(0,2)  #0-1
        self.sectorSize             = 512 # bytes
        self.swapsides              = False
        self.sectorStartStringPrefix = ""
        self.sectorDataStartStringPrefix = ""
        self.imageExtension         = 'img'

class diskFormatDOS(diskFormatRoot):
    def __init__(self):
        super().__init__()
        self.name                   = 'ibmdos'
        self.sectorStartString      = "a1a1a1fe"
        self.sectorDataStartString  = "a1a1a1fb"
        self.expectedSectorsPerTrack = 9
        self.sectorStartStringPrefix = "000000000000"
        self.sectorDataStartStringPrefix = "00"

        self.sectorStartMarker = self.getFlexibleRegExString( self.sectorStartStringPrefix + self.sectorStartString)
        self.sectorDataStartMarker = self.getFlexibleRegExString( self.sectorDataStartStringPrefix + self.sectorDataStartString )
        self.sectorStartMarkerLength = len( self.sectorStartMarker )
        self.sectorDataStartMarkerLength = len( self.sectorDataStartMarker )
        self.legalOffsetRangeLowerBorder = 704
        self.legalOffsetRangeUpperBorder = 716
        self.legalOffsetRange = range(self.legalOffsetRangeLowerBorder,self.legalOffsetRangeUpperBorder+1)

        #TODO: check value 1320 *8 bits. 512 bytes as data content wrapped in
        #sector meta data bytes, 1320 is just a good guess that just works
        #maybe we can shrink it more
        self.sectorLength = 1320*8

    def getFlexibleRegExString( self, hexString ):
        searchKey = self.hexString2bitString( hexString )
        regExString = ""
        for bit in searchKey:
            regExString += "." + bit
        regExString = regExString[1:]
        return regExString

    def hexString2bitString(self, hexString ):
        bitString = ""
        for nibble in hexString:
            bitString += str(bin(int(nibble,16))[2:]).zfill(4)
        return bitString

class diskFormat1581(diskFormatDOS):
    def __init__(self):
        super().__init__()
        self.name                   = 'cbm1581'
        self.expectedSectorsPerTrack = 10
        self.swapsides              = True
        self.imageExtension         = 'd81'

class IBMDoubleDensityFloppyDiskImager:
    '''
    loops over all 80 tracks using both heads
    and collects all the sector data of all tracks
    to store it into an image file
    '''
    def __init__( self, diskFormat, imagename, retries, serialDevice, storeBitstream = False ):

        print ("Selected disk format is " + diskFormat.name + ", we expect " + str(diskFormat.expectedSectorsPerTrack) + " sectors per track")
        print ("Target image file is: " + imagename)
        print ("Serial device is: " + serialDevice)

        image = b''
        trackData = {}
        rawTracks = {}
        trackLength = diskFormat.expectedSectorsPerTrack * diskFormat.sectorSize
        vldtr = SingleTrackSectorListValidator( retries, diskFormat, serialDevice, storeBitstream )
        for trackno in diskFormat.trackRange:
            trackData[ trackno ] = {}
            rawTracks[ trackno ] = {}
            for headno in diskFormat.headRange:
                trackDataTmp = vldtr.processTrack( trackno, headno )
                if not len(trackDataTmp) == trackLength:
                    print ("ERROR track should have " + str(trackLength) + " bytes but has " + str(len(trackData)))
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
            with open('raw_debug_image_d81.py', "w") as f:
                f.write(repr(rawTracks))
        vldtr.printSerialStats()

class SingleTrackSectorListValidator:
    '''
    asks track reader to read a specific track from disk (processTrack). gets
    structured data of all found sectors of one track. validates crc values and
    manages optional read retries.
    '''
    def __init__(self, retries, diskFormat, serialDevice, storeBitstream = False):
        self.maxRetries = retries
        self.diskFormat = diskFormat
        self.minSectorNumber = 1
        self.validSectorData = {}
        self.storeBitstream = storeBitstream
        self.decompressedBitstream = ""
        if serialDevice == "simulated":
            self.arduino = ArduinoSimulator(diskFormat)
        else:
            self.arduino = ArduinoFloppyControlInterface(serialDevice, diskFormat)
        self.trackParser = SingleIBMTrackSectorParser(self.diskFormat, self.arduino)
        self.arduino.openSerialConnection()

    def printSerialStats(self):
        self.trackParser.printSerialStats()

    def processTrack(self, trackno, headno):
        trackData = b''
        self.validSectorData = {}
        self.retries = self.maxRetries
        while self.retries > 0:
            if self.retries < self.maxRetries:
                print ("  Repeat track read - attempt " + str( self.maxRetries - self.retries +1 ) + " of " + str(self.maxRetries) )
            self.addValidSectors( self.trackParser.detectSectors(trackno, headno), trackno, headno )
            if self.storeBitstream is True:
                self.decompressedBitstream = self.trackParser.getDecompressedBitstream()
            vsc = len(self.validSectorData)
            print (f"Reading track: {trackno:2d}, head: {headno}. Number of valid sectors found: {vsc}/{self.diskFormat.expectedSectorsPerTrack}")
            if vsc == self.diskFormat.expectedSectorsPerTrack:
                self.retries = 0
            else:
                self.retries = self.retries -1
        if len(self.validSectorData) == self.diskFormat.expectedSectorsPerTrack:
            for sectorno in sorted(self.validSectorData):
                if not len(self.validSectorData[sectorno]) == self.diskFormat.sectorSize * 2:
                    print("  Invalid sector data length." + str(len(self.validSectorData[sectorno])) )
                #print ("Adding sector no " + str(sectorno))
                trackData += binascii.unhexlify(self.validSectorData[sectorno])
        elif len(self.validSectorData) == 0:
            trackData = bytes(chr(0) * self.diskFormat.sectorSize * self.diskFormat.expectedSectorsPerTrack ,'utf-8')
            #print ("bytes: " + str(len(trackData)))
            print("  Notice: Filled up empty track with zeros.");
        else:
            print("  Not enough sectors found.");
        return trackData

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
        crc_data_check   = sectorprops["crc_data"] == self.getCRC( self.diskFormat.sectorDataStartString + sectorprops["data"] )
        crc_header_check = sectorprops["crc_header"] == self.getCRC( self.diskFormat.sectorStartString + sectorprops["header"])
        return (crc_header_check and crc_data_check)

    def addValidSectors(self, sectors, t, h):
        for sectorprops in sectors:
            isSameTrack = True if sectorprops['trackno'] == t else False
            if isSameTrack is False:
                raise Exception( "Error: Wrong track number: " + str(sectorprops["trackno"]) )
            isSameHead  = True if sectorprops['sideno'] == h else False
            if isSameHead is False:
                raise Exception( "Error: Wrong head/side number: "+ str(sectorprops["sideno"]) + " Please check that you chose the right disk format (swapsides?)." )

            if not sectorprops["sectorno"] in self.validSectorData:
                crcCheck = self.isValidCRC(sectorprops)
                #self.printSectorDebugOutput(sectorprops, crcCheck)
                if crcCheck is True:
                    if int(sectorprops["sectorno"]) >= self.minSectorNumber and int(sectorprops["sectorno"]) <= self.diskFormat.expectedSectorsPerTrack:
                        self.validSectorData[ sectorprops["sectorno"] ] = sectorprops["data"]
                    else:
                        raise Exception( "Sector number is out of expected bounds: "+ str(sectorprops["sectorno"]) )

    def printSectorDebugOutput(self, sectorprops, crcCheck):
        infostring =""
        for prop in sectorprops:
            if prop != "data" and prop != "crc_check":
                infostring += prop + ":" + str(sectorprops[prop]) + ", "
        infostring += "CRC check "
        infostring += "FAILED" if crcCheck is False else "SUCCESSFUL"
        print ("- "+ infostring)

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

    def detectSectors(self, trackno, headno):
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

    def mfmDecode(self, stream):
        result = ""
        keep = False;
        for char in stream:
            if keep is True:
                result += char
            keep = not keep
        return result

    def convertBitstreamBytes( self, data, flagHexInt ):
        if data is "":
            return ""
        ba = bitstring.BitArray('0b'+data )
        return ba.hex if flagHexInt is True else ba.int

    def grabSectorChunkHex( self, start, length):
        return self.convertBitstreamBytes( self.mfmDecode( self.currentSectorBitstream[ start: start+length ]), True)

    def grabSectorChunkInt( self, start, length):
        return self.convertBitstreamBytes( self.mfmDecode( self.currentSectorBitstream[ start: start+length ]), False)

    def getMarkers(self):
        sectorMarkers = []
        dataMarkers = []
        dataMarkersTmp = []
        rawSectors = re.split( self.diskFormat.sectorStartMarker, self.decompressedBitstream)
        del rawSectors[-1] #delete last entry
        previousBits = 0
        for rawSector in rawSectors:
            previousBits += len( rawSector ) + self.diskFormat.sectorStartMarkerLength
            sectorMarkers.append( previousBits )
        dataMarkerMatchesIterator = re.finditer( self.diskFormat.sectorDataStartMarker, self.decompressedBitstream)
        for dataMarker in dataMarkerMatchesIterator:
            (startPosDataMarker, endPosDataMarker) = (dataMarker.span() )
            if endPosDataMarker >= sectorMarkers[0] + self.diskFormat.legalOffsetRangeLowerBorder:
                dataMarkersTmp.append(endPosDataMarker)
            else:
                print("Ignoring datamarker - is in front of first sector marker")
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
        return (sectorMarkers, dataMarkers)

    def parseSingleSector(self, sectorStart, dataMarker):
        dataMarker = dataMarker - sectorStart
        self.currentSectorBitstream = self.decompressedBitstream[sectorStart : sectorStart + self.sectorDataBitSize + 32 + dataMarker]
        return {
            "trackno"      : self.grabSectorChunkInt(  0, 16),
            "sideno"       : self.grabSectorChunkInt( 16, 16),
            "sectorno"     : self.grabSectorChunkInt( 32, 16),
            "sectorlength" : self.grabSectorChunkInt( 56,  8),
            "crc_header"   : self.grabSectorChunkHex( 64, 32),
            "header"       : self.grabSectorChunkHex(  0, 64),#complete raw header data for crc check
            "data"         : self.grabSectorChunkHex( dataMarker, self.sectorDataBitSize),
            "crc_data"     : self.grabSectorChunkHex( dataMarker + self.sectorDataBitSize, 32)
        }

    def printSerialStats(self):
        (tdtr,tdtc,tdtd) = self.arduino.getStats()
        print ( "Total duration of all track reads   : " + tdtr + " seconds")
        print ( "Total duration other serial commands: " + tdtc + " seconds")
        print ( "Total duration of all decompressions: " + tdtd + " seconds")

class ArduinoFloppyControlInterface:
    '''
    implements the commands defined by Rob Smith's
    Arduino Amiga Floppy Disk Reader/Writer project
    these commands are sent to an Arduino via serial
    connection running with 2m baud
    compare sourcecode of ArduinoInterface.cpp at:
        https://github.com/RobSmithDev/ArduinoFloppyDiskReader/
        blob/master/ArduinoFloppyReader/lib/ArduinoInterface.cpp
    '''
    def __init__(self, serialDevice, diskFormat):
        self.serialDevice = serialDevice
        self.trackRange = diskFormat.trackRange
        self.hexZeroByte = bytes(chr(0),'utf-8')
        self.decompressMap = { 0: "", 1: "01", 2: "001", 3: "0001"}
        self.connectionEstablished = False
        self.isRunning = False
        self.serial = False
        self.currentTrack = 100
        self.currentHead = 2
        self.total_duration_trackread = 0
        self.total_duration_cmds = 0
        self.total_duration_decompress = 0
        self.cmd = {
            "version"     : ( b'?', "Detecting firmware version" ),
            "motor_on"    : ( b'+', "Switching motor on" ),
            "motor_off"   : ( b'-', "Switching motor off" ),
            "rewind"      : ( b'.', "Rewinding to track 0"),
            "head0"       : ( b'[', "Selecting head 0"),
            "head1"       : ( b']', "Selecting head 1"),
            "select_track": ( b'#', "Selecting track"), # not complete command without track number
            "read_track"  : ( b'<', "Reading track"),
            "read_track_from_index_hole" : ( b'<1', "Reading track from index hole"),  # combined command
            "read_track_ignoring_index_hole" : ( b'<0', "Instantly reading track"),  # combined command
            "write_track" : ( b'>', "Writing track"),
            "enable_write": ( b'~', "Enable writing"),
            "erase_track" : ( b'X', "Erasing track"),
            #"diagnostics" : ( b'&', "Launching diagnostics routines")
        }

    def __del__(self):
        if self.connectionEstablished is True:
            self.sendCommand("rewind")
            self.sendCommand("motor_off")
            self.isRunning = False
            self.serial.close()

    def openSerialConnection(self):
        self.serial = Serial( self.serialDevice, 2000000, timeout=None)
        self.connectionEstablished = True
        print ("Connection to microcontroller established via " + self.serialDevice )
        self.serial.reset_input_buffer()
        self.sendCommand("version")
        self.sendCommand("rewind")
        #print( self.serial.get_settings())

    def connectionIsUsable(self, cmd):
        executeCMD = False
        if cmd == "motor_off":
            self.isRunning = False
            executeCMD = True
        elif cmd == "motor_on":
            self.isRunning = True
            executeCMD = True
        elif self.isRunning is False: #and not cmd == "motor_on":
            self.sendCommand("motor_on")
            executeCMD = True
        elif self.isRunning is True:
            executeCMD=True
        return executeCMD

    def sendCommand(self, cmdname, param=b''):
        (cmd, label) = self.cmd[cmdname]
        if self.connectionEstablished is False:
            self.openSerialConnection()
        if cmdname == "version" or self.connectionIsUsable(cmdname) is True:
            starttime_serialcmd = time.time()
            #print ("...Processing cmd " + cmdname)
            self.serial.reset_input_buffer()
            maxRetries = 1
            retries = maxRetries
            while retries > 0:
                self.serial.write( cmd + param)
                reply = self.serial.read(1)
                if cmdname == "version":
                    firmware = self.serial.read(4)
                    print ("Firmware version on Arduino: " + str(firmware))
                duration_serialcmd = int((time.time() - starttime_serialcmd)*1000)/1000
                self.total_duration_cmds += duration_serialcmd
                if param != b'':
                    label2 = label + " " + str(param)
                else:
                    label2 = label
#                print  ("    Serial cmd duration:                            " + str(duration_serialcmd) + " seconds " + label2)
                if not reply == b'1':
                    retries = retries - 1
                    if retries == 0:
                        retries=0
                        raise Exception ( label2 + ": Something went wrong! Reply was " + str(reply))
                    else:
                        print ( "Retrying: " + label2 + ": Reply was " + str(reply))
                else:
                    retries = 0 #success
                    #print( "   " + label + ": OK")
        else:
            raise Exception ( label + ": Connection was not usable!")

    def selectTrackAndHead(self, track, head):
        if self.currentTrack != track:
            if not track in self.trackRange:
                raise Exception("Error: Track is not in range")
            trs = str(track) if track > 9 else '0'+str(track)
            btrack = bytes( trs,'utf-8' )
            self.sendCommand( "select_track", btrack )# Moving head to track
            self.currentTrack = track
        if self.currentHead != head:
            if head >= 0 and head < 2:
                self.sendCommand("head" + str(head))
                self.currentHead = head
            else:
                print ('ERROR: Head should be 0 or 1!')

    def getCompressedTrackData(self, track, head):
        self.selectTrackAndHead(track, head)
        starttime_trackread = time.time()
        #self.serial.write(self.cmd["read_track_from_index_hole"][0])
        self.serial.write(self.cmd["read_track_ignoring_index_hole"][0])
        #speedup for Linux where pyserial seems to be very optimized
        if platform.system() == "Linux":
            trackbytes = self.serial.read_until( self.hexZeroByte , 12200)
        else:
            trackbytes = self.serial.read(10380)
            self.serial.timeout = 0
            trackbytes = trackbytes + self.serial.readline()
            self.serial.timeout = None
        duration_trackread = int((time.time() - starttime_trackread)*1000)/1000
        self.total_duration_trackread += duration_trackread
#        print  ("    Track read duration:                            " + str(duration_trackread) + " seconds")
        tracklength = len(trackbytes)
        if tracklength < 10223:
            print ("Track length suspicously short: " + str(tracklength) + " bytes")
        return trackbytes

    def getDecompressedBitstream(self, track, head):
        compressedBytes = self.getCompressedTrackData(track, head)
        starttime_decompress = time.time()
        decompressedBitstream = ""
        #print( "Length of compressed bitstream: "+ str(len(compressedBitstream)) )
        for byte in compressedBytes:
            bits=bin(byte)[2:].zfill(8)
            for chunk in range(0,4):
                value=int(bits[chunk*2:chunk*2+2])&3
                if value > 3:
                    print ("ERROR decompressBitstream illegal value!")
                decompressedBitstream += self.decompressMap[value]

        duration_decompress = int((time.time() - starttime_decompress)*1000)/1000
#        print  ("    Decompress duration:                            " + str(duration_decompress) + " seconds")
        self.total_duration_decompress += duration_decompress
        return decompressedBitstream
        '''
        Looking for a way to performance-improve this method. Tried to
        experiment with bitstring.Bits(), but that appears to be way slower than
        the code used now. Will come back to this at some point in the future.
        Example code:
            self.decompressMap2 = { '0b00': '', '0b01': '01', '0b10': '001', '0b11': '0001'}
            b = bitstring.Bits(bytes = compressedBytes)
            for bits in b.cut(2):
                decompressedBitstream += self.decompressMap2[str(bits)]
        '''

    def getStats(self):
        tdtr = str(int(self.total_duration_trackread*100)/100)
        tdtc = str(int(self.total_duration_cmds*100)/100)
        tdtd = str(int(self.total_duration_decompress*100)/100)
        return (tdtr, tdtc, tdtd)

class ArduinoSimulator(ArduinoFloppyControlInterface):

    def __init__(self, diskFormat):
        super().__init__("bla", diskFormat)
        with open('raw_debug_image_d81.py', 'r') as f: self.rawTrackData = ast.literal_eval(f.read())

    def __del__(self):
        pass

    def openSerialConnection(self):
        pass

    def connectionIsUsable(self, cmd):
        return True

    def getDecompressedBitstream(self, track, head):
#        if head == 0:
#            time.sleep(1)
        return self.rawTrackData[track][head]

if __name__ == '__main__':
    main()
