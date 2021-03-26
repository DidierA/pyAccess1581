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

import time, platform
from serial import Serial

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
        self.ignoreIndexPulse = False # more conservative and slower but works
        self.isRunning = False
        self.serial = False
        self.currentTrack = 100 #invalid value on purpose
        self.currentHead = 2 #invalid value on purpose
        self.total_duration_trackread = 0
        self.total_duration_cmds = 0
        self.total_duration_decompress = 0
        self.cmd = {
            "version"        : ( b'?', "Detecting firmware version" ),
                #returns firmware version, currently V1.3
            "motor_on_read"  : ( b'+', "Switching motor on in read mode" ),
                #if motor was already running it will be first switched off
                #and on again, an active write mode will be disabled
            "motor_on_write" : ( b'~', "Switching motor on in write mode"),
                #if motor was already running it will be switched off
                #and on again, write mode will be enabled
            "motor_off"      : ( b'-', "Switching motor off" ),
            "rewind"         : ( b'.', "Rewinding to track 0"),
            "head0"          : ( b'[', "Selecting head 0"),#lower disk side
            "head1"          : ( b']', "Selecting head 1"),#upper disk side
            "select_track"   : ( b'#', "Selecting track"),
                # incomplete without two digit track number
                #"read_track"     : ( b'<', "Reading track"),
            "read_track_from_index_pulse" : ( bytes( '<' + chr(1),'utf-8'), "Reading track from index pulse"),  # combined command
            "read_track_ignoring_index_pulse" : ( bytes( '<' + chr(0),'utf-8'), "Instantly reading track"),  # combined command
            "write_track"    : ( b'>', "Writing track"),
            "erase_track"    : ( b'X', "Erasing track"), # fills track with 0xAA
            "diagnostics" : ( b'&', "Launching diagnostics routines")
        }

    def __del__(self):
        if self.connectionEstablished is True:
            self.sendCommand("rewind")
            self.sendCommand("motor_off")
            self.isRunning = False
            self.serial.close()

    def setIgnoreIndexPulse(self, b ):
        self.ignoreIndexPulse = b

    def openSerialConnection(self):
        self.serial = Serial( \
            self.serialDevice, \
            2000000, \
            timeout=5, \
            exclusive=True, \
            rtscts=True
            #bytesize=Serial.EIGHTBITS \
        )
        self.connectionEstablished = True
        print ("Connection to microcontroller established via " + self.serialDevice )
        print ("Waiting 2s for Arduino to wake up")
        time.sleep(2)
        # self.serial.reset_input_buffer()
        # self.serial.rtscts = True
        self.sendCommand("version")
        self.sendCommand("rewind")
        #print( self.serial.get_settings())

    def connectionIsUsable(self, cmd):
        executeCMD = False
        if cmd == "motor_off":
            self.isRunning = False
            executeCMD = True
        elif cmd == "motor_on_read" or cmd == "motor_on_write":
            self.isRunning = True
            executeCMD = True
        elif self.isRunning is False:
            self.sendCommand("motor_on_read")
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
            #print ("...Processing cmd '" + cmdname+ "'")
            self.serial.reset_input_buffer()
            self.serial.reset_output_buffer()
            print ('Sending ' + repr(cmd+param))
            self.serial.write( cmd + param)
            reply = self.serial.read(1)
            print('Received ' + repr(reply))
            if cmdname == "version":
                firmware = self.serial.read(4)
                print ("Firmware version on Arduino: " + str(firmware))
            duration_serialcmd = int((time.time() - starttime_serialcmd)*1000)/1000
            self.total_duration_cmds += duration_serialcmd
            if param != b'':
                label2 = label + " " + str(param)
            else:
                label2 = label
            if not reply == b'1':
                if cmdname == "motor_on_write":
                    raise Exception ( label2 + ": Something went wrong! Disk is probably write protected!")
                else:
                    raise Exception ( label2 + ": Something went wrong! Reply was " + str(reply))
        else:
            raise Exception ( label + ": Connection was not usable!")

    def testCTS(self):
        print ("Starting CTS self test (diagnostics), please wait...")
        self.sendCommand("motor_on_read")
        self.serial.rtscts = False
        for a in range(1, 10):
            p = b'2' if a % 2 == 0 else b'1'
            self.sendCommand("diagnostics", p)
            #time.sleep(1)
            ctsState = self.serial.cts
            print( "Toggling CTS by sending diagnostics cmd + " + str(p) + " / State of CTS line: " + str(ctsState))
            self.sendCommand("diagnostics")
            if (ctsState is True and p == b'2') or (ctsState is False and p == b'1'):
                raise Exception("Unexpected CTS state!")
            #time.sleep(1)
        print ("CTS test was successful.")

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

    def handleWriteProtection(self):
        writingAllowed = self.serial.read(1)
        isWriteProtected = False if writingAllowed == b'Y' else True
        if isWriteProtected is True:
            print("Error: Disk is probably write protected.")
            return False
        else:
            return True

    def eraseCurrentTrack(self):
        self.sendCommand("erase_track") # fill whole track with 0xAA
        if self.handleWriteProtection() is False:
            return
        eraseDone = self.serial.read(1)
        if eraseDone != b'1':
            raise Exception("Track erase failed " + str(reply))

    def prepareWriteWithErase(self, track, head):
        self.sendCommand("motor_on_write")
        self.serial.rtscts = True
        self.selectTrackAndHead(track, head)
        time.sleep(1)
        self.eraseCurrentTrack()
        time.sleep(1)


    def writeTrackData(self, track, head, data):
        '''
        in which format do we provide the track data here? Let's have a look at
        Robert Smith's sourcecode:
        https://github.com/RobSmithDev/ArduinoFloppyDiskReader/
        blob/master/FloppyDriveController.sketch/FloppyDriveController.sketch.ino
        Quote: "Write a track to disk from the UART - the data should be
        pre-MFM encoded raw track data where '1's are the pulses/phase
        reversals to trigger"
        '''
        datalen = len(data)
        if datalen > 65535:
            raise Exception ( "track data to write is far too long!")
        starttime_trackwrite = time.time()
        self.prepareWriteWithErase(track, head)
        self.sendCommand("write_track") #calls writeTrackFromUART in sketch
        if self.handleWriteProtection() is False:
            return
        '''
        chunksize = 2048
        byteDataChunks = []
        pointer = 0
        startPortions = [ 32, 32, 32, 32]
        for p in startPortions:
            old = pointer
            pointer += p
            print(f"Appending from {old} to {old+p}")
            byteDataChunks.append( data[ old: old + p ].encode() )
        print(f"Pointer is at {pointer} of len {datalen}")
        xran = range(0, int((datalen-pointer)/chunksize))
        print(xran)
        for i in xran:
            offset = chunksize * i + pointer
            chunk = data[offset:offset+chunksize ]
            bytechunk = chunk.encode() #bytes( chunk, 'utf-8' )
            print(f"Appending from {offset} to {offset+chunksize}")
            byteDataChunks.append( bytechunk )
        byteDataChunks.append( data[offset+chunksize:].encode())
        '''
        byteData = bytes( data,'utf-8' )
        lenByteData = len(byteData)
        #calculate low byte and high byte of datalen
        datalen_hb = int(datalen / 255)
        datalen_lb = datalen - (255 * datalen_hb)

        print (f"Debug Datalengths: {datalen}, {datalen_hb}, {datalen_lb}, {lenByteData}")
        #send data length high byte
        self.serial.write( bytes( chr(datalen_hb),'utf-8' ))
        #send data length low byte
        self.serial.write( bytes( chr(datalen_lb),'utf-8' ))
        #index pulse setting 1= WRITE FROM INDEX PULSE
        self.serial.write( bytes( chr(1),'utf-8' ))
        reply = self.serial.read(1)
        #print ("Reply pulse setting :" + str(reply))
        if reply != b'!':
            raise Exception("Track write: We didn't get the '!' that we expected:" + str(reply))
        numb = self.serial.write( byteData )
        print(f"Bytes written via Serial: {numb}")
        '''
        count = 0
        for c in byteDataChunks:
            print (f"Portion {count}")
            count +=1
            #print (c)
            numb = self.serial.write( c )
            #while self.serial.cts is False:
            #    print("Waiting...")
            #print ("Continue...")
            print(f"  Bytes written via Serial: {numb}")
        '''

        self.serial.flush()#???
        reply = self.serial.read(1)
        if reply == b'X':
            raise Exception("Track write failed: Buffer underflow")
        elif reply != b'1':
            raise Exception("Track write failed " + str(reply))
#        self.serial.rtscts = False
        self.serial.reset_input_buffer()
        self.serial.reset_output_buffer()
        print (f"Finished writing track {track} head {head}")
        time.sleep(1)
        #FIXME improve read/write motor switching
        self.sendCommand("motor_on_read")#in case we were in write mode

    def getCompressedTrackData(self, track, head):
        self.selectTrackAndHead(track, head)
        starttime_trackread = time.time()
        if self.ignoreIndexPulse is True:
            self.serial.write(self.cmd["read_track_ignoring_index_pulse"][0])
        else:
            self.serial.write(self.cmd["read_track_from_index_pulse"][0])
        #speedup for Linux where pyserial seems to be very optimized
        if platform.system() == "Linux":
            trackbytes = self.serial.read_until( self.hexZeroByte , 12200)
            #workaround for problematic disks
            tracklength = len(trackbytes)
            if tracklength < 10223:
                print ("Track length suspicously short: " + str(tracklength) + " bytes")
        else:
            #self.serial.timeout = 1
            trackbytes = self.serial.read_until(expected=b'\x00',size=(0x1900*2+0x44)+1) # The Arduino sends 0 at the end of transmission.
            #self.serial.timeout = 0
            # trackbytes = trackbytes + self.serial.readline()
            #self.serial.timeout = None
            print(f'Read {len(trackbytes)} bytes from serial. Last byte:{trackbytes[-1]}')
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

    def __init__(self, diskFormat, rawTrackData):
        super().__init__("bla", diskFormat)
        self.rawTrackData = rawTrackData

    def __del__(self):
        pass

    def openSerialConnection(self):
        pass

    def connectionIsUsable(self, cmd):
        return True

    def getDecompressedBitstream(self, track, head):
        return self.rawTrackData[track][head]

if __name__ == '__main__':
    main()
