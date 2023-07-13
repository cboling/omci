package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cboling/omci/v2"
	"github.com/google/gopacket"
	"log"
	"os"
	"strconv"
	"strings"
)

var verbose = false
var inputFile = "cg-omci-sequence.omci.txt"

type PacketEntry struct {
	Timestamp  float64 `json:"timestamp"`
	Packet     string  `json:"message"`
	LineNumber int
}

// NewPacketEntry receives and input line and decodes it to a PacketEntry
func NewPacketEntry(message string, lineNumber int) (*PacketEntry, error) {
	// Format is:
	//    <timestamp>:<type>:<packet-data>
	// such as:
	//    0000013234.0096899080:RES:1f3e320a010780010000000000000000000000000000000000000000000000000000000000000000b0e7bd0
	var items = strings.Split(message, ":")
	if len(items) != 3 {
		// Watch for blank lines
		if len(items) == 1 && items[0] == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid input '%v', expected 3 field separated by ':' and only found %d",
			message, len(items))
	}
	val, err := strconv.ParseFloat(items[0], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp '%v'", items[0])
	}
	return &PacketEntry{
		Timestamp:  val,
		Packet:     items[2],
		LineNumber: lineNumber,
	}, nil
}

// ParseArgs will parse the command line arguments
func ParseCommandLineArgs() {
	var help string
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	help = fmt.Sprintf("OMCI Input File, default: '%v'", inputFile)
	flag.StringVar(&inputFile, "input", inputFile, help)

	help = fmt.Sprintf("Verbose output to console: '%v'", verbose)
	flag.BoolVar(&verbose, "verbose", verbose, help)

	flag.Parse()
}

// readPacketEntries is responsible for reading the input line and providing
// back a timestamp (if applicable) and an ASCII hex string input of the packet
// data. The packet data can be in an application specific format that the 'stringToPacket'
// function can decode into an actual byte-slice of the packet that can be provided to
// the packet decoder.
func readPacketEntries(file string) ([]PacketEntry, error) {
	if verbose {
		fmt.Printf("Opening input file: '%v'\n", inputFile)
	}
	input, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func(input *os.File) {
		err := input.Close()
		if err != nil && verbose {
			fmt.Print("Failed to properly close the input file '%v': '%v",
				file, err)
		}
	}(input)

	// Read all the input and parse into a buffer.  Abort on error
	fileScanner := bufio.NewScanner(input)
	fileScanner.Split(bufio.ScanLines)
	packetEntries := make([]PacketEntry, 0)
	var lineNo = 1

	for fileScanner.Scan() {
		msg := fileScanner.Text()
		newEntry, err := NewPacketEntry(msg, lineNo)
		if err != nil {
			fmt.Printf("Failed to parse entry on line %d: error: %v: '%v'", lineNo, err, msg)
			return nil, err
		}
		if newEntry != nil {
			packetEntries = append(packetEntries, *newEntry)
		}
		lineNo += 1
	}
	return packetEntries, nil
}

// processEntries runs through each line and attempts to decode and output results
func processEntries(entries []PacketEntry) (err error) {

	for index, packet := range entries {
		timestamp := packet.Timestamp
		packetString := packet.Packet
		lineNumber := packet.LineNumber

		if len(packetString) > 0 {
			data, err := stringToPacket(packetString)
			if err != nil {
				log.Printf("Failed at line number %d", lineNumber)
				log.Fatal(err)
			}
			// Decode and save into array for later processing
			packet := gopacket.NewPacket(data, omci.LayerTypeOMCI, gopacket.NoCopy)

			if _, ok := packet.Layer(omci.LayerTypeOMCI).(*omci.OMCI); ok {

				dumpFrame(index, timestamp, packet)

			} else {
				return fmt.Errorf("OMCI decode failed, entry %v. line %v of '%v'", index, lineNumber, inputFile)
			}
		}

	}
	return nil
}

// stringToPacket is responsible for reading in the OMCI packet portion of the input
// file and returns a byte slice that can be passed directly into the OMCI go-packet
// decoder
func stringToPacket(input string) ([]byte, error) {
	var p []byte
	if verbose {
		fmt.Printf("String '%v' is %d bytes long", input, len(input))
	}
	// Limit string to 40 octets since lines for this format are often of an odd length for some reason unknown
	// TODO: Check with cg team on why odd length in hexstring output
	p, err := hex.DecodeString(input[:80])
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return p, nil
}

func dumpFrame(index int, timestamp float64, packet gopacket.Packet) {

	pktString := packet.String()
	log.Println(fmt.Sprintf("Index: %v, Timestamp: %v: Packet: %v", index, timestamp, pktString))

	packet.Dump()
}

func main() {
	ParseCommandLineArgs()

	if entries, err := readPacketEntries(inputFile); err == nil {
		if err := processEntries(entries); err != nil {
			fmt.Print(err)
		}
	}
}
