package main

import (
	".."
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
)

func main() {
	// MibResetRequestTest tests decode/encode of a MIB Reset Request

	mibResetRequest := "00014F0A000200000000000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(mibResetRequest)
	if err != nil {
		fmt.Println(err)
	} else {
		packet := gopacket.NewPacket(data, omci.LayerTypeOMCI, gopacket.NoCopy)
		fmt.Println(packet)

		omciLayer := packet.Layer(omci.LayerTypeOMCI)
		fmt.Println(omciLayer)

		omciObj, _ := omciLayer.(*omci.OMCI)
		fmt.Println(omciObj)

		msgLayer := packet.Layer(omci.LayerTypeMibResetRequest)
		fmt.Println(msgLayer)

		msgObj, _ := msgLayer.(*omci.MibResetRequest)
		fmt.Println(msgObj)

		// Test serialization back to form
		// TODO: Turn on computeChecksums and handle that with a MIC calculation
		var options gopacket.SerializeOptions
		options.FixLengths = true

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, options, omciObj, msgObj)
		outgoingPacket := buffer.Bytes()

		reconstituted := packetToString(outgoingPacket)
		fmt.Println(reconstituted)
	}
	createGalEthernetProfile := "0002440A011000010030000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err = stringToPacket(createGalEthernetProfile)
	if err != nil {
		fmt.Println(err)
	} else {
		packet := gopacket.NewPacket(data, omci.LayerTypeOMCI, gopacket.NoCopy)
		fmt.Println(packet)

		omciLayer := packet.Layer(omci.LayerTypeOMCI)
		fmt.Println(omciLayer)
		fmt.Println(omciLayer.(*omci.OMCI))

		msgLayer := packet.Layer(omci.LayerTypeCreateRequest)
		fmt.Println(msgLayer)
		fmt.Println(msgLayer.(*omci.CreateRequest))
	}
}

func stringToPacket(input string) ([]byte, error) {
	var p []byte

	p, err := hex.DecodeString(input)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return p, nil
}

func packetToString(input []byte) string {
	return hex.EncodeToString(input)
}
