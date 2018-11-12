package main

import (
	".."
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
)

func main() {
	mibResetExample()
	createGalEthernetProfileExample()
	setTContExample()
}

func mibResetExample() {
	fmt.Println("======================================================")
	fmt.Println("======================================================")
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
}

func createGalEthernetProfileExample() {
	fmt.Println("======================================================")
	fmt.Println("======================================================")
	createGalEthernetProfile := "0002440A011000010030000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(createGalEthernetProfile)
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

		omciMsg, ok2 := omciLayer.(*omci.OMCI)
		fmt.Println(ok2)

		omciMsg2, ok3 := msgLayer.(*omci.CreateRequest)
		fmt.Println(ok3)
		fmt.Println(omciMsg2.EntityClass)    // uint16(0x0110))
		fmt.Println(omciMsg2.EntityInstance) // uint16(1))

		// Test serialization back to former string
		var options gopacket.SerializeOptions
		options.FixLengths = true

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, options, omciMsg, omciMsg2)
		fmt.Println(err)

		outgoingPacket := buffer.Bytes()
		reconstituted := packetToString(outgoingPacket)
		fmt.Println(createGalEthernetProfile)
		fmt.Println(reconstituted)
	}
}

func setTContExample()() {
	fmt.Println("======================================================")
	fmt.Println("======================================================")
	setTCont := "0003480A010680008000040000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(setTCont)
	if err != nil {
		fmt.Println(err)
	} else {
		packet := gopacket.NewPacket(data, omci.LayerTypeOMCI, gopacket.NoCopy)
		fmt.Println(packet)

		omciLayer := packet.Layer(omci.LayerTypeOMCI)
		fmt.Println(omciLayer)
		fmt.Println(omciLayer.(*omci.OMCI))

		omciMsg, ok := omciLayer.(*omci.OMCI)
		fmt.Println(ok)
		fmt.Println(omciMsg)

		layers := packet.Layers()
		for _, layer := range layers {
			ltype := layer.LayerType()
			fmt.Println(ltype, omci.LayerTypeSetRequest)
		}
		msgLayer := packet.Layer(omci.LayerTypeSetRequest)
		fmt.Println(msgLayer)
		fmt.Println(msgLayer.(*omci.SetRequest))

		omciMsg, ok2 := omciLayer.(*omci.OMCI)
		fmt.Println(ok2)

		omciMsg2, ok3 := msgLayer.(*omci.CreateRequest)
		fmt.Println(ok3)
		fmt.Println(omciMsg2.EntityClass)    // uint16(0x0110))
		fmt.Println(omciMsg2.EntityInstance) // uint16(1))

		// Test serialization back to former string
		var options gopacket.SerializeOptions
		options.FixLengths = true

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, options, omciMsg, omciMsg2)
		fmt.Println(err)

		outgoingPacket := buffer.Bytes()
		reconstituted := packetToString(outgoingPacket)
		fmt.Println(setTCont)
		fmt.Println(reconstituted)
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
