package main

import (
	"encoding/hex"
	"fmt"

	"github.com/cboling/omci"
	"github.com/google/gopacket"
)

func main() {
	mibResetExample()
	createGalEthernetProfileExample()
	setTContExample()
	create8021pMapperService_profile()
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

func setTContExample() {
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

		msgLayer := packet.Layer(omci.LayerTypeSetRequest)
		fmt.Println(msgLayer)
		fmt.Println(msgLayer.(*omci.SetRequest))

		omciMsg, ok := omciLayer.(*omci.OMCI)
		fmt.Printf("SET Request OMCI Layer Decode status: %v\n", ok)
		fmt.Printf("   TransactionID: %v\n", omciMsg.TransactionID)
		fmt.Printf("   MessageType: %v (%#x)\n", omciMsg.MessageType, omciMsg.MessageType)
		fmt.Printf("   \n")

		setRequest, ok2 := msgLayer.(*omci.SetRequest)
		fmt.Printf("SET Request Decode status: %v\n", ok2)
		fmt.Printf("  EntityID: %v, InstanceID: %#x\n", setRequest.EntityClass, setRequest.EntityInstance)
		fmt.Printf("  AttributeMask: %#x\n", setRequest.AttributeMask)
		fmt.Printf("  Attributes: %v\n", setRequest.Attributes)

		// Test serialization back to former string
		var options gopacket.SerializeOptions
		options.FixLengths = true

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, options, omciMsg, setRequest)
		fmt.Println(err)

		outgoingPacket := buffer.Bytes()
		reconstituted := packetToString(outgoingPacket)
		fmt.Println(setTCont)
		fmt.Println(reconstituted)
	}
}

func create8021pMapperService_profile() {
	fmt.Println("======================================================")
	fmt.Println("======================================================")
	create8021pMapperServiceProfile := "0007440A00828000ffffffffffffffff" +
		"ffffffffffffffffffff000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(create8021pMapperServiceProfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	packet := gopacket.NewPacket(data, omci.LayerTypeOMCI, gopacket.NoCopy)

	omciLayer := packet.Layer(omci.LayerTypeOMCI)
	fmt.Println(omciLayer)
	fmt.Println(omciLayer.(*omci.OMCI))

	msgLayer := packet.Layer(omci.LayerTypeCreateRequest)
	fmt.Println(msgLayer)
	fmt.Println(msgLayer.(*omci.CreateRequest))

	omciMsg, ok := omciLayer.(*omci.OMCI)
	fmt.Printf("Create Request OMCI Layer Decode status: %v\n", ok)
	fmt.Printf("   TransactionID: %v\n", omciMsg.TransactionID)
	fmt.Printf("   MessageType: %v (%#x)\n", omciMsg.MessageType, omciMsg.MessageType)
	fmt.Printf("   \n")

	createRequest, ok2 := msgLayer.(*omci.CreateRequest)
	fmt.Printf("Create Request Decode status: %v\n", ok2)
	fmt.Printf("  EntityID: %v, InstanceID: %v\n", createRequest.EntityClass, createRequest.EntityInstance)
	fmt.Printf("  Attributes: %v\n", createRequest.Attributes)

	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciMsg, createRequest)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)

	fmt.Println(create8021pMapperServiceProfile)
	fmt.Println(reconstituted)
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
