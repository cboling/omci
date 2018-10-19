package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cboling/omci"
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

		customLayer := packet.Layer(omci.LayerTypeOMCI)
		fmt.Println(customLayer)
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
