package main

import (
	".."
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
)

func main() {

	var allMsgTypes = [...]omci.MsgType{
		omci.Create,
		omci.Delete,
		omci.Set,
		omci.Get,
		omci.GetAllAlarms,
		omci.GetAllAlarmsNext,
		omci.MibUpload,
		omci.MibUploadNext,
		omci.MibReset,
		omci.AlarmNotification,
		omci.AttributeValueChange,
		omci.Test,
		omci.StartSoftwareDownload,
		omci.DownloadSection,
		omci.EndSoftwareDownload,
		omci.ActivateSoftware,
		omci.CommitSoftware,
		omci.SynchronizeTime,
		omci.Reboot,
		omci.GetNext,
		omci.TestResult,
		omci.GetCurrentData,
		omci.SetTable}

	var requestMask byte = 0
	var responseMask byte = 0x20

	for _, msg := range allMsgTypes {
		// Test responses first since covers autonomous events
		mtResponse := byte(msg) | responseMask
		decoder, err := omci.MsgTypeToStructDecoder(mtResponse)

		mtRequest := byte(msg) | requestMask
		decoder, err = omci.MsgTypeToStructDecoder(mtRequest)
		fmt.Println(err)
		if decoder == nil {
			fmt.Println("Arggggghhh!")
		}
	}
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
