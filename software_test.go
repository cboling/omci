/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package omci_test

import (
	"fmt"
	. "github.com/cboling/omci"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

// TODO: Create request/response tests for all of the following types
//Test,
//                    1                   2                   3                   4
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
// 0004530a00070001ff000f424001000100000000000000000000000000000000000000000000000000000028
// 0004530a
//         00070001             - ONU-G instance 0001
//                 ff           - window size - 1
//                   000f4240   - image size
//                           01
//                             000100000000000000000000000000000000000000000000000000000028
func TestStartSoftwareDownloadRequestDecode(t *testing.T) {
	goodMessage := "0004530a00070001ff000f424001000100000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0004), omciMsg.TransactionID)
	assert.Equal(t, StartSoftwareDownloadRequestType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*StartSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(0xff), request.WindowSize)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadRequestSerialize(t *testing.T) {
	//// TODO: Need to complete implementation & debug this
	//goodMessage := "0000530a0007000113000f424001000100000000000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   StartSoftwareDownloadRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &StartSoftwareDownloadRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestStartSoftwareDownloadResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, omciLayer)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, StartSoftwareDownloadResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*StartSoftwareDownloadResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   StartSoftwareDownloadResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &StartSoftwareDownloadResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

//                    1                   2                   3                   4
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
// 0008140a00070001		    - Download section, AR=0
//                 cc       - Section 0xcc
//                   01020304050607080910111213141516171819202122232425262728293031
//                                                                                 00000028

func TestDownloadSectionRequestDecodeNoResponseExpected(t *testing.T) {
	goodMessage := "0008140a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestType, omciMsg.MessageType)
	assert.False(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(0xcc), request.SectionNumber)
	assert.Equal(t, MaxDownloadSectionLength, len(request.SectionData))

	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))
	assert.Equal(t, sectionData, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionRequestDecodeResponseExpected(t *testing.T) {
	goodMessage := "0008540a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestWithResponseType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(0xcc), request.SectionNumber)
	assert.Equal(t, 31, len(request.SectionData))

	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))
	assert.Equal(t, sectionData, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionRequestSerializeNoResponseExpected(t *testing.T) {
	goodMessage := "0123140a00070000cc0102030405060708091011121314151617181920212223242526272829303100000028"

	omciLayer := &OMCI{
		TransactionID: 0x0123,
		MessageType:   DownloadSectionRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionRequestSerializeNoResponsePartialDataExpected(t *testing.T) {
	// If a small buffer is provided, serialize will now zero extend the baseline format
	goodMessage := "0123140a00070000cc0102030405060708091011121314151617181920212223242526272829000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0123,
		MessageType:   DownloadSectionRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("0102030405060708091011121314151617181920212223242526272829")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength-2, len(sectionData)) // Partial data buffer

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionRequestSerializeResponseExpectedMethod1(t *testing.T) {
	goodMessage := "2468540a00070000cc0102030405060708091011121314151617181920212223242526272829303100000028"

	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestType, // or DownloadSectionRequestWithResponseType
		ResponseExpected: true,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionRequestSerializeResponseExpectedMethod2(t *testing.T) {
	goodMessage := "2468540a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"

	// In this case, just use the request type with AR response requested already encoded
	omciLayer := &OMCI{
		TransactionID: 0x2468,
		MessageType:   DownloadSectionRequestWithResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionResponseDecode(t *testing.T) {
	goodMessage := "0022340a00070001061f00000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0022))
	assert.Equal(t, omciMsg.MessageType, DownloadSectionResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*DownloadSectionResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0x1f), response.SectionNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseSerialize(t *testing.T) {
	goodMessage := "0022340a00070001061f00000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0022,
		MessageType:   DownloadSectionResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result:        me.DeviceBusy,
		SectionNumber: 0x1f,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestEndSoftwareDownloadRequestDecode(t *testing.T) {
	//
	// 8100 55 0a 0007 0001 ff92a226 000f4240 01 0001 00000000000000000000000000000000000000000000000028
	//
	goodMessage := "8100550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x8100))
	assert.Equal(t, omciMsg.MessageType, EndSoftwareDownloadRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*EndSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint32(0xff92a226), request.CRC32)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)
	assert.Equal(t, byte(1), request.NumberOfInstances)
	assert.Equal(t, 1, len(request.ImageInstances))
	assert.Equal(t, uint16(1), request.ImageInstances[0])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadRequestSerialize(t *testing.T) {
	// 8100 55 0a 0007 0001 ff92a226 000f4240 01 0001 00000000000000000000000000000000000000000000000028
	goodMessage := "8100550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8100,
		MessageType:   EndSoftwareDownloadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
		},
		CRC32:             0xff92a226,
		ImageSize:         1000000,
		NumberOfInstances: 1,
		ImageInstances:    []uint16{1},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestEndSoftwareDownloadResponseDecode(t *testing.T) {
	// 8123 35 0a 0007 0001 06 0000000000000000000000000000000000000000000000000000000000000000000028
	goodMessage := "8123350a00070001060000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x8123))
	assert.Equal(t, omciMsg.MessageType, EndSoftwareDownloadResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*EndSoftwareDownloadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0), response.NumberOfInstances)
	assert.Nil(t, response.MeResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadResponseSerialize(t *testing.T) {
	goodMessage := "8456350a00070000010000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8456,
		MessageType:   EndSoftwareDownloadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default is zero
		},
		Result:            me.ProcessingError,
		NumberOfInstances: 0,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestActivateSoftwareRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000560a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, omciLayer)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, ActivateSoftwareRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeActivateSoftwareRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*ActivateSoftwareRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareRequestSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000560a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   ActivateSoftwareRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &ActivateSoftwareRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestActivateSoftwareResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, omciLayer)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, ActivateSoftwareResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeActivateSoftwareResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*ActivateSoftwareResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   ActivateSoftwareResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &ActivateSoftwareResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCommitSoftwareRequestDecode(t *testing.T) {
	goodMessage := "0011570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x11))
	assert.Equal(t, omciMsg.MessageType, CommitSoftwareRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCommitSoftwareRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CommitSoftwareRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint16(1), request.MeBasePacket.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareRequestSerialize(t *testing.T) {
	goodMessage := "0044570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x44,
		MessageType:   CommitSoftwareRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCommitSoftwareResponseDecode(t *testing.T) {
	goodMessage := "00aa370a00070001060000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0xaa))
	assert.Equal(t, omciMsg.MessageType, CommitSoftwareResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCommitSoftwareResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CommitSoftwareResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, uint16(1), response.MeBasePacket.EntityInstance)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareResponseSerialize(t *testing.T) {
	goodMessage := "8001370a00070001060000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8001,
		MessageType:   CommitSoftwareResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
		},
		Result: me.DeviceBusy,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

//                    1                   2                   3                   4
//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
// 0008140a00070001		    - Download section, AR=0
//                 cc       - Section 0xcc
//                   01020304050607080910111213141516171819202122232425262728293031
//                                                                                 00000028
func TestExtendedDownloadSectionRequestDecodeNoResponseExpected(t *testing.T) {
	goodMessage := "0008140b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x88
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.Nil(t, packet.ErrorLayer())

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestType, omciMsg.MessageType)
	assert.False(t, omciMsg.ResponseExpected)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(length), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(sectionNumber), request.SectionNumber)
	assert.Equal(t, length-1, len(request.SectionData))

	data, err = stringToPacket(payloadTotal)
	assert.NoError(t, err)
	assert.Equal(t, data, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionRequestDecodeResponseExpected(t *testing.T) {
	goodMessage := "0008540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x88
	length := 1 + (20 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.Nil(t, packet.ErrorLayer())

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestWithResponseType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(length), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(sectionNumber), request.SectionNumber)
	assert.Equal(t, length-1, len(request.SectionData))

	data, err = stringToPacket(payloadTotal)
	assert.NoError(t, err)
	assert.Equal(t, data, request.SectionData)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionRequestDecodeTruncated(t *testing.T) {
	goodMessage := "0008540b000700010000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	failure := packet.ErrorLayer()
	assert.NotNil(t, failure)

	decodeFailure, ok := failure.(*gopacket.DecodeFailure)
	assert.NotNil(t, decodeFailure)
	assert.True(t, ok)
	assert.NotNil(t, decodeFailure.String())
	assert.True(t, len(decodeFailure.String()) > 0)

	metadata := packet.Metadata()
	assert.NotNil(t, metadata)
	assert.True(t, metadata.Truncated)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionRequestSerializeNoResponseExpected(t *testing.T) {
	goodMessage := "0123140b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	omciLayer := &OMCI{
		TransactionID:    0x0123,
		MessageType:      DownloadSectionRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestExtendedDownloadSectionRequestSerializeResponseExpectedMethod1(t *testing.T) {
	goodMessage := "2468540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestType, // or DownloadSectionRequestWithResponseType
		ResponseExpected: true,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestExtendedDownloadSectionRequestSerializeResponseExpectedMethod2(t *testing.T) {
	goodMessage := "2468540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	// In this case, just use the request type with AR response requested already encoded
	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestWithResponseType,
		ResponseExpected: true,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestExtendedDownloadSectionResponseDecode(t *testing.T) {
	goodMessage := "0022340b000700010002061f"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0022))
	assert.Equal(t, omciMsg.MessageType, DownloadSectionResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, ExtendedIdent)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*DownloadSectionResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0x1f), response.SectionNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionResponseDecodeTruncated(t *testing.T) {
	goodMessage := "0022340b00070001000106"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	failure := packet.ErrorLayer()
	assert.NotNil(t, failure)

	decodeFailure, ok := failure.(*gopacket.DecodeFailure)
	assert.NotNil(t, decodeFailure)
	assert.True(t, ok)
	assert.NotNil(t, decodeFailure.String())
	assert.True(t, len(decodeFailure.String()) > 0)

	metadata := packet.Metadata()
	assert.NotNil(t, metadata)
	assert.True(t, metadata.Truncated)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionResponseSerialize(t *testing.T) {
	goodMessage := "0022340b000700010002061f"

	omciLayer := &OMCI{
		TransactionID:    0x0022,
		MessageType:      DownloadSectionResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		Result:        me.DeviceBusy,
		SectionNumber: 0x1f,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}
