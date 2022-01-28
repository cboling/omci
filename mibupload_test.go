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
	. "github.com/cboling/omci/v2"
	me "github.com/cboling/omci/v2/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestMibUploadRequestDecode(t *testing.T) {
	goodMessage := "03604d0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0360), omciMsg.TransactionID)
	assert.Equal(t, MibUploadRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)
	msgLayer := packet.Layer(LayerTypeMibUploadRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeMibUploadRequest, request.LayerType())
	assert.Equal(t, LayerTypeMibUploadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadRequestDecodeExtended(t *testing.T) {
	goodMessage := "03604d0b000200000000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0360), omciMsg.TransactionID)
	assert.Equal(t, MibUploadRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(0), omciMsg.Length)
	msgLayer := packet.Layer(LayerTypeMibUploadRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeMibUploadRequest, request.LayerType())
	assert.Equal(t, LayerTypeMibUploadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadRequestSerialize(t *testing.T) {
	goodMessage := "03604d0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0360,
		MessageType:   MibUploadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
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

func TestMibUploadRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   MibUploadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestMibUploadRequestSerializeExtended(t *testing.T) {
	goodMessage := "03604d0b000200000000"

	omciLayer := &OMCI{
		TransactionID:    0x0360,
		MessageType:      MibUploadRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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

func TestMibUploadResponseDecode(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0360), omciMsg.TransactionID)
	assert.Equal(t, MibUploadResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, response.NumberOfCommands, uint16(0x112))
}

func TestMibUploadResponseDecodeExtended(t *testing.T) {
	goodMessage := "03602d0b0002000000020112"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0360), omciMsg.TransactionID)
	assert.Equal(t, MibUploadResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, response.NumberOfCommands, uint16(0x112))
}

func TestMibUploadResponseSerialize(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0360,
		MessageType:   MibUploadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		NumberOfCommands: uint16(0x112),
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

func TestMibUploadResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   MibUploadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		NumberOfCommands: uint16(0x112),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestMibUploadResponseSerializeExtended(t *testing.T) {
	goodMessage := "03602d0b0002000000020112"

	omciLayer := &OMCI{
		TransactionID:    0x0360,
		MessageType:      MibUploadResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		NumberOfCommands: uint16(0x112),
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

func TestMibUploadNextRequestDecode(t *testing.T) {
	goodMessage := "02864e0a00020000003a00000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeMibUploadNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(0x3a), request.CommandSequenceNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextRequestDecodeExtended(t *testing.T) {
	goodMessage := "02864e0b000200000002003a"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeMibUploadNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(0x3a), request.CommandSequenceNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextRequestSerialize(t *testing.T) {
	goodMessage := "02864e0a00020000003a00000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0286,
		MessageType:   MibUploadNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		CommandSequenceNumber: uint16(0x3a),
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

func TestMibUploadNextRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   MibUploadNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		CommandSequenceNumber: uint16(0x3a),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestMibUploadNextRequestSerializeExtended(t *testing.T) {
	goodMessage := "02864e0b000200000002003a"

	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		CommandSequenceNumber: uint16(0x3a),
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

func TestMibUploadNextResponseDecode(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.PriorityQueueClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	attributes := me.AttributeValueMap{
		"QueueConfigurationOption":                            byte(0),
		"MaximumQueueSize":                                    uint16(0),
		"AllocatedQueueSize":                                  uint16(0),
		"DiscardBlockCounterResetInterval":                    uint16(0),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0),
		"RelatedPort":                                         uint32(16842752),
		"TrafficSchedulerPointer":                             uint16(0),
		"Weight":                                              byte(1),
		"BackPressureOperation":                               uint16(0),
		"BackPressureTime":                                    uint32(0),
		"BackPressureOccurQueueThreshold":                     uint16(0),
		"BackPressureClearQueueThreshold":                     uint16(0),
	}
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, pktValue, value)
	}
	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextResponseDecodeExtendedOneMe(t *testing.T) {
	firstMe := "001801150000ffe001123443215678876501010000FFBB011234000000006789"
	goodMessage := "02862e0b000200000020" + firstMe
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2+6+24), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.PriorityQueueClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	attributes := me.AttributeValueMap{
		"QueueConfigurationOption":                            byte(1),
		"MaximumQueueSize":                                    uint16(0x1234),
		"AllocatedQueueSize":                                  uint16(0x4321),
		"DiscardBlockCounterResetInterval":                    uint16(0x5678),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
		"RelatedPort":                                         uint32(16842752),
		"TrafficSchedulerPointer":                             uint16(0xFFBB),
		"Weight":                                              byte(1),
		"BackPressureOperation":                               uint16(0x1234),
		"BackPressureTime":                                    uint32(0),
		"BackPressureOccurQueueThreshold":                     uint16(0x6789),
	}
	// 01 1234 4321 5678 8765 01010000 FFBB 01 1234 00000000 6789
	// 01123443215678876501010000FFBB011234000000006789
	//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	// Only the first ME
	assert.Nil(t, response.AdditionalMEs)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextResponseDecodeExtendedThreeMe(t *testing.T) {
	first := "001801150000ffe001123443215678876501010000FFBB011234000000006789"
	second := "001801150001ffe001123443215678876501010000FFBB011234000000006789"
	third := "001801150002ffe001123443215678876501010000FFBB011234000000006789"
	goodMessage := "02862e0b000200000060" + first + second + third
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3*(8+24)), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.PriorityQueueClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	attributes := me.AttributeValueMap{
		"QueueConfigurationOption":                            byte(1),
		"MaximumQueueSize":                                    uint16(0x1234),
		"AllocatedQueueSize":                                  uint16(0x4321),
		"DiscardBlockCounterResetInterval":                    uint16(0x5678),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
		"RelatedPort":                                         uint32(16842752),
		"TrafficSchedulerPointer":                             uint16(0xFFBB),
		"Weight":                                              byte(1),
		"BackPressureOperation":                               uint16(0x1234),
		"BackPressureTime":                                    uint32(0),
		"BackPressureOccurQueueThreshold":                     uint16(0x6789),
	}
	// 01 1234 4321 5678 8765 01010000 FFBB 01 1234 00000000 6789
	// 01123443215678876501010000FFBB011234000000006789
	//  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	// Other two are the same, just different managed entity IDs

	assert.Equal(t, 2, len(response.AdditionalMEs))
	assert.Equal(t, me.PriorityQueueClassID, response.AdditionalMEs[0].GetClassID())
	assert.Equal(t, uint16(1), response.AdditionalMEs[0].GetEntityID())
	for name, value := range attributes {
		pktValue, err := response.AdditionalMEs[0].GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	assert.Equal(t, me.PriorityQueueClassID, response.AdditionalMEs[1].GetClassID())
	assert.Equal(t, uint16(2), response.AdditionalMEs[1].GetEntityID())
	for name, value := range attributes {
		pktValue, err := response.AdditionalMEs[1].GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextResponseDecodeExtendedMaxLength(t *testing.T) {
	// Max payload after header length field and not including MIC is 1966 octets
	maxPayloadLen := MaxExtendedLength - 10 - 4

	// Payload is AttrLen (2) + ME Hdr (6) + attributes which is 30 octets
	// below. That allows 65 'common' payloads with a remainder of 16 octets
	// to fill with another ME
	commonPayloadFmt := "00160115%04xffc001123443215678876501010000FFBB01123487654321"
	lastPayload := "00080115000078001234432156788765"
	msgHeader := fmt.Sprintf("02862e0b00020000%04x", maxPayloadLen)
	numCommon := 65

	goodMessage := msgHeader + fmt.Sprintf(commonPayloadFmt, 0)
	for instance := 1; instance < numCommon; instance++ {
		goodMessage += fmt.Sprintf(commonPayloadFmt, instance)
	}
	goodMessage += lastPayload

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)
	assert.Equal(t, MaxExtendedLength-4, len(data))

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(maxPayloadLen), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.PriorityQueueClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	attributes := me.AttributeValueMap{
		"QueueConfigurationOption":                            byte(1),
		"MaximumQueueSize":                                    uint16(0x1234),
		"AllocatedQueueSize":                                  uint16(0x4321),
		"DiscardBlockCounterResetInterval":                    uint16(0x5678),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
		"RelatedPort":                                         uint32(16842752),
		"TrafficSchedulerPointer":                             uint16(0xFFBB),
		"Weight":                                              byte(1),
		"BackPressureOperation":                               uint16(0x1234),
		"BackPressureTime":                                    uint32(0x87654321),
	}
	lastPayloadAttributes := me.AttributeValueMap{
		"MaximumQueueSize":                                    uint16(0x1234),
		"AllocatedQueueSize":                                  uint16(0x4321),
		"DiscardBlockCounterResetInterval":                    uint16(0x5678),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
	}
	// Check first ME that is stored in same location as in baseline message
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	// Check remainder of the package = (numCommon - 1) + trailing me
	assert.Equal(t, numCommon, len(response.AdditionalMEs))
	for index, additional := range response.AdditionalMEs {
		if index == numCommon-1 {
			break
		}
		assert.Equal(t, me.PriorityQueueClassID, additional.GetClassID())
		assert.Equal(t, uint16(index+1), additional.GetEntityID())
		for name, value := range attributes {
			pktValue, err := additional.GetAttribute(name)
			assert.Nil(t, err)
			assert.Equal(t, value, pktValue)
		}
	}
	// And check the last one
	assert.Equal(t, me.PriorityQueueClassID, response.AdditionalMEs[numCommon-1].GetClassID())
	assert.Equal(t, uint16(0), response.AdditionalMEs[numCommon-1].GetEntityID())
	for name, value := range lastPayloadAttributes {
		pktValue, err := response.AdditionalMEs[numCommon-1].GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, value, pktValue)
	}
	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextResponseSerialize(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010002000000030004000500000028"

	omciLayer := &OMCI{
		TransactionID: 0x0286,
		MessageType:   MibUploadNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(0),
			"MaximumQueueSize":                                    uint16(0),
			"AllocatedQueueSize":                                  uint16(0),
			"DiscardBlockCounterResetInterval":                    uint16(0),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(2),
			"BackPressureTime":                                    uint32(3),
			"BackPressureOccurQueueThreshold":                     uint16(4),
			"BackPressureClearQueueThreshold":                     uint16(5),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		ReportedME: *reportedME,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   MibUploadNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(0),
			"MaximumQueueSize":                                    uint16(0),
			"AllocatedQueueSize":                                  uint16(0),
			"DiscardBlockCounterResetInterval":                    uint16(0),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(2),
			"BackPressureTime":                                    uint32(3),
			"BackPressureOccurQueueThreshold":                     uint16(4),
			"BackPressureClearQueueThreshold":                     uint16(5),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		ReportedME: *reportedME,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, omciErr)
}

func TestMibUploadNextResponseSerializeExtendedOneMe(t *testing.T) {
	firstMe := "001801150000ffe001123443215678876501010000FFBB011234000000006789"
	goodMessage := "02862e0b000200000020" + firstMe

	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1),
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0xFFBB),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0x1234),
			"BackPressureTime":                                    uint32(0),
			"BackPressureOccurQueueThreshold":                     uint16(0x6789),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		ReportedME: *reportedME,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseSerializeExtendedTwoMe(t *testing.T) {
	first := "001801150000ffe001123443215678876501010000FFBB011234000000006789"
	second := "001801150001ffe001123443215678876501010000FFBB011234000000006789"
	goodMessage := "02862e0b000200000040" + first + second

	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1),
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0xFFBB),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0x1234),
			"BackPressureTime":                                    uint32(0),
			"BackPressureOccurQueueThreshold":                     uint16(0x6789),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	additional := make([]me.ManagedEntity, 1)

	for inst := 1; inst < 2; inst++ {
		paramData.EntityID = uint16(inst)
		entity, _ := me.NewPriorityQueue(paramData)
		additional[inst-1] = *entity
	}
	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		ReportedME:    *reportedME,
		AdditionalMEs: additional,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseSerializeExtendedThreeMe(t *testing.T) {
	first := "001801150000ffe001123443215678876501010000FFBB011234000000006789"
	second := "001801150001ffe001123443215678876501010000FFBB011234000000006789"
	third := "001801150002ffe001123443215678876501010000FFBB011234000000006789"
	goodMessage := "02862e0b000200000060" + first + second + third

	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1),
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0xFFBB),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0x1234),
			"BackPressureTime":                                    uint32(0),
			"BackPressureOccurQueueThreshold":                     uint16(0x6789),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	additional := make([]me.ManagedEntity, 2)

	for inst := 1; inst < 3; inst++ {
		paramData.EntityID = uint16(inst)
		entity, _ := me.NewPriorityQueue(paramData)
		additional[inst-1] = *entity
	}
	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		ReportedME:    *reportedME,
		AdditionalMEs: additional,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseSerializeExtendedMaxFrame(t *testing.T) {
	// Max payload after header length field and not including MIC is 1966 octets
	maxPayloadLen := MaxExtendedLength - 10 - 4

	// Payload is AttrLen (2) + ME Hdr (6) + attributes which is 30 octets
	// below. That allows 65 'common' payloads with a remainder of 16 octets
	// to fill with another ME
	commonPayloadFmt := "00160115%04xffc001123443215678876501010000FFBB01123487654321"
	lastPayload := "00080115000078001234432156788765"
	msgHeader := fmt.Sprintf("02862e0b00020000%04x", maxPayloadLen)
	numCommon := 65

	goodMessage := msgHeader + fmt.Sprintf(commonPayloadFmt, 0)
	for instance := 1; instance < numCommon; instance++ {
		goodMessage += fmt.Sprintf(commonPayloadFmt, instance)
	}
	goodMessage += lastPayload

	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1),
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0xFFBB),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0x1234),
			"BackPressureTime":                                    uint32(0x87654321),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		ReportedME:    *reportedME,
		AdditionalMEs: make([]me.ManagedEntity, numCommon),
	}
	for instance := 0; instance < numCommon-1; instance++ {
		paramData.EntityID = uint16(instance + 1)
		reportedME, err = me.NewPriorityQueue(paramData)
		assert.NotNil(t, err)
		assert.Equal(t, err.StatusCode(), me.Success)
		request.AdditionalMEs[instance] = *reportedME
	}
	lastMeParams := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
		},
	}
	// And the last one to fully fill out the maximum sized frame
	reportedME, err = me.NewPriorityQueue(lastMeParams)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	request.AdditionalMEs[numCommon-1] = *reportedME

	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseSerializeExtendedMaxFramePlusOneByteTooMany(t *testing.T) {
	// Identical to last test but last ME has one extra octet
	numCommon := 65
	omciLayer := &OMCI{
		TransactionID:    0x0286,
		MessageType:      MibUploadNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1),
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0xFFBB),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0x1234),
			"BackPressureTime":                                    uint32(0x87654321),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		ReportedME:    *reportedME,
		AdditionalMEs: make([]me.ManagedEntity, numCommon),
	}
	for instance := 0; instance < numCommon-1; instance++ {
		paramData.EntityID = uint16(instance + 1)
		reportedME, err = me.NewPriorityQueue(paramData)
		assert.NotNil(t, err)
		assert.Equal(t, err.StatusCode(), me.Success)
		request.AdditionalMEs[instance] = *reportedME
	}
	lastMeParams := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(1), // This is the extra byte
			"MaximumQueueSize":                                    uint16(0x1234),
			"AllocatedQueueSize":                                  uint16(0x4321),
			"DiscardBlockCounterResetInterval":                    uint16(0x5678),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0x8765),
		},
	}
	// And the last one to fully fill out the maximum sized frame
	reportedME, err = me.NewPriorityQueue(lastMeParams)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	request.AdditionalMEs[numCommon-1] = *reportedME

	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, omciErr)
}

func TestMibUploadNextResponseBadCommandNumberDecode(t *testing.T) {
	// Test of a MIB Upload next Response that results when an invalid command number.
	// Note that if all attributes of a managed entity do not fit within one MIB
	// upload next response message, the attributes will be split over several
	// messages. The OLT can use the information in the attribute mask to determine
	// which attribute values are reported in which MIB upload next response message.
	//TODO: Implement
}

func TestMibUploadNextResponseBadCommandNumberSerialize(t *testing.T) {
	// Test of a MIB Upload next Response that results when an invalid command number
	// is requested.
	//TODO: Implement
}

func TestMibUploadNextSequence(t *testing.T) {
	mibUploadNextSequence := [...]string{
		"00032e0a00020000000200008000000000000000000000000000000000000000000000000000000000000028",
		"00042e0a0002000000050101f0002f2f05202020202020202020202020202020202020202000000000000028",
		"00052e0a00020000000501010f80202020202020202020202020202020202020202000000000000000000028",
		"00062e0a0002000000050104f000303001202020202020202020202020202020202020202000000000000028",
		"00072e0a00020000000501040f80202020202020202020202020202020202020202000000000000000000028",
		"00082e0a0002000000050180f000f8f801202020202020202020202020202020202020202000000000000028",
		"00092e0a00020000000501800f80202020202020202020202020202020202020202000000000000000000028",
		"000a2e0a0002000000060101f0002f054252434d12345678000000000000000000000000000c000000000028",
		"000b2e0a00020000000601010f004252434d0000000000000000000000000000000000000000000000000028",
		"000c2e0a000200000006010100f8202020202020202020202020202020202020202000000000000000000028",
		"000d2e0a00020000000601010004000000000000000000000000000000000000000000000000000000000028",
		"000e2e0a0002000000060104f00030014252434d12345678000000000000000000000000000c000000000028",
		"000f2e0a00020000000601040f004252434d0000000000000000000000000000000000000000000000000028",
		"00102e0a000200000006010400f8202020202020202020202020202020202020202000000800000000000028",
		"00112e0a00020000000601040004000000000000000000000000000000000000000000000000000000000028",
		"00122e0a0002000000060180f000f8014252434d12345678000000000000000000000000000c000000000028",
		"00132e0a00020000000601800f004252434d0000000000000000000000000000000000000000000000000028",
		"00142e0a000200000006018000f8202020202020202020202020202020202020202000084040000000000028",
		"00152e0a00020000000601800004000000000000000000000000000000000000000000000000000000000028",
		"00162e0a0002000000070000f0003530323247574f3236363230303301010100000000000000000000000028",
		"00172e0a0002000000070001f0003530323247574f3236363230303300000100000000000000000000000028",
		"00182e0a0002000000830000c000202020202020202020202020202020202020202020202020000000000028",
		"00192e0a00020000008300002000202020202020202020202020202000000000000000000000000000000028",
		"001a2e0a00020000008300001000000000000000000000000000000000000000000000000000000000000028",
		"001b2e0a0002000000850000ffe0000000000000000000000000000000000000000000000000000000000028",
		"001c2e0a0002000000860001c00000001018aaaa000000000000000000000000000000000000000000000028",
		"001d2e0a00020000008600012000000000000000000000000000000000000000000000000000000000000028",
		"001e2e0a00020000008600011f80000000000000000000000000000000000000000000000000000000000028",
		"001f2e0a00020000008600010078000000000000000000000000000000000000000000000000000000000028",
		"00202e0a00020000008600010004000000000000000000000000000000000000000000000000000000000028",
		"00212e0a00020000008600010002000000000000000000000000000000000000000000000000000000000028",
		"00222e0a0002000001000000e0004252434d00000000000000000000000000004252434d1234567800000028",
		"00232e0a00020000010000001f80000000000000000000000000000000000000000000000000000000000028",
		"00242e0a00020000010000000040000000000000000000000000000000000000000000000000000000000028",
		"00252e0a00020000010000000038000000000000000000000000000003000000000000000000000000000028",
		"00262e0a0002000001010000f80042564d344b3030425241303931352d3030383300b3000001010000000028",
		"00272e0a000200000101000007f8000000010020027c85630016000030000000000000000000000000000028",
		"00282e0a0002000001068000e00000ff01010000000000000000000000000000000000000000000000000028",
		"00292e0a0002000001068001e00000ff01010000000000000000000000000000000000000000000000000028",
		"002a2e0a0002000001068002e00000ff01010000000000000000000000000000000000000000000000000028",
		"002b2e0a0002000001068003e00000ff01010000000000000000000000000000000000000000000000000028",
		"002c2e0a0002000001068004e00000ff01010000000000000000000000000000000000000000000000000028",
		"002d2e0a0002000001068005e00000ff01010000000000000000000000000000000000000000000000000028",
		"002e2e0a0002000001068006e00000ff01010000000000000000000000000000000000000000000000000028",
		"002f2e0a0002000001068007e00000ff01010000000000000000000000000000000000000000000000000028",
		"00302e0a0002000001078001ffff01000800300000050900000000ffff000000008181000000000000000028",
		"00312e0a0002000001080401f000000000000401000000000000000000000000000000000000000000000028",
		"00322e0a0002000001150401fff0000080008000000000040100000000010000000000000000000000000028",
		"00332e0a0002000001150401000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00342e0a0002000001150402fff0000080008000000000040100010000010000000000000000000000000028",
		"00352e0a0002000001150402000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00362e0a0002000001150403fff0000080008000000000040100020000010000000000000000000000000028",
		"00372e0a0002000001150403000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00382e0a0002000001150404fff0000080008000000000040100030000010000000000000000000000000028",
		"00392e0a0002000001150404000f0200020002000200ffff0900000000000000000000000000000000000028",
		"003a2e0a0002000001150405fff0000080008000000000040100040000010000000000000000000000000028",
		"003b2e0a0002000001150405000f0200020002000200ffff0900000000000000000000000000000000000028",
		"003c2e0a0002000001150406fff0000080008000000000040100050000010000000000000000000000000028",
		"003d2e0a0002000001150406000f0200020002000200ffff0900000000000000000000000000000000000028",
		"003e2e0a0002000001150407fff0000080008000000000040100060000010000000000000000000000000028",
		"003f2e0a0002000001150407000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00402e0a0002000001150408fff0000080008000000000040100070000010000000000000000000000000028",
		"00412e0a0002000001150408000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00422e0a0002000001158000fff0000100010000000000800000000000010000000000000000000000000028",
		"00432e0a0002000001158000000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00442e0a0002000001158001fff0000100010000000000800000010000010000000000000000000000000028",
		"00452e0a0002000001158001000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00462e0a0002000001158002fff0000100010000000000800000020000010000000000000000000000000028",
		"00472e0a0002000001158002000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00482e0a0002000001158003fff0000100010000000000800000030000010000000000000000000000000028",
		"00492e0a0002000001158003000f0200020002000200ffff0900000000000000000000000000000000000028",
		"004a2e0a0002000001158004fff0000100010000000000800000040000010000000000000000000000000028",
		"004b2e0a0002000001158004000f0200020002000200ffff0900000000000000000000000000000000000028",
		"004c2e0a0002000001158005fff0000100010000000000800000050000010000000000000000000000000028",
		"004d2e0a0002000001158005000f0200020002000200ffff0900000000000000000000000000000000000028",
		"004e2e0a0002000001158006fff0000100010000000000800000060000010000000000000000000000000028",
		"004f2e0a0002000001158006000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00502e0a0002000001158007fff0000100010000000000800000070000010000000000000000000000000028",
		"00512e0a0002000001158007000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00522e0a0002000001158008fff0000100010000000000800100000000010000000000000000000000000028",
		"00532e0a0002000001158008000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00542e0a0002000001158009fff0000100010000000000800100010000010000000000000000000000000028",
		"00552e0a0002000001158009000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00562e0a000200000115800afff0000100010000000000800100020000010000000000000000000000000028",
		"00572e0a000200000115800a000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00582e0a000200000115800bfff0000100010000000000800100030000010000000000000000000000000028",
		"00592e0a000200000115800b000f0200020002000200ffff0900000000000000000000000000000000000028",
		"005a2e0a000200000115800cfff0000100010000000000800100040000010000000000000000000000000028",
		"005b2e0a000200000115800c000f0200020002000200ffff0900000000000000000000000000000000000028",
		"005c2e0a000200000115800dfff0000100010000000000800100050000010000000000000000000000000028",
		"005d2e0a000200000115800d000f0200020002000200ffff0900000000000000000000000000000000000028",
		"005e2e0a000200000115800efff0000100010000000000800100060000010000000000000000000000000028",
		"005f2e0a000200000115800e000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00602e0a000200000115800ffff0000100010000000000800100070000010000000000000000000000000028",
		"00612e0a000200000115800f000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00622e0a0002000001158010fff0000100010000000000800200000000010000000000000000000000000028",
		"00632e0a0002000001158010000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00642e0a0002000001158011fff0000100010000000000800200010000010000000000000000000000000028",
		"00652e0a0002000001158011000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00662e0a0002000001158012fff0000100010000000000800200020000010000000000000000000000000028",
		"00672e0a0002000001158012000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00682e0a0002000001158013fff0000100010000000000800200030000010000000000000000000000000028",
		"00692e0a0002000001158013000f0200020002000200ffff0900000000000000000000000000000000000028",
		"006a2e0a0002000001158014fff0000100010000000000800200040000010000000000000000000000000028",
		"006b2e0a0002000001158014000f0200020002000200ffff0900000000000000000000000000000000000028",
		"006c2e0a0002000001158015fff0000100010000000000800200050000010000000000000000000000000028",
		"006d2e0a0002000001158015000f0200020002000200ffff0900000000000000000000000000000000000028",
		"006e2e0a0002000001158016fff0000100010000000000800200060000010000000000000000000000000028",
		"006f2e0a0002000001158016000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00702e0a0002000001158017fff0000100010000000000800200070000010000000000000000000000000028",
		"00712e0a0002000001158017000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00722e0a0002000001158018fff0000100010000000000800300000000010000000000000000000000000028",
		"00732e0a0002000001158018000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00742e0a0002000001158019fff0000100010000000000800300010000010000000000000000000000000028",
		"00752e0a0002000001158019000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00762e0a000200000115801afff0000100010000000000800300020000010000000000000000000000000028",
		"00772e0a000200000115801a000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00782e0a000200000115801bfff0000100010000000000800300030000010000000000000000000000000028",
		"00792e0a000200000115801b000f0200020002000200ffff0900000000000000000000000000000000000028",
		"007a2e0a000200000115801cfff0000100010000000000800300040000010000000000000000000000000028",
		"007b2e0a000200000115801c000f0200020002000200ffff0900000000000000000000000000000000000028",
		"007c2e0a000200000115801dfff0000100010000000000800300050000010000000000000000000000000028",
		"007d2e0a000200000115801d000f0200020002000200ffff0900000000000000000000000000000000000028",
		"007e2e0a000200000115801efff0000100010000000000800300060000010000000000000000000000000028",
		"007f2e0a000200000115801e000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00802e0a000200000115801ffff0000100010000000000800300070000010000000000000000000000000028",
		"00812e0a000200000115801f000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00822e0a0002000001158020fff0000100010000000000800400000000010000000000000000000000000028",
		"00832e0a0002000001158020000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00842e0a0002000001158021fff0000100010000000000800400010000010000000000000000000000000028",
		"00852e0a0002000001158021000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00862e0a0002000001158022fff0000100010000000000800400020000010000000000000000000000000028",
		"00872e0a0002000001158022000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00882e0a0002000001158023fff0000100010000000000800400030000010000000000000000000000000028",
		"00892e0a0002000001158023000f0200020002000200ffff0900000000000000000000000000000000000028",
		"008a2e0a0002000001158024fff0000100010000000000800400040000010000000000000000000000000028",
		"008b2e0a0002000001158024000f0200020002000200ffff0900000000000000000000000000000000000028",
		"008c2e0a0002000001158025fff0000100010000000000800400050000010000000000000000000000000028",
		"008d2e0a0002000001158025000f0200020002000200ffff0900000000000000000000000000000000000028",
		"008e2e0a0002000001158026fff0000100010000000000800400060000010000000000000000000000000028",
		"008f2e0a0002000001158026000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00902e0a0002000001158027fff0000100010000000000800400070000010000000000000000000000000028",
		"00912e0a0002000001158027000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00922e0a0002000001158028fff0000100010000000000800500000000010000000000000000000000000028",
		"00932e0a0002000001158028000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00942e0a0002000001158029fff0000100010000000000800500010000010000000000000000000000000028",
		"00952e0a0002000001158029000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00962e0a000200000115802afff0000100010000000000800500020000010000000000000000000000000028",
		"00972e0a000200000115802a000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00982e0a000200000115802bfff0000100010000000000800500030000010000000000000000000000000028",
		"00992e0a000200000115802b000f0200020002000200ffff0900000000000000000000000000000000000028",
		"009a2e0a000200000115802cfff0000100010000000000800500040000010000000000000000000000000028",
		"009b2e0a000200000115802c000f0200020002000200ffff0900000000000000000000000000000000000028",
		"009c2e0a000200000115802dfff0000100010000000000800500050000010000000000000000000000000028",
		"009d2e0a000200000115802d000f0200020002000200ffff0900000000000000000000000000000000000028",
		"009e2e0a000200000115802efff0000100010000000000800500060000010000000000000000000000000028",
		"009f2e0a000200000115802e000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00a02e0a000200000115802ffff0000100010000000000800500070000010000000000000000000000000028",
		"00a12e0a000200000115802f000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00a22e0a0002000001158030fff0000100010000000000800600000000010000000000000000000000000028",
		"00a32e0a0002000001158030000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00a42e0a0002000001158031fff0000100010000000000800600010000010000000000000000000000000028",
		"00a52e0a0002000001158031000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00a62e0a0002000001158032fff0000100010000000000800600020000010000000000000000000000000028",
		"00a72e0a0002000001158032000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00a82e0a0002000001158033fff0000100010000000000800600030000010000000000000000000000000028",
		"00a92e0a0002000001158033000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00aa2e0a0002000001158034fff0000100010000000000800600040000010000000000000000000000000028",
		"00ab2e0a0002000001158034000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00ac2e0a0002000001158035fff0000100010000000000800600050000010000000000000000000000000028",
		"00ad2e0a0002000001158035000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00ae2e0a0002000001158036fff0000100010000000000800600060000010000000000000000000000000028",
		"00af2e0a0002000001158036000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00b02e0a0002000001158037fff0000100010000000000800600070000010000000000000000000000000028",
		"00b12e0a0002000001158037000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00b22e0a0002000001158038fff0000100010000000000800700000000010000000000000000000000000028",
		"00b32e0a0002000001158038000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00b42e0a0002000001158039fff0000100010000000000800700010000010000000000000000000000000028",
		"00b52e0a0002000001158039000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00b62e0a000200000115803afff0000100010000000000800700020000010000000000000000000000000028",
		"00b72e0a000200000115803a000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00b82e0a000200000115803bfff0000100010000000000800700030000010000000000000000000000000028",
		"00b92e0a000200000115803b000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00ba2e0a000200000115803cfff0000100010000000000800700040000010000000000000000000000000028",
		"00bb2e0a000200000115803c000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00bc2e0a000200000115803dfff0000100010000000000800700050000010000000000000000000000000028",
		"00bd2e0a000200000115803d000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00be2e0a000200000115803efff0000100010000000000800700060000010000000000000000000000000028",
		"00bf2e0a000200000115803e000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00c02e0a000200000115803ffff0000100010000000000800700070000010000000000000000000000000028",
		"00c12e0a000200000115803f000f0200020002000200ffff0900000000000000000000000000000000000028",
		"00c22e0a0002000001168000f000800000000200000000000000000000000000000000000000000000000028",
		"00c32e0a0002000001168001f000800000000200000000000000000000000000000000000000000000000028",
		"00c42e0a0002000001168002f000800000000200000000000000000000000000000000000000000000000028",
		"00c52e0a0002000001168003f000800000000200000000000000000000000000000000000000000000000028",
		"00c62e0a0002000001168004f000800000000200000000000000000000000000000000000000000000000028",
		"00c72e0a0002000001168005f000800000000200000000000000000000000000000000000000000000000028",
		"00c82e0a0002000001168006f000800000000200000000000000000000000000000000000000000000000028",
		"00c92e0a0002000001168007f000800000000200000000000000000000000000000000000000000000000028",
		"00ca2e0a0002000001168008f000800100000200000000000000000000000000000000000000000000000028",
		"00cb2e0a0002000001168009f000800100000200000000000000000000000000000000000000000000000028",
		"00cc2e0a000200000116800af000800100000200000000000000000000000000000000000000000000000028",
		"00cd2e0a000200000116800bf000800100000200000000000000000000000000000000000000000000000028",
		"00ce2e0a000200000116800cf000800100000200000000000000000000000000000000000000000000000028",
		"00cf2e0a000200000116800df000800100000200000000000000000000000000000000000000000000000028",
		"00d02e0a000200000116800ef000800100000200000000000000000000000000000000000000000000000028",
		"00d12e0a000200000116800ff000800100000200000000000000000000000000000000000000000000000028",
		"00d22e0a0002000001168010f000800200000200000000000000000000000000000000000000000000000028",
		"00d32e0a0002000001168011f000800200000200000000000000000000000000000000000000000000000028",
		"00d42e0a0002000001168012f000800200000200000000000000000000000000000000000000000000000028",
		"00d52e0a0002000001168013f000800200000200000000000000000000000000000000000000000000000028",
		"00d62e0a0002000001168014f000800200000200000000000000000000000000000000000000000000000028",
		"00d72e0a0002000001168015f000800200000200000000000000000000000000000000000000000000000028",
		"00d82e0a0002000001168016f000800200000200000000000000000000000000000000000000000000000028",
		"00d92e0a0002000001168017f000800200000200000000000000000000000000000000000000000000000028",
		"00da2e0a0002000001168018f000800300000200000000000000000000000000000000000000000000000028",
		"00db2e0a0002000001168019f000800300000200000000000000000000000000000000000000000000000028",
		"00dc2e0a000200000116801af000800300000200000000000000000000000000000000000000000000000028",
		"00dd2e0a000200000116801bf000800300000200000000000000000000000000000000000000000000000028",
		"00de2e0a000200000116801cf000800300000200000000000000000000000000000000000000000000000028",
		"00df2e0a000200000116801df000800300000200000000000000000000000000000000000000000000000028",
		"00e02e0a000200000116801ef000800300000200000000000000000000000000000000000000000000000028",
		"00e12e0a000200000116801ff000800300000200000000000000000000000000000000000000000000000028",
		"00e22e0a0002000001168020f000800400000200000000000000000000000000000000000000000000000028",
		"00e32e0a0002000001168021f000800400000200000000000000000000000000000000000000000000000028",
		"00e42e0a0002000001168022f000800400000200000000000000000000000000000000000000000000000028",
		"00e52e0a0002000001168023f000800400000200000000000000000000000000000000000000000000000028",
		"00e62e0a0002000001168024f000800400000200000000000000000000000000000000000000000000000028",
		"00e72e0a0002000001168025f000800400000200000000000000000000000000000000000000000000000028",
		"00e82e0a0002000001168026f000800400000200000000000000000000000000000000000000000000000028",
		"00e92e0a0002000001168027f000800400000200000000000000000000000000000000000000000000000028",
		"00ea2e0a0002000001168028f000800500000200000000000000000000000000000000000000000000000028",
		"00eb2e0a0002000001168029f000800500000200000000000000000000000000000000000000000000000028",
		"00ec2e0a000200000116802af000800500000200000000000000000000000000000000000000000000000028",
		"00ed2e0a000200000116802bf000800500000200000000000000000000000000000000000000000000000028",
		"00ee2e0a000200000116802cf000800500000200000000000000000000000000000000000000000000000028",
		"00ef2e0a000200000116802df000800500000200000000000000000000000000000000000000000000000028",
		"00f02e0a000200000116802ef000800500000200000000000000000000000000000000000000000000000028",
		"00f12e0a000200000116802ff000800500000200000000000000000000000000000000000000000000000028",
		"00f22e0a0002000001168030f000800600000200000000000000000000000000000000000000000000000028",
		"00f32e0a0002000001168031f000800600000200000000000000000000000000000000000000000000000028",
		"00f42e0a0002000001168032f000800600000200000000000000000000000000000000000000000000000028",
		"00f52e0a0002000001168033f000800600000200000000000000000000000000000000000000000000000028",
		"00f62e0a0002000001168034f000800600000200000000000000000000000000000000000000000000000028",
		"00f72e0a0002000001168035f000800600000200000000000000000000000000000000000000000000000028",
		"00f82e0a0002000001168036f000800600000200000000000000000000000000000000000000000000000028",
		"00f92e0a0002000001168037f000800600000200000000000000000000000000000000000000000000000028",
		"00fa2e0a0002000001168038f000800700000200000000000000000000000000000000000000000000000028",
		"00fb2e0a0002000001168039f000800700000200000000000000000000000000000000000000000000000028",
		"00fc2e0a000200000116803af000800700000200000000000000000000000000000000000000000000000028",
		"00fd2e0a000200000116803bf000800700000200000000000000000000000000000000000000000000000028",
		"00fe2e0a000200000116803cf000800700000200000000000000000000000000000000000000000000000028",
		"00ff2e0a000200000116803df000800700000200000000000000000000000000000000000000000000000028",
		"01002e0a000200000116803ef000800700000200000000000000000000000000000000000000000000000028",
		"01012e0a000200000116803ff000800700000200000000000000000000000000000000000000000000000028",
		"01022e0a0002000001490401c000000000000000000000000000000000000000000000000000000000000028",
		"01032e0a00020000014904012000000000000000000000000000000000000000000000000000000000000028",
		"01042e0a00020000014904011800ffffffff0000000000000000000000000000000000000000000000000028",
	}
	firstTid := uint16(3)

	for _, packetString := range mibUploadNextSequence {
		data, err := stringToPacket(packetString)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		omciMsg, ok := omciLayer.(*OMCI)
		assert.True(t, ok)
		assert.Equal(t, firstTid, omciMsg.TransactionID)
		assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
		assert.Equal(t, uint16(40), omciMsg.Length)

		msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
		assert.NotNil(t, msgLayer)

		uploadResponse, ok2 := msgLayer.(*MibUploadNextResponse)
		assert.True(t, ok2)
		assert.Equal(t, me.OnuDataClassID, uploadResponse.EntityClass)
		assert.Equal(t, uint16(0), uploadResponse.EntityInstance)

		// Test serialization back to former string
		var options gopacket.SerializeOptions
		options.FixLengths = true

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, options, omciMsg, uploadResponse)
		assert.NoError(t, err)

		outgoingPacket := buffer.Bytes()
		reconstituted := packetToString(outgoingPacket)
		assert.Equal(t, strings.ToLower(packetString), reconstituted)

		// Advance TID
		firstTid += 1
	}
}

// TestUnsupportedG988ClassIDMibUploadNextResponse tests decoding of an Unknown class ID that is
// in the range of IDs assigned for G.988 use
func TestUnsupportedG988ClassIDMibUploadNextResponse(t *testing.T) {
	// The unsupported G.988 class ID below is 37 (0x0025), which is marked in the G.988
	// (11/2017) as 'Intentionally left blank).  The encoded frame is a Get-Next
	// response with a single attribute 1 & 16 (0x8001) encoded.
	//
	tid := 3
	cid := 0x25
	eid := 1
	mask := 0x8000
	omci_hdr := "00032e0a"
	msg_hdr := "00020000"
	reported_me_hdr := "002500018000"
	attr := "0102030405060708090A0B0C0D0E0F101112131415161718191A"
	trailer := "0000002828ce00e2"
	msg := omci_hdr + msg_hdr + reported_me_hdr + attr + trailer
	data, err := stringToPacket(msg)
	assert.NoError(t, err)

	// Decode packet (lazy this time)
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.Lazy)
	assert.NotNil(t, packet)

	// OMCI Layer Contents are the
	//   - TCI          (2 bytes)
	//   - Msg Type     (1 byte)
	//   - Device Ident (1 byte)
	//
	// payload is remaining layers (less optional length and MIC)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	contents := omciLayer.LayerContents()
	payload := omciLayer.LayerPayload()
	assert.NotNil(t, contents)
	assert.NotNil(t, payload)
	assert.Equal(t, len(contents), len(omci_hdr)/2)
	assert.Equal(t, len(payload), len(msg_hdr+reported_me_hdr+attr)/2)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(tid), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, uint16(40), omciMsg.Length)

	// Message Layer contents for a MIB upload next response (baseline message set) are the
	//    - OMCI Message Header (TCI, msg Type, ...)  (4 bytes)
	//
	// Message Layer payload for a MIB upload next response are the
	//    - ONU Data Class/Instance                   (4 bytes)
	//    - Reported Managed Entity Class/Instance    (4 bytes)
	//    - Attribute Mask                            (2 bytes)
	//    - Attributes
	//      and zero-padding (but not length & MIC)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	contents = msgLayer.LayerContents()
	payload = msgLayer.LayerPayload()
	assert.NotNil(t, contents)
	assert.NotNil(t, payload)
	assert.Equal(t, len(msg_hdr)/2, len(contents))
	assert.Equal(t, len(reported_me_hdr+attr)/2, len(payload))

	uploadResponse, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, uploadResponse)

	assert.Equal(t, me.OnuDataClassID, uploadResponse.EntityClass)
	assert.Equal(t, uint16(0), uploadResponse.EntityInstance)
	assert.Equal(t, me.ClassID(cid), uploadResponse.ReportedME.GetClassID())
	assert.Equal(t, uint16(eid), uploadResponse.ReportedME.GetEntityID())
	assert.Equal(t, uint16(mask), uploadResponse.ReportedME.GetAttributeMask())

	name := "UnknownAttr_1"
	blobAttribute, err := uploadResponse.ReportedME.GetAttribute(name)
	assert.Nil(t, err)
	assert.NotNil(t, blobAttribute)
}

func TestUnsupportedG988ClassIDMibUploadNextResponseAttributes(t *testing.T) {
	// Same as previous, but try different attribute mask combinations
	tid := 3
	cid := 0x25
	eid := 1

	// There are a number of ranges for vendor ID use. List below picks one from
	// each of those ranges
	masks := []uint16{0x8001, 0x0000, 0x0001, 0x8000}

	trailer := "0000002828ce00e2"
	attr := "0102030405060708090A0B0C0D0E0F101112131415161718191A"

	for _, mask := range masks {
		hdr := fmt.Sprintf("00032e0a0002000000250001%04x", mask)

		msg := hdr + attr + trailer
		data, err := stringToPacket(msg)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, packet)

		omciMsg, ok := omciLayer.(*OMCI)
		assert.True(t, ok)
		assert.Equal(t, uint16(tid), omciMsg.TransactionID)
		assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
		assert.Equal(t, uint16(40), omciMsg.Length)

		msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
		assert.NotNil(t, msgLayer)

		uploadResponse, ok2 := msgLayer.(*MibUploadNextResponse)
		assert.True(t, ok2)
		assert.NotNil(t, uploadResponse)
		assert.Equal(t, me.OnuDataClassID, uploadResponse.EntityClass)
		assert.Equal(t, uint16(0), uploadResponse.EntityInstance)
		assert.Equal(t, me.ClassID(cid), uploadResponse.ReportedME.GetClassID())
		assert.Equal(t, uint16(eid), uploadResponse.ReportedME.GetEntityID())
		assert.Equal(t, mask, uploadResponse.ReportedME.GetAttributeMask())
	}
}

// TestUnsupportedVendorClassIDMibUploadNextResponse tests decoding of an Unknown class ID that is
// in the range of IDs assigned for vendor assignment
func TestUnsupportedVendorClassIDMibUploadNextResponse(t *testing.T) {
	tid := 3
	eid := 0
	mask := 0x8000

	// There are a number of ranges for vendor ID use. List below picks one from
	// each of those ranges
	classIDs := []uint16{250, 355, 65500}

	hdr := "00032e0a00020000"
	attr := "0102030405060708090A0B0C0D0E0F101112131415161718191A"
	trailer := "0000002828ce00e2"

	for _, cid := range classIDs {
		cidToMask := fmt.Sprintf("%04x%04x%04x", cid, eid, mask)
		msg := hdr + cidToMask + attr + trailer
		data, err := stringToPacket(msg)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, packet)

		omciMsg, ok := omciLayer.(*OMCI)
		assert.True(t, ok)
		assert.Equal(t, uint16(tid), omciMsg.TransactionID)
		assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
		assert.Equal(t, uint16(40), omciMsg.Length)

		msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
		assert.NotNil(t, msgLayer)

		uploadResponse, ok2 := msgLayer.(*MibUploadNextResponse)
		assert.True(t, ok2)
		assert.NotNil(t, uploadResponse)
		assert.Equal(t, me.OnuDataClassID, uploadResponse.EntityClass)
		assert.Equal(t, uint16(0), uploadResponse.EntityInstance)
		assert.Equal(t, me.ClassID(cid), uploadResponse.ReportedME.GetClassID())
		assert.Equal(t, uint16(eid), uploadResponse.ReportedME.GetEntityID())
		assert.Equal(t, uint16(mask), uploadResponse.ReportedME.GetAttributeMask())

		name := "UnknownAttr_1"
		blobAttribute, err := uploadResponse.ReportedME.GetAttribute(name)

		assert.Nil(t, err)
		assert.NotNil(t, blobAttribute)

		byteValue, ok3 := blobAttribute.([]uint8)
		assert.True(t, ok3)
		assert.NotNil(t, byteValue)
	}
}

func TestMibUpload(t *testing.T) {
	mibUpload := "00304D0A000200000000000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(mibUpload)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x30), omciMsg.TransactionID)
	assert.Equal(t, MibUploadRequestType, omciMsg.MessageType)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibUploadRequest)
	assert.NotNil(t, msgLayer)

	uploadRequest, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.Equal(t, me.OnuDataClassID, uploadRequest.EntityClass)
	assert.Equal(t, uint16(0), uploadRequest.EntityInstance)

	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciMsg, uploadRequest)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(mibUpload), reconstituted)
}
