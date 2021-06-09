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
	. "github.com/cboling/omci"
	me "github.com/cboling/omci/generated"
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
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0360))
	assert.Equal(t, omciMsg.MessageType, MibUploadRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))
	msgLayer := packet.Layer(LayerTypeMibUploadRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

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
	var alarms [224 / 8]byte
	alarms[0] = 0x80

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

func TestMibUploadResponse(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0360))
	assert.Equal(t, omciMsg.MessageType, MibUploadResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
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
	var alarms [224 / 8]byte
	alarms[0] = 0x80

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
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0286))
	assert.Equal(t, omciMsg.MessageType, MibUploadNextRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.CommandSequenceNumber, uint16(0x3a))

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
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0286))
	assert.Equal(t, omciMsg.MessageType, MibUploadNextResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.ReportedME.GetClassID(), me.PriorityQueueClassID)
	assert.Equal(t, response.ReportedME.GetEntityID(), uint16(0))

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

func TestMibUploadNextResponseSerialize(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010000000000000000000000000028"

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
			"BackPressureOperation":                               uint16(0),
			"BackPressureTime":                                    uint32(0),
			"BackPressureOccurQueueThreshold":                     uint16(0),
			"BackPressureClearQueueThreshold":                     uint16(0),
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
