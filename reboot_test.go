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

func TestRebootRequestDecode(t *testing.T) {
	goodMessage := "0001590a01000000010000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0001))
	assert.Equal(t, omciMsg.MessageType, RebootRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeRebootRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*RebootRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.OnuGClassID)
	assert.Equal(t, request.EntityInstance, uint16(0))
	assert.Equal(t, request.RebootCondition, uint8(1))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestRebootRequestSerialize(t *testing.T) {
	goodMessage := "0001590a01000000020000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0001,
		MessageType:   RebootRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &RebootRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			// Default Instance ID is 0
		},
		RebootCondition: uint8(2),
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

func TestRebootResponseDecode(t *testing.T) {
	goodMessage := "023c390a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x023c))
	assert.Equal(t, omciMsg.MessageType, RebootResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeRebootResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*RebootResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.EntityClass, me.OnuGClassID)
	assert.Equal(t, response.EntityInstance, uint16(0))
	assert.Equal(t, response.Result, me.Success)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestRebootResponseSerialize(t *testing.T) {
	goodMessage := "023c390a01000000060000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x023c,
		MessageType:   RebootResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &RebootResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
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

func TestExtendedRebootRequestDecode(t *testing.T) {
	goodMessage := "0001590b01000000000101"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0001), omciMsg.TransactionID)
	assert.Equal(t, RebootRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeRebootRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*RebootRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, me.OnuGClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)
	assert.Equal(t, uint8(1), request.RebootCondition)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedRebootRequestSerialize(t *testing.T) {
	goodMessage := "0001590b01000000000102"

	omciLayer := &OMCI{
		TransactionID:    0x0001,
		MessageType:      RebootRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &RebootRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			Extended:    true,
		},
		RebootCondition: uint8(2),
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

func TestExtendedRebootResponseDecode(t *testing.T) {
	goodMessage := "023c390b01000000000100"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x023c), omciMsg.TransactionID)
	assert.Equal(t, RebootResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeRebootResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*RebootResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.OnuGClassID, response.EntityClass)
	assert.Equal(t, uint16(0), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedRebootResponseSerialize(t *testing.T) {
	goodMessage := "023c390b01000000000106"

	omciLayer := &OMCI{
		TransactionID:    0x023c,
		MessageType:      RebootResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &RebootResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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
