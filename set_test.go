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

func TestSetRequestDecode(t *testing.T) {
	goodMessage := "0107480a01000000020000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0107))
	assert.Equal(t, omciMsg.MessageType, SetRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetRequestSerialize(t *testing.T) {
	goodMessage := "0107480a01000000020001000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0107,
		MessageType:   SetRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x200),
		Attributes:    me.AttributeValueMap{"AdministrativeState": byte(1)},
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

func TestSetResponseDecode(t *testing.T) {
	goodMessage := "0107280a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0107))
	assert.Equal(t, omciMsg.MessageType, SetResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetResponseSerialize(t *testing.T) {
	goodMessage := "0107280a01000000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0107,
		MessageType:   SetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result: me.Success,
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

func TestExtendedSetRequestDecode(t *testing.T) {
	goodMessage := "0107480b010000000003020001"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint16(0x0200), request.AttributeMask)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedSetRequestSerialize(t *testing.T) {
	goodMessage := "0107480b010000000003020001"

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		AttributeMask: uint16(0x200),
		Attributes:    me.AttributeValueMap{"AdministrativeState": byte(1)},
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

func TestExtendedSetResponseDecode(t *testing.T) {
	goodMessage := "0107280b01000000000100"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)
	// TODO: Also test result == 9 decode

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.Success, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedSetResponseSerialize(t *testing.T) {
	goodMessage := "0107280b01000000000103"

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		Result: me.ParameterError,
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

func TestSetResponseTableFailedAttributesDecode(t *testing.T) {
	// This is a SET Response with failed and unsupported attributes
	// TODO:Implement (also implement for Extended message set)
}

func TestSetResponseTableFailedAttributesSerialize(t *testing.T) {
	// This is a SET Response with failed and unsupported attributes
	// TODO:Implement (also implement for Extended message set)
}
