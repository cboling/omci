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

func TestMibResetRequestDecode(t *testing.T) {
	goodMessage := "01094f0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, MibResetRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibResetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibResetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, me.OnuDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibResetRequestSerialize(t *testing.T) {
	goodMessage := "01094f0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0109,
		MessageType:   MibResetRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibResetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuDataClassID,
			// Default Instance ID is 0
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

func TestMibResetResponseDecode(t *testing.T) {
	goodMessage := "00012F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, MibResetResponseType)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibResetResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibResetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibResetResponseSerialize(t *testing.T) {
	goodMessage := "00012F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x01,
		MessageType:   MibResetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibResetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuDataClassID,
			// Default Instance ID is 0
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

func TestExtendedMibResetRequestDecode(t *testing.T) {
	goodMessage := "01094f0b000200000000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, MibResetRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(0), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibResetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibResetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, me.OnuDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedMibResetRequestSerialize(t *testing.T) {
	goodMessage := "01094f0b000200000000"

	omciLayer := &OMCI{
		TransactionID:    0x0109,
		MessageType:      MibResetRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &MibResetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuDataClassID,
			Extended:    true,
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

func TestExtendedMibResetResponseDecode(t *testing.T) {
	goodMessage := "00012F0B00020000000106"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, MibResetResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeMibResetResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibResetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedMibResetResponseSerialize(t *testing.T) {
	goodMessage := "00012F0B00020000000106"

	omciLayer := &OMCI{
		TransactionID:    0x01,
		MessageType:      MibResetResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &MibResetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuDataClassID,
			Extended:    true,
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
