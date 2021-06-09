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

func TestSynchronizeTimeRequestDecode(t *testing.T) {
	goodMessage := "0109580a0100000007e20c0101301b0000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, SynchronizeTimeRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SynchronizeTimeRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.Year, uint16(2018))
	assert.Equal(t, request.Month, uint8(12))
	assert.Equal(t, request.Day, uint8(1))
	assert.Equal(t, request.Hour, uint8(01))
	assert.Equal(t, request.Minute, uint8(48))
	assert.Equal(t, request.Second, uint8(27))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSynchronizeTimeRequestSerialize(t *testing.T) {
	goodMessage := "0109580a0100000007e20c0101301b0000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0109,
		MessageType:   SynchronizeTimeRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SynchronizeTimeRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			// Default Instance ID is 0
		},
		Year:   uint16(2018),
		Month:  uint8(12),
		Day:    uint8(1),
		Hour:   uint8(01),
		Minute: uint8(48),
		Second: uint8(27),
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

func TestSynchronizeTimeResponseDecode(t *testing.T) {
	goodMessage := "0109380a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, SynchronizeTimeResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SynchronizeTimeResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSynchronizeTimeResponseSerialize(t *testing.T) {
	goodMessage := "0109380a01000000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0109,
		MessageType:   SynchronizeTimeResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SynchronizeTimeResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:         me.Success,
		SuccessResults: uint8(0),
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

func TestExtendedSynchronizeTimeRequestDecode(t *testing.T) {
	goodMessage := "0109580b01000000000707e20c0101301b"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, SynchronizeTimeRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(7), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SynchronizeTimeRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint16(2018), request.Year)
	assert.Equal(t, uint8(12), request.Month)
	assert.Equal(t, uint8(1), request.Day)
	assert.Equal(t, uint8(01), request.Hour)
	assert.Equal(t, uint8(48), request.Minute)
	assert.Equal(t, uint8(27), request.Second)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedSynchronizeTimeRequestSerialize(t *testing.T) {
	goodMessage := "0109580b01000000000707e20c0101301b"

	omciLayer := &OMCI{
		TransactionID:    0x0109,
		MessageType:      SynchronizeTimeRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SynchronizeTimeRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			Extended:    true,
		},
		Year:   uint16(2018),
		Month:  uint8(12),
		Day:    uint8(1),
		Hour:   uint8(01),
		Minute: uint8(48),
		Second: uint8(27),
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

func TestExtendedSynchronizeTimeResponseDecode(t *testing.T) {
	goodMessage := "0109380b0100000000020001"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, SynchronizeTimeResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SynchronizeTimeResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint8(1), response.SuccessResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedSynchronizeTimeResponseSerialize(t *testing.T) {
	goodMessage := "0109380b0100000000020001"

	omciLayer := &OMCI{
		TransactionID:    0x0109,
		MessageType:      SynchronizeTimeResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SynchronizeTimeResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			Extended:    true,
		},
		Result:         me.Success,
		SuccessResults: uint8(1),
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
