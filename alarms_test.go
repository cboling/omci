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

func TestGetAllAlarmsRequestDecode(t *testing.T) {
	goodMessage := "04454b0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0445))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.AlarmRetrievalMode, byte(0))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsRequestSerialize(t *testing.T) {
	goodMessage := "04454b0a00020000010000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0445,
		MessageType:   GetAllAlarmsRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AlarmRetrievalMode: byte(1),
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

func TestGetAllAlarmsResponseDecode(t *testing.T) {
	goodMessage := "04452b0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0445))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.NumberOfCommands, uint16(3))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsResponseSerialize(t *testing.T) {
	goodMessage := "04452b0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0445,
		MessageType:   GetAllAlarmsResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		NumberOfCommands: uint16(3),
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

func TestGetAllAlarmsNextRequestDecode(t *testing.T) {
	goodMessage := "02344c0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0234))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsNextRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextRequestSerialize(t *testing.T) {
	goodMessage := "02344c0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0234,
		MessageType:   GetAllAlarmsNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		CommandSequenceNumber: uint16(0),
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

func TestGetAllAlarmsNextResponseDecode(t *testing.T) {
	goodMessage := "02342c0a00020000000b01028000000000000000000000000000000000000000000000000000000000000028f040fc87"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0234))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsNextResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	var alarms [224 / 8]byte
	alarms[0] = 0x80
	assert.Equal(t, response.AlarmEntityClass, me.PhysicalPathTerminationPointEthernetUniClassID)
	assert.Equal(t, response.AlarmEntityInstance, uint16(0x102))
	assert.Equal(t, response.AlarmBitMap, alarms)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextResponseSerialize(t *testing.T) {
	goodMessage := "02342c0a00020000000b01028000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0234,
		MessageType:   GetAllAlarmsNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	request := &GetAllAlarmsNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AlarmEntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
		AlarmEntityInstance: uint16(0x102),
		AlarmBitMap:         alarms,
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

func TestGetAllAlarmsNextResponseBadCommandNumberDecode(t *testing.T) {
	// Test of a GetNext Response that results when an invalid command number
	// is requested. In the case where the ONU receives a get all alarms next
	// request message in which the command sequence number is out of range,
	// the ONU should respond with a message in which bytes 9 to 40 are all
	// set to 0. This corresponds to a response with entity class 0, entity
	// instance 0, and bit map all 0s.
	//TODO: Implement
}

func TestGetAllAlarmsNextResponseBadCommandNumberSerialize(t *testing.T) {
	// Test of a GetNext Response that results when an invalid command number
	// is requested.
	//TODO: Implement
}

// TODO: Create request/response tests for all of the following types -> SetTable

func TestAlarmNotificationDecode(t *testing.T) {
	goodMessage := "0000100a000b0104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AlarmNotificationType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.PhysicalPathTerminationPointEthernetUniClassID)
	assert.Equal(t, request.EntityInstance, uint16(0x104))
	assert.Equal(t, request.AlarmBitmap, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	assert.Equal(t, request.AlarmSequenceNumber, byte(5))

	// Active/Clear tests
	active, err2 := request.IsAlarmActive(0)
	clear, err3 := request.IsAlarmClear(0)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.True(t, active)
	assert.False(t, clear)

	// Active/Clear for undefined alarm bits
	active, err2 = request.IsAlarmActive(1)
	clear, err3 = request.IsAlarmClear(1)
	assert.NotNil(t, err2)
	assert.NotNil(t, err3)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestInvalidClassAlarmNotificationDecode(t *testing.T) {
	// Choosing GalEthernetProfile (272) since it does not support alarms, show we should
	// file the decode
	badMessage := "0000100a01100104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(badMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AlarmNotificationType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.Nil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.False(t, ok2)
	assert.Nil(t, request)
}

func TestUnknownsMeAlarmNotificationDecode(t *testing.T) {
	// Choosing class ID 22 since it is in the G.988 class ID space and is reserved
	goodMessage := "0000100a00160104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AlarmNotificationType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.ClassID(22))
	assert.Equal(t, request.EntityInstance, uint16(0x104))
	assert.Equal(t, request.AlarmBitmap, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	assert.Equal(t, request.AlarmSequenceNumber, byte(5))
}

func TestVendorSpecificAlarmNotificationDecode(t *testing.T) {
	// Choosing class ID 255 since it is in the first vendor specific class ID space
	goodMessage := "0000100a00FF0104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AlarmNotificationType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.ClassID(255))
	assert.Equal(t, request.EntityInstance, uint16(0x104))
	assert.Equal(t, request.AlarmBitmap, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	assert.Equal(t, request.AlarmSequenceNumber, byte(5))
}

func TestAlarmNotificationSerialize(t *testing.T) {
	goodMessage := "0000100a000b0104800000000000000000000000000000000000000000000000000000000000000500000028"

	omciLayer := &OMCI{
		TransactionID: 0,
		MessageType:   AlarmNotificationType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &AlarmNotificationMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
			EntityInstance: uint16(0x104),
		},
		AlarmBitmap: [28]byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AlarmSequenceNumber: byte(5),
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

func TestExtendedAlarmNotificationDecode(t *testing.T) {
	//                                   1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
	goodMessage := "0000100b000b0104001d8000000000000000000000000000000000000000000000000000000005"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(29), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, request.EntityClass)
	assert.Equal(t, uint16(0x104), request.EntityInstance)
	assert.Equal(t, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, request.AlarmBitmap)
	assert.Equal(t, byte(5), request.AlarmSequenceNumber)

	// Active/Clear tests
	active, err2 := request.IsAlarmActive(0)
	clear, err3 := request.IsAlarmClear(0)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.True(t, active)
	assert.False(t, clear)

	// Active/Clear for undefined alarm bits
	active, err2 = request.IsAlarmActive(1)
	clear, err3 = request.IsAlarmClear(1)
	assert.NotNil(t, err2)
	assert.NotNil(t, err3)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedAlarmNotificationSerialize(t *testing.T) {
	//                                   1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
	goodMessage := "0000100b000b0104001d8000000000000000000000000000000000000000000000000000000005"

	omciLayer := &OMCI{
		TransactionID:    0,
		MessageType:      AlarmNotificationType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &AlarmNotificationMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
			EntityInstance: uint16(0x104),
			Extended:       true,
		},
		AlarmBitmap: [28]byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AlarmSequenceNumber: byte(5),
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
