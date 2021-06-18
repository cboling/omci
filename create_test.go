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

func TestCreateRequestDecode(t *testing.T) {
	goodMessage := "000C440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"
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
	assert.Equal(t, LayerTypeCreateRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0xc), omciMsg.TransactionID)
	assert.Equal(t, CreateRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeCreateRequest, request.LayerType())
	assert.Equal(t, LayerTypeCreateRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.GemPortNetworkCtpClassID, request.EntityClass)
	assert.Equal(t, uint16(0x100), request.EntityInstance)

	attributes := request.Attributes
	assert.NotNil(t, attributes)

	// As this is a create request, gather up all set-by-create attributes
	// make sure we got them all, and nothing else
	meDefinition, omciErr := me.LoadManagedEntityDefinition(request.EntityClass)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), me.Success)

	attrDefs := meDefinition.GetAttributeDefinitions()

	sbcMask := getSbcMask(meDefinition)
	for index := uint(1); index < uint(len(attrDefs)); index++ {
		attrName := attrDefs[index].GetName()

		if sbcMask&uint16(1<<(uint)(16-index)) != 0 {
			_, ok3 := attributes[attrName]
			assert.True(t, ok3)
		} else {
			_, ok3 := attributes[attrName]
			assert.False(t, ok3)
		}
		//fmt.Printf("Name: %v, Value: %v\n", attrName, attributes[attrName])
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciMsg, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCreateRequestSerialize(t *testing.T) {
	goodMessage := "000C440A010C0100040080000301000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0c,
		MessageType:   CreateRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GemPortNetworkCtpClassID,
			EntityInstance: uint16(0x100),
		},
		Attributes: me.AttributeValueMap{
			"PortId":                              0x400,
			"TContPointer":                        0x8000,
			"Direction":                           3,
			"TrafficManagementPointerForUpstream": 0x100,
			"TrafficDescriptorProfilePointerForUpstream":   0,
			"PriorityQueuePointerForDownStream":            0,
			"TrafficDescriptorProfilePointerForDownstream": 0,
			"EncryptionKeyRing":                            0,
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

func TestCreateResponseDecode(t *testing.T) {
	goodMessage := "0157240a01100001000000000000000000000000000000000000000000000000000000000000000000000028a9ccbeb9"
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
	assert.Equal(t, LayerTypeCreateResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0157), omciMsg.TransactionID)
	assert.Equal(t, CreateResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CreateResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeCreateResponse, response.LayerType())
	assert.Equal(t, LayerTypeCreateResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCreateResponseSerialize(t *testing.T) {
	goodMessage := "0157240a01100001000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0157,
		MessageType:   CreateResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CreateResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: uint16(1),
		},
		Result:                 me.Success,
		AttributeExecutionMask: uint16(0),
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

func TestExtendedCreateRequestDecode(t *testing.T) {
	goodMessage := "000C440B010C0100000E0400800003010000000000000000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)
	// TODO: Trailing optional SBC attributes can be omitted at the option
	//       of the transmitter
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeCreateRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0xc), omciMsg.TransactionID)
	assert.Equal(t, CreateRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(14), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeCreateRequest, request.LayerType())
	assert.Equal(t, LayerTypeCreateRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.GemPortNetworkCtpClassID, request.EntityClass)
	assert.Equal(t, uint16(0x100), request.EntityInstance)

	attributes := request.Attributes
	assert.NotNil(t, attributes)

	// As this is a create request, gather up all set-by-create attributes
	// make sure we got them all, and nothing else
	meDefinition, omciErr := me.LoadManagedEntityDefinition(request.EntityClass)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), me.Success)

	attrDefs := meDefinition.GetAttributeDefinitions()

	sbcMask := getSbcMask(meDefinition)
	for index := uint(1); index < uint(len(attrDefs)); index++ {
		attrName := attrDefs[index].GetName()

		if sbcMask&uint16(1<<(uint)(16-index)) != 0 {
			_, ok3 := attributes[attrName]
			assert.True(t, ok3)
		} else {
			_, ok3 := attributes[attrName]
			assert.False(t, ok3)
		}
		//fmt.Printf("Name: %v, Value: %v\n", attrName, attributes[attrName])
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciMsg, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedCreateRequestSerialize(t *testing.T) {
	goodMessage := "000C440B010C0100000E0400800003010000000000000000"
	omciLayer := &OMCI{
		TransactionID:    0x0c,
		MessageType:      CreateRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GemPortNetworkCtpClassID,
			EntityInstance: uint16(0x100),
			Extended:       true,
		},
		Attributes: me.AttributeValueMap{
			"PortId":                              0x0400,
			"TContPointer":                        0x8000,
			"Direction":                           3,
			"TrafficManagementPointerForUpstream": 0x100,
			"TrafficDescriptorProfilePointerForUpstream":   0,
			"PriorityQueuePointerForDownStream":            0,
			"TrafficDescriptorProfilePointerForDownstream": 0,
			"EncryptionKeyRing":                            0,
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

func TestExtendedCreateResponseDecode(t *testing.T) {
	goodMessage := "0157240b01100001000100"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)
	// TODO: Also test sending reason code 3

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeCreateResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0157), omciMsg.TransactionID)
	assert.Equal(t, CreateResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CreateResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeCreateResponse, response.LayerType())
	assert.Equal(t, LayerTypeCreateResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.Success, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedCreateResponseSerialize(t *testing.T) {
	goodMessage := "0157240b01100001000100"

	omciLayer := &OMCI{
		TransactionID:    0x0157,
		MessageType:      CreateResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &CreateResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		Result:                 me.Success,
		AttributeExecutionMask: uint16(0), // Optional since success
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
