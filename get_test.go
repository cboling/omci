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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	. "github.com/cboling/omci"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestGetRequestDecode(t *testing.T) {
	goodMessage := "035e490a01070000004400000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetRequestSerialize(t *testing.T) {
	goodMessage := "035e490a01070000004400000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x0044),
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

func TestGetResponseDecode(t *testing.T) {
	goodMessage := "035e290a01070000000044dbcb05f10000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.Result, me.Success)
	assert.Equal(t, response.AttributeMask, uint16(0x0044))
	assert.Equal(t, response.Attributes["TransmitOpticalLevel"], uint16(0x05f1))
	assert.Equal(t, response.Attributes["OpticalSignalLevel"], uint16(0xdbcb))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetResponseSerialize(t *testing.T) {
	goodMessage := "035e290a01070000000044dbcb05f10000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0x0044),
		Attributes: me.AttributeValueMap{
			"TransmitOpticalLevel": uint16(0x05f1),
			"OpticalSignalLevel":   uint16(0xdbcb)},
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

///////////////////////////////////////////////////////////////////////
// Packet definitions for attributes of various types/sizes
func toOctets(str string) []byte {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("Invalid Base-64 string: '%v'", str))
	}
	return data
}

func TestGetResponseSerializeTruncationFailure(t *testing.T) {
	// Too much data and 'fix-length' is not specified.  This response has 26
	// octets in the requested data, but only 25 octets available

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0xE000),
		Attributes: me.AttributeValueMap{
			"VendorId":     toOctets("ICAgIA=="),
			"Version":      toOctets("MAAAAAAAAAAAAAAAAAA="),
			"SerialNumber": toOctets("AAAAAAAAAAA="),
		},
	}
	// Test serialization and verify truncation failure
	var options gopacket.SerializeOptions
	options.FixLengths = false

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
	assert.IsType(t, &me.MessageTruncatedError{}, err)
}

func TestGetResponseSerializeTruncationButOkay(t *testing.T) {
	// Too much data and 'fix-length' is specified so it packs as much as
	// possible and adjusts the failure masks

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	response := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0xE000),
		Attributes: me.AttributeValueMap{
			"VendorId":     toOctets("ICAgIA=="),
			"Version":      toOctets("MAAAAAAAAAAAAAAAAAA="),
			"SerialNumber": toOctets("AAAAAAAAAAA="),
		},
	}
	// Test serialization and verify truncation failure
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, response)
	assert.NoError(t, err)

	// Now deserialize it and see if we have the proper result (Attribute Failure)
	// and a non-zero failed mask
	responsePacket := buffer.Bytes()
	packet := gopacket.NewPacket(responsePacket, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer2 := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer2)

	omciMsg2, ok := omciLayer2.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciLayer.TransactionID, omciMsg2.TransactionID)
	assert.Equal(t, omciLayer.MessageType, GetResponseType)
	assert.Equal(t, omciLayer.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciLayer.Length, uint16(40))

	msgLayer2 := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer2)

	response2, ok2 := msgLayer2.(*GetResponse)
	assert.True(t, ok2)
	assert.Equal(t, me.AttributeFailure, response2.Result)
	assert.NotZero(t, response2.AttributeMask)
	assert.NotZero(t, response2.FailedAttributeMask)
	assert.Zero(t, response2.UnsupportedAttributeMask)
}

func TestGetResponseTableFailedAttributesDecode(t *testing.T) {
	// This is a GET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestGetResponseTableFailedAttributesSerialize(t *testing.T) {
	// This is a GET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestGetResponseTableAttributeDecode(t *testing.T) {
	// This is a GET Response for a table attribute. It should return the attribute
	// size as a uint16.
	// TODO:Implement
}

func TestGetResponseTableAttributeSerialize(t *testing.T) {
	// This is a GET Response for a table attribute. It should return the attribute
	// size as a uint16.
	// TODO:Implement
}

func TestExtendedGetRequestDecode(t *testing.T) {
	//ONU-2G: 257
	goodMessage := "035e490b010100000002fffc"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, ExtendedIdent)
	assert.Equal(t, omciMsg.Length, uint16(2))

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	//ONU-2G: 257
	assert.Equal(t, me.Onu2GClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)
	assert.Equal(t, uint16(0xfffc), request.AttributeMask)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedGetRequestDecodeTruncated(t *testing.T) {
	goodMessage := "035e490b010100000002ff"
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

func TestExtendedGetRequestSerialize(t *testing.T) {
	goodMessage := "035e490b010100000002fffc"

	omciLayer := &OMCI{
		TransactionID:    0x035e,
		MessageType:      GetRequestType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &GetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.Onu2GClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		AttributeMask: uint16(0xfffc),
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

func TestExtendedGetResponseDecode(t *testing.T) {
	attrDef, omciErr := me.GetAttributesDefinitions(me.Onu2GClassID)
	assert.NotNil(t, attrDef)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), me.Success)

	attributes := []interface{}{
		toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAA="), //  1: MultiByteField - "EquipmentId"  (20 zeros)
		byte(0xb4),                               //  2: ByteField   - "OpticalNetworkUnitManagementAndControlChannelOmccVersion"
		uint16(0x1234),                           //  3: Uint16Field - "VendorProductCode"
		byte(1),                                  //  4: ByteField   - "SecurityCapability"
		byte(1),                                  //  5: ByteField   - "SecurityMode"
		uint16(0x5678),                           //  6: Uint16Field - "TotalPriorityQueueNumber"
		byte(0x44),                               //  7: ByteField   - "TotalTrafficSchedulerNumber"
		byte(1),                                  //  8: ByteField   - "Deprecated"
		uint16(0x55aa),                           //  9: Uint16Field - "TotalGemPortIdNumber"
		uint32(0xC4108011),                       // 10: Uint32Field - "Sysuptime"
		uint16(0x6),                              // 11: Uint16Field - "ConnectivityCapability"
		byte(6),                                  // 12: ByteField   - "CurrentConnectivityMode"
		uint16(2),                                // 13: Uint16Field - "QualityOfServiceQosConfigurationFlexibility"
		uint16(0x1234),                           // 14: Uint16Field - "PriorityQueueScaleFactor"
	}
	attributeData := make([]byte, 0)

	// Walk through all attributes and encode them
	for _, value := range attributes {
		//attrDef, err := meDef.GetAttributeByIndex(index)
		var buf []byte
		u8, ok := value.(byte)
		if ok {
			buf = []byte{u8}
		} else {
			u16, ok := value.(uint16)
			if ok {
				buf = make([]byte, 2)
				binary.BigEndian.PutUint16(buf, u16)
			} else {
				u32, ok := value.(uint32)
				if ok {
					buf = make([]byte, 4)
					binary.BigEndian.PutUint32(buf, u32)
				} else {
					bytes, ok := value.([]byte)
					if ok {
						buf = bytes
					} else {
						assert.True(t, false) // Unknown attribute type
					}
				}
			}
		}
		attributeData = append(attributeData, buf...)
	}
	attributeMask := 0xfffc
	msgLength := len(attributeData) + 7
	// Results is 0 ("00"), and the two optional attribute masks are 0 ("00000000") as well
	goodMessage := "035e290b01010000" + fmt.Sprintf("%04x", msgLength) +
		"00" + fmt.Sprintf("%04x", attributeMask) + "00000000" + packetToString(attributeData)

	data, err := stringToPacket(goodMessage)
	assert.NotNil(t, data)
	assert.Nil(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, ExtendedIdent)
	assert.Equal(t, omciMsg.Length, uint16(msgLength))

	msgLayer := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.Result, me.Success)
	assert.Equal(t, response.AttributeMask, uint16(attributeMask))
	assert.Equal(t, response.FailedAttributeMask, uint16(0))
	assert.Equal(t, response.UnsupportedAttributeMask, uint16(0))

	assert.Equal(t, response.Attributes["EquipmentId"], toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	assert.Equal(t, response.Attributes["OpticalNetworkUnitManagementAndControlChannelOmccVersion"], byte(0xb4)) //  )
	assert.Equal(t, response.Attributes["VendorProductCode"], uint16(0x1234))
	assert.Equal(t, response.Attributes["SecurityCapability"], byte(1))
	assert.Equal(t, response.Attributes["SecurityMode"], byte(1))
	assert.Equal(t, response.Attributes["TotalPriorityQueueNumber"], uint16(0x5678))
	assert.Equal(t, response.Attributes["TotalTrafficSchedulerNumber"], byte(0x44))
	assert.Equal(t, response.Attributes["Deprecated"], byte(1))
	assert.Equal(t, response.Attributes["TotalGemPortIdNumber"], uint16(0x55aa))
	assert.Equal(t, response.Attributes["Sysuptime"], uint32(0xC4108011))
	assert.Equal(t, response.Attributes["ConnectivityCapability"], uint16(0x6))
	assert.Equal(t, response.Attributes["CurrentConnectivityMode"], byte(6))
	assert.Equal(t, response.Attributes["QualityOfServiceQosConfigurationFlexibility"], uint16(2))
	assert.Equal(t, response.Attributes["PriorityQueueScaleFactor"], uint16(0x1234))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedGetResponseSerialize(t *testing.T) {
	goodMessage := "035e290b01010000003100fffc" +
		"000000000000000000000000000000000000000000000000" +
		"b4123401015678440155aac410801100060600021234"

	omciLayer := &OMCI{
		TransactionID:    0x035e,
		MessageType:      GetResponseType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.Onu2GClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		Result:        0,
		AttributeMask: uint16(0xfffc),
		Attributes: me.AttributeValueMap{
			"EquipmentId": toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			"OpticalNetworkUnitManagementAndControlChannelOmccVersion": byte(0xb4),
			"VendorProductCode":                           uint16(0x1234),
			"SecurityCapability":                          byte(1),
			"SecurityMode":                                byte(1),
			"TotalPriorityQueueNumber":                    uint16(0x5678),
			"TotalTrafficSchedulerNumber":                 byte(0x44),
			"Deprecated":                                  byte(1),
			"TotalGemPortIdNumber":                        uint16(0x55aa),
			"Sysuptime":                                   uint32(0xC4108011),
			"ConnectivityCapability":                      uint16(0x6),
			"CurrentConnectivityMode":                     byte(6),
			"QualityOfServiceQosConfigurationFlexibility": uint16(2),
			"PriorityQueueScaleFactor":                    uint16(0x1234),
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
