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
package omci

import (
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

// TODO: Move test of generated items to Generated...

var allMsgTypes = [...]me.MsgType{
	me.Create,
	me.Delete,
	me.Set,
	me.Get,
	me.GetAllAlarms,
	me.GetAllAlarmsNext,
	me.MibUpload,
	me.MibUploadNext,
	me.MibReset,
	me.AlarmNotification,
	me.AttributeValueChange,
	me.Test,
	me.StartSoftwareDownload,
	me.DownloadSection,
	me.EndSoftwareDownload,
	me.ActivateSoftware,
	me.CommitSoftware,
	me.SynchronizeTime,
	me.Reboot,
	me.GetNext,
	me.TestResult,
	me.GetCurrentData,
	me.SetTable}

var allResults = [...]me.Results{
	me.Success,
	me.ProcessingError,
	me.NotSupported,
	me.ParameterError,
	me.UnknownEntity,
	me.UnknownInstance,
	me.DeviceBusy,
	me.InstanceExists}

// MibResetRequestTest tests decode/encode of a MIB Reset Request
func TestMsgTypeStrings(t *testing.T) {
	for _, msg := range allMsgTypes {
		strMsg := msg.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

func TestResultsStrings(t *testing.T) {
	for _, code := range allResults {
		strMsg := code.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

// TestOmciDecode will test for proper error checking of things that
// are invalid at the OMCI decode layer
func TestOmciDecode(t *testing.T) {
	// TID = 0 on autonomous ONU notifications only.  Get packet back but ErrorLayer()
	// returns non-nil
	tidZeroOnNonNotification := "0000440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(tidZeroOnNonNotification)
	assert.NoError(t, err)
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Only Baseline and Extended Message types allowed
	invalidMessageType := "000C440F010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err = stringToPacket(invalidMessageType)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Bad baseline message length
	badBaselineMsgLength := "000C440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000029"

	data, err = stringToPacket(badBaselineMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Bad extended message length
	badExtendedMsgLength := "000C440B010C010000290400800003010000" +
		"00000000000000000000000000000000" +
		"00000000000000000000"

	data, err = stringToPacket(badExtendedMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Huge extended message length
	hugeExtendedMsgLength := "000C440B010C010007BD0400800003010000" +
		"00000000000000000000000000000000" +
		"00000000000000000000"

	data, err = stringToPacket(hugeExtendedMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())
	// fmt.Println(packet.ErrorLayer())
}

// TestOmciSerialization will test for proper error checking of things that
// are invalid at the OMCI layer
func TestOmciSerialization(t *testing.T) {
	// TODO: Add unit test
}

func TestCreateRequestDecode(t *testing.T) {
	goodMessage := "000C440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0xc))
	assert.Equal(t, omciMsg.MessageType, byte(me.Create)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.Equal(t, request.EntityClass, me.GemPortNetworkCtpClassId)
	assert.Equal(t, request.EntityInstance, uint16(0x100))

	attributes := request.Attributes
	assert.NotNil(t, attributes)

	// As this is a create request, gather up all set-by-create attributes
	// make sure we got them all, and nothing else
	meDefinition, err := me.LoadManagedEntityDefinition(request.EntityClass)
	assert.Nil(t, err)

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
}

func TestCreateRequestSerialize(t *testing.T) {
	goodMessage := "000C440A010C0100040080000301000000000000000000000000000000000000000000000000000000000028"

	// TODO: Support setting of the length during serialization
	omciLayer := &OMCI{
		TransactionID:    0x0c,
		MessageType:      byte(me.Create) | me.AR,
		DeviceIdentifier: BaselineIdent,
		Length:           0x28,
	}
	request := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GemPortNetworkCtpClassId,
			EntityInstance: uint16(0x100),
		},
		Attributes: me.AttributeValueMap{
			"PortId":                                       0x400,
			"TContPointer":                                 0x8000,
			"Direction":                                    3,
			"TrafficManagementPointerForUpstream":          0x100,
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

func TestCreateResponse(t *testing.T) {
	goodMessage := "0108240a002d0900000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.Create)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CreateResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

func TestDeleteResquest(t *testing.T) {
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.MessageType, byte(me.Delete)|me.AR)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeDeleteRequest)
	//
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*DeleteRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
}

func TestDeleteResponse(t *testing.T) {
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.MessageType, byte(me.Delete)|me.AK)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeDeleteResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*DeleteResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
}

func TestSetRequest(t *testing.T) {
	goodMessage := "0107480a01000000020000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.Set)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestSetResponse(t *testing.T) {
	goodMessage := "0107280a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.Set)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

func TestGetRequest(t *testing.T) {
	goodMessage := "035e490a01070000004400000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.Get)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestGetResponse(t *testing.T) {
	goodMessage := "035e290a01070000000044dbcb05f10000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.Get)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

// TODO: Create request/response tests for all of the following types
//me.GetAllAlarms,
//me.GetAllAlarmsNext,

func TestMibUploadRequest(t *testing.T) {
	goodMessage := "03604d0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibUpload)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))
	msgLayer := packet.Layer(LayerTypeMibUploadRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestMibUploadResponse(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibUpload)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

func TestMibUploadNextRequest(t *testing.T) {
	goodMessage := "02864e0a00020000003a00000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibUploadNext)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestMibUploadNextResponse(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibUploadNext)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

func TestMibResetRequest(t *testing.T) {
	goodMessage := "00014F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibReset)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibResetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibResetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestMibResetResponse(t *testing.T) {
	goodMessage := "00012F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.MibReset)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibResetResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibResetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

// TODO: Create request/response tests for all of the following types
//me.Test,
//me.StartSoftwareDownload,
//me.DownloadSection,
//me.EndSoftwareDownload,
//me.ActivateSoftware,
//me.CommitSoftware,

func TestSynchronizeTimeRequest(t *testing.T) {
	goodMessage := "0109580a0100000007e20c0001301b0000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.SynchronizeTime)|me.AR)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SynchronizeTimeRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

func TestSynchronizeTimeResponse(t *testing.T) {
	goodMessage := "0109380a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.SynchronizeTime)|me.AK)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SynchronizeTimeResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
}

// TODO: Create request/response tests for all of the following types
//me.Reboot,
//me.GetNext,
//me.GetCurrentData,
//me.SetTable}

// TODO: Create notification tests for all of the following types
//me.AlarmNotification,

func TestAttributeValueChange(t *testing.T) {
	goodMessage := "0000110a0007000080004d4c2d33363236000000000000002020202020202020202020202020202000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, byte(me.AttributeValueChange))
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAttributeValueChange)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AttributeValueChangeMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
}

// TODO: Create notification tests for all of the following types
//me.TestResult,
