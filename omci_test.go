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
	"encoding/hex"
	"fmt"
	. "github.com/cboling/omci"
	. "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func stringToPacket(input string) ([]byte, error) {
	var p []byte

	p, err := hex.DecodeString(input)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return p, nil
}

func packetToString(input []byte) string {
	return strings.ToLower(hex.EncodeToString(input))
}

func getSbcMask(meDefinition IManagedEntityDefinition) uint16 {
	var sbcMask uint16

	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if SupportsAttributeAccess(attr, SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	return sbcMask
}

func TestDeviceIdents(t *testing.T) {

	baselineString := BaselineIdent.String()
	assert.NotZero(t, len(baselineString))

	extendedString := ExtendedIdent.String()
	assert.NotZero(t, len(extendedString))

	assert.NotEqual(t, baselineString, extendedString)

	unknownString := DeviceIdent(0xff).String()
	assert.NotZero(t, len(unknownString))
	assert.NotEqual(t, unknownString, baselineString)
	assert.NotEqual(t, unknownString, extendedString)
}

func TestOmciCanDecodeAndNextLayer(t *testing.T) {

	baselineString := BaselineIdent.String()
	assert.NotZero(t, len(baselineString))

	createGalEthernetProfile := "0002440A011000010030000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(createGalEthernetProfile)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeCreateRequest, omciMsg.NextLayerType())

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	omciMsg2, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.Equal(t, LayerTypeCreateRequest, omciMsg2.LayerType())
	assert.Equal(t, LayerTypeCreateRequest, omciMsg2.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, omciMsg2.NextLayerType())
}

func TestOmciHeaderVeryShort(t *testing.T) {
	// Need at least 6 octets in OMCI header to decode Message Type
	message := "000159"
	data, err := stringToPacket(message)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.Nil(t, omciLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.True(t, packet.Metadata().Truncated)
}

func TestOmciHeaderBaselineShort(t *testing.T) {
	msgTypes := []MessageType{
		CreateRequestType,
		CreateResponseType,
		DeleteRequestType,
		DeleteResponseType,
		SetRequestType,
		SetResponseType,
		GetRequestType,
		GetResponseType,
		GetAllAlarmsRequestType,
		GetAllAlarmsResponseType,
		GetAllAlarmsNextRequestType,
		GetAllAlarmsNextResponseType,
		MibUploadRequestType,
		MibUploadResponseType,
		MibUploadNextRequestType,
		MibUploadNextResponseType,
		MibResetRequestType,
		MibResetResponseType,
		TestRequestType,
		TestResponseType,
		StartSoftwareDownloadRequestType,
		StartSoftwareDownloadResponseType,
		DownloadSectionRequestType,
		DownloadSectionRequestWithResponseType,
		DownloadSectionResponseType,
		EndSoftwareDownloadRequestType,
		EndSoftwareDownloadResponseType,
		ActivateSoftwareRequestType,
		ActivateSoftwareResponseType,
		CommitSoftwareRequestType,
		CommitSoftwareResponseType,
		SynchronizeTimeRequestType,
		SynchronizeTimeResponseType,
		RebootRequestType,
		RebootResponseType,
		GetNextRequestType,
		GetNextResponseType,
		GetCurrentDataRequestType,
		GetCurrentDataResponseType,
		AlarmNotificationType,
		AttributeValueChangeType,
		TestResultType,
	}
	for _, msgType := range msgTypes {
		// Smallest message baseline is 40 bytes (length and MIC optional)
		tid := 1
		if msgType == AlarmNotificationType || msgType == AttributeValueChangeType {
			tid = 0
		}
		msg39 := fmt.Sprintf("%04x%02x0a0002000000000000000000000000000000000000000000000000000000000000000000",
			uint16(tid), uint8(msgType))

		data, err := stringToPacket(msg39)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.Nil(t, omciLayer)

		badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
		assert.NotNil(t, badLayer)
		truncated := packet.Metadata().Truncated
		assert.True(t, truncated)

		// Let length be optional size baseline size is fixed and we can recover from that
		msg40 := fmt.Sprintf("%04x%02x0a000200000000000000000000000000000000000000000000000000000000000000000000",
			uint16(tid), uint8(msgType))
		data, err = stringToPacket(msg40)
		assert.NoError(t, err)

		packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer = packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		omciMsg, ok := omciLayer.(*OMCI)
		assert.True(t, ok)
		assert.Equal(t, uint16(40), omciMsg.Length)
	}
}

func TestOmciHeaderExtendedShort(t *testing.T) {
	// Smallest message possible is an Extended Set Delete request which
	// is 10 octets.

	//mibResetRequest := "0001 4F 0A 0002 0000 0000000000000000" +
	//	"00000000000000000000000000000000" +
	//	"000000000000000000000028"

}
