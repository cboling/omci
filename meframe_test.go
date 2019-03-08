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
	"testing"
)

var messageTypeCreators map[MessageType]func(*testing.T)

func init() {
	messageTypeCreators = make(map[MessageType]func(*testing.T), 0)
	// TODO: Create MessageType to CreateFunc Map entries
	messageTypeCreators[CreateRequestType] = testCreateRequestTypeMeFrame
	messageTypeCreators[CreateResponseType] = testCreateResponseTypeMeFrame
	messageTypeCreators[DeleteRequestType] = testDeleteRequestTypeMeFrame
	messageTypeCreators[DeleteResponseType] = testDeleteResponseTypeMeFrame
	messageTypeCreators[SetRequestType] = testSetRequestTypeMeFrame
	messageTypeCreators[SetResponseType] = testSetResponseTypeMeFrame
	messageTypeCreators[GetRequestType] = testGetRequestTypeMeFrame
	messageTypeCreators[GetResponseType] = testGetResponseTypeMeFrame
	messageTypeCreators[GetAllAlarmsRequestType] = testGetAllAlarmsRequestTypeMeFrame
	messageTypeCreators[GetAllAlarmsResponseType] = testGetAllAlarmsResponseTypeMeFrame
	messageTypeCreators[GetAllAlarmsNextRequestType] = testGetAllAlarmsNextRequestTypeMeFrame
	messageTypeCreators[GetAllAlarmsNextResponseType] = testGetAllAlarmsNextResponseTypeMeFrame
	messageTypeCreators[MibUploadRequestType] = testMibUploadRequestTypeMeFrame
	messageTypeCreators[MibUploadResponseType] = testMibUploadResponseTypeMeFrame
	messageTypeCreators[MibUploadNextRequestType] = testMibUploadNextRequestTypeMeFrame
	messageTypeCreators[MibUploadNextResponseType] = testMibUploadNextResponseTypeMeFrame
	messageTypeCreators[MibResetRequestType] = testMibResetRequestTypeMeFrame
	messageTypeCreators[MibResetResponseType] = testMibResetResponseTypeMeFrame
	messageTypeCreators[TestRequestType] = testTestRequestTypeMeFrame
	messageTypeCreators[TestResponseType] = testTestResponseTypeMeFrame
	messageTypeCreators[StartSoftwareDownloadRequestType] = testStartSoftwareDownloadRequestTypeMeFrame
	messageTypeCreators[StartSoftwareDownloadResponseType] = testStartSoftwareDownloadResponseTypeMeFrame
	messageTypeCreators[DownloadSectionRequestType] = testDownloadSectionRequestTypeMeFrame
	messageTypeCreators[DownloadSectionResponseType] = testDownloadSectionResponseTypeMeFrame
	messageTypeCreators[EndSoftwareDownloadRequestType] = testEndSoftwareDownloadRequestTypeMeFrame
	messageTypeCreators[EndSoftwareDownloadResponseType] = testEndSoftwareDownloadResponseTypeMeFrame
	messageTypeCreators[ActivateSoftwareRequestType] = testActivateSoftwareRequestTypeMeFrame
	messageTypeCreators[ActivateSoftwareResponseType] = testActivateSoftwareResponseTypeMeFrame
	messageTypeCreators[CommitSoftwareRequestType] = testCommitSoftwareRequestTypeMeFrame
	messageTypeCreators[CommitSoftwareResponseType] = testCommitSoftwareResponseTypeMeFrame
	messageTypeCreators[SynchronizeTimeRequestType] = testSynchronizeTimeRequestTypeMeFrame
	messageTypeCreators[SynchronizeTimeResponseType] = testSynchronizeTimeResponseTypeMeFrame
	messageTypeCreators[RebootRequestType] = testRebootRequestTypeMeFrame
	messageTypeCreators[RebootResponseType] = testRebootResponseTypeMeFrame
	messageTypeCreators[GetNextRequestType] = testGetNextRequestTypeMeFrame
	messageTypeCreators[GetNextResponseType] = testGetNextResponseTypeMeFrame
	messageTypeCreators[GetCurrentDataRequestType] = testGetCurrentDataRequestTypeMeFrame
	messageTypeCreators[GetCurrentDataResponseType] = testGetCurrentDataResponseTypeMeFrame
	messageTypeCreators[SetTableRequestType] = testSetTableRequestTypeMeFrame
	messageTypeCreators[SetTableResponseType] = testSetTableResponseTypeMeFrame
	messageTypeCreators[AlarmNotificationType] = testAlarmNotificationTypeMeFrame
	messageTypeCreators[AttributeValueChangeType] = testAttributeValueChangeTypeMeFrame
	messageTypeCreators[TestResultType] = testTestResultTypeMeFrame
}

func TestExample(t *testing.T) {
	assert.True(t, true)
}

// genFrame is a helper function to make tests a little easier to read.
// For a real application, use the .../omci/generated/class.go 'New'
// functions to create your Managed Entity and then use it to call the
// EncodeFrame method.
func genFrame(meInstance *ManagedEntityInstance, messageType MessageType, options ...FrameOption) ([]byte, error) {
	//omciParams := me.ParamData{
	//	EntityID:   eid,
	//	Attributes: attr,
	//}
	//omciMe, _ := omci.ManagedEntityToInstance(omciInstance)
	//mask, _ := me.GetAttributeBitmap(*omciInstance.GetAttributeDefinitions(),
	//	mapset.NewSetWith(attribute))
	//var mask uint16

	omciLayer, msgLayer, err := meInstance.EncodeFrame(messageType, options...)
	if err != nil {
		return nil, err
	}
	// Make sure the Transaction ID is set
	omciLayer.TransactionID = 1
	if messageType == AlarmNotificationType ||
		messageType == AttributeValueChangeType ||
		messageType == TestResultType {
		omciLayer.TransactionID = 0
	}
	// Serialize the frame and send it
	var serializeOptions gopacket.SerializeOptions
	serializeOptions.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, omciLayer, msgLayer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func getMEsThatSupportAMessageType(msgType MessageType) []*me.ManagedEntity {
	entities := make([]*me.ManagedEntity, 0)

	// TODO: Loop through class IDs and collect MEs

	return entities
}

func TestFrameFormat(t *testing.T) {
	// TODO: Add support here and additional tests for various frame
	//       options (as individual test functions of course...)
	//format := omci.FrameFormat(omci.BaselineIdent)
	assert.True(t, true)
}

func TestAllMessageTypes(t *testing.T) {
	// TODO: Create a loop to run through all message types (req/resp)
	//       and then look at all message types that support that Message
	//       type and create an MEFrame (serialized) ready for transmission.
	//       If possible, feed that back to the library and decode and
	//		 test that it works.
}

func testCreateRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testCreateResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testDeleteRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testDeleteResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSetRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSetResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetAllAlarmsRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetAllAlarmsResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetAllAlarmsNextRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetAllAlarmsNextResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibUploadRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibUploadResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibUploadNextRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibUploadNextResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibResetRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testMibResetResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testTestRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testTestResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testStartSoftwareDownloadRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testStartSoftwareDownloadResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testDownloadSectionRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testDownloadSectionResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testEndSoftwareDownloadRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testEndSoftwareDownloadResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testActivateSoftwareRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testActivateSoftwareResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testCommitSoftwareRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testCommitSoftwareResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSynchronizeTimeRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSynchronizeTimeResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testRebootRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testRebootResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetNextRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetNextResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetCurrentDataRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testGetCurrentDataResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSetTableRequestTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testSetTableResponseTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testAlarmNotificationTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testAttributeValueChangeTypeMeFrame(t *testing.T) {
	// TODO: Implement
}

func testTestResultTypeMeFrame(t *testing.T) {
	// TODO: Implement
}
