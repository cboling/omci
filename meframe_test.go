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
	"math/rand"
	"testing"
)

var messageTypeTestFuncs map[MessageType]func(*testing.T, *me.ManagedEntity)

func init() {
	messageTypeTestFuncs = make(map[MessageType]func(*testing.T, *me.ManagedEntity), 0)

	messageTypeTestFuncs[CreateRequestType] = testCreateRequestTypeMeFrame
	messageTypeTestFuncs[CreateResponseType] = testCreateResponseTypeMeFrame
	messageTypeTestFuncs[DeleteRequestType] = testDeleteRequestTypeMeFrame
	messageTypeTestFuncs[DeleteResponseType] = testDeleteResponseTypeMeFrame
	messageTypeTestFuncs[SetRequestType] = testSetRequestTypeMeFrame
	messageTypeTestFuncs[SetResponseType] = testSetResponseTypeMeFrame
	messageTypeTestFuncs[GetRequestType] = testGetRequestTypeMeFrame
	messageTypeTestFuncs[GetResponseType] = testGetResponseTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsRequestType] = testGetAllAlarmsRequestTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsResponseType] = testGetAllAlarmsResponseTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsNextRequestType] = testGetAllAlarmsNextRequestTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsNextResponseType] = testGetAllAlarmsNextResponseTypeMeFrame
	messageTypeTestFuncs[MibUploadRequestType] = testMibUploadRequestTypeMeFrame
	messageTypeTestFuncs[MibUploadResponseType] = testMibUploadResponseTypeMeFrame
	messageTypeTestFuncs[MibUploadNextRequestType] = testMibUploadNextRequestTypeMeFrame
	messageTypeTestFuncs[MibUploadNextResponseType] = testMibUploadNextResponseTypeMeFrame
	messageTypeTestFuncs[MibResetRequestType] = testMibResetRequestTypeMeFrame
	messageTypeTestFuncs[MibResetResponseType] = testMibResetResponseTypeMeFrame
	messageTypeTestFuncs[TestRequestType] = testTestRequestTypeMeFrame
	messageTypeTestFuncs[TestResponseType] = testTestResponseTypeMeFrame
	messageTypeTestFuncs[StartSoftwareDownloadRequestType] = testStartSoftwareDownloadRequestTypeMeFrame
	messageTypeTestFuncs[StartSoftwareDownloadResponseType] = testStartSoftwareDownloadResponseTypeMeFrame
	messageTypeTestFuncs[DownloadSectionRequestType] = testDownloadSectionRequestTypeMeFrame
	messageTypeTestFuncs[DownloadSectionResponseType] = testDownloadSectionResponseTypeMeFrame
	messageTypeTestFuncs[EndSoftwareDownloadRequestType] = testEndSoftwareDownloadRequestTypeMeFrame
	messageTypeTestFuncs[EndSoftwareDownloadResponseType] = testEndSoftwareDownloadResponseTypeMeFrame
	messageTypeTestFuncs[ActivateSoftwareRequestType] = testActivateSoftwareRequestTypeMeFrame
	messageTypeTestFuncs[ActivateSoftwareResponseType] = testActivateSoftwareResponseTypeMeFrame
	messageTypeTestFuncs[CommitSoftwareRequestType] = testCommitSoftwareRequestTypeMeFrame
	messageTypeTestFuncs[CommitSoftwareResponseType] = testCommitSoftwareResponseTypeMeFrame
	messageTypeTestFuncs[SynchronizeTimeRequestType] = testSynchronizeTimeRequestTypeMeFrame
	messageTypeTestFuncs[SynchronizeTimeResponseType] = testSynchronizeTimeResponseTypeMeFrame
	messageTypeTestFuncs[RebootRequestType] = testRebootRequestTypeMeFrame
	messageTypeTestFuncs[RebootResponseType] = testRebootResponseTypeMeFrame
	messageTypeTestFuncs[GetNextRequestType] = testGetNextRequestTypeMeFrame
	messageTypeTestFuncs[GetNextResponseType] = testGetNextResponseTypeMeFrame
	messageTypeTestFuncs[GetCurrentDataRequestType] = testGetCurrentDataRequestTypeMeFrame
	messageTypeTestFuncs[GetCurrentDataResponseType] = testGetCurrentDataResponseTypeMeFrame
	messageTypeTestFuncs[SetTableRequestType] = testSetTableRequestTypeMeFrame
	messageTypeTestFuncs[SetTableResponseType] = testSetTableResponseTypeMeFrame
	messageTypeTestFuncs[AlarmNotificationType] = testAlarmNotificationTypeMeFrame
	messageTypeTestFuncs[AttributeValueChangeType] = testAttributeValueChangeTypeMeFrame
	messageTypeTestFuncs[TestResultType] = testTestResultTypeMeFrame
}

func getMEsThatSupportAMessageType(messageType MessageType) []*me.ManagedEntity {
	msgType := me.MsgType(byte(messageType) & me.MsgTypeMask)

	entities := make([]*me.ManagedEntity, 0)
	for _, classID := range me.GetSupportedClassIDs() {
		if managedEntity, err := me.LoadManagedEntityDefinition(classID); err == nil {
			supportedTypes := managedEntity.GetManagedEntityDefinition().GetMessageTypes()
			if supportedTypes.Contains(msgType) {
				entities = append(entities, managedEntity)
			}
		}
	}
	return entities
}

func TestFrameFormat(t *testing.T) {
	// TODO: Add support here and additional tests for various frame
	//       options (as individual test functions of course...)
	//format := omci.FrameFormat(omci.BaselineIdent)
	assert.True(t, true)
}

func TestAllMessageTypes(t *testing.T) {
	// Loop over all message types
	for _, messageType := range allMessageTypes {

		if testRoutine, ok := messageTypeTestFuncs[messageType]; ok {
			// Loop over all Managed Entities that support that type
			for _, managedEntity := range getMEsThatSupportAMessageType(messageType) {
				// Call the test routine
				testRoutine(t, managedEntity)
			}
		}
	}
	// TODO: Create a loop to run through all message types (req/resp)
	//       and then look at all message types that support that Message
	//       type and create an MEFrame (serialized) ready for transmission.
	//       If possible, feed that back to the library and decode and
	//		 test that it works.
}

// genFrame is a helper function to make tests a little easier to read.
// For a real application, use the .../omci/generated/class.go 'New'
// functions to create your Managed Entity and then use it to call the
// EncodeFrame method.
func genFrame(meInstance *me.ManagedEntity, messageType MessageType, options ...FrameOption) ([]byte, error) {
	//omciParams := me.ParamData{
	//	EntityID:   eid,
	//	Attributes: attr,
	//}
	//omciMe, _ := omci.ManagedEntityToInstance(omciInstance)
	//mask, _ := me.GetAttributeBitmap(*omciInstance.GetAttributeDefinitions(),
	//	mapset.NewSetWith(attribute))
	//var mask uint16
	omciLayer, msgLayer, err := EncodeFrame(meInstance, messageType, options...)
	if err != nil {
		return nil, err
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

func pickAValue(attrDef *me.AttributeDefinition) interface{} {
	constraint := attrDef.Constraint
	defaultVal := attrDef.DefValue

	if attrDef.TableSupport {
		// TODO: Not yet supported
		return nil
	}
	switch attrDef.GetSize() {
	case 1:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint8); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint8)

	case 2:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint16); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint16)

	case 4:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint32); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint32)

	case 8:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint64); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint64)

	default:
		size := attrDef.GetSize()
		value := make([]uint8, size)
		for index := 0; index < size; index++ {
			value[index] = uint8(index & 0xFF)
		}
		return value
	}
	return nil
}

func testCreateRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID:   0,
		Attributes: me.AttributeValueMap{},
	}
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.GetAccess()|me.SetByCreate == me.SetByCreate {
			params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
		}
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, CreateRequestType, TransactionID(tid))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	// TODO: Implement

}

func testCreateResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testDeleteRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testDeleteResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetAllAlarmsRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetAllAlarmsResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetAllAlarmsNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetAllAlarmsNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibResetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibResetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testTestRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testTestResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testStartSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testStartSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testDownloadSectionRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testDownloadSectionResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testEndSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testEndSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testActivateSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testActivateSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testCommitSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testCommitSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSynchronizeTimeRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSynchronizeTimeResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testRebootRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testRebootResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetCurrentDataRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testGetCurrentDataResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSetTableRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testSetTableResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testAlarmNotificationTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testAttributeValueChangeTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testTestResultTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}
