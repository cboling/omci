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

func TestFrameFormatNotYetSupported(t *testing.T) {
	// We do not yet support extended frame formats. Once we do, add a bunch of tests
	// to cover it

	params := me.ParamData{
		Attributes: me.AttributeValueMap{"MibDataSync": 0},
	}
	managedEntity, err := me.NewOnuData(params)
	assert.Nil(t, err)

	var buffer []byte
	buffer, err = genFrame(managedEntity, GetRequestType, FrameFormat(ExtendedIdent), TransactionID(1))
	assert.Nil(t, buffer)
	assert.NotNil(t, err)
}

func TestAllMessageTypes(t *testing.T) {
	// Loop over all message types
	for _, messageType := range allMessageTypes {
		//typeTested := false
		if testRoutine, ok := messageTypeTestFuncs[messageType]; ok {
			// Loop over all Managed Entities that support that type
			for _, managedEntity := range getMEsThatSupportAMessageType(messageType) {
				// Call the test routine
				testRoutine(t, managedEntity)
				//typeTested = true
			}
		}
		// Verify at least one test ran for this message type
		// TODO: Enable once all tests are working -> assert.True(t, typeTested)
	}
}

// genFrame is a helper function to make tests a little easier to read.
// For a real application, use the .../omci/generated/class.go 'New'
// functions to create your Managed Entity and then use it to call the
// EncodeFrame method.
func genFrame(meInstance *me.ManagedEntity, messageType MessageType, options ...FrameOption) ([]byte, error) {
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
}

func testCreateRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.SetByCreate) {
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

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, CreateRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*CreateRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, *meInstance.GetAttributeValueMap(), msgObj.Attributes)
}

func testCreateResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var mask uint16
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.SetByCreate) {
			// Random 20% chance this parameter was bad
			if rand.Int31n(5) == 0 {
				mask |= uint16(1 << (16 - attrDef.Index))
			}
		}
	}
	var frame []byte
	frame, err = genFrame(meInstance, CreateResponseType,
		TransactionID(tid), Result(result), AttributeExecutionMask(mask))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, CreateResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*CreateResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)

	if result == me.ParameterError {
		assert.Equal(t, mask, msgObj.AttributeExecutionMask)
	} else {
		assert.Zero(t, msgObj.AttributeExecutionMask)
	}
}

func testDeleteRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, DeleteRequestType, TransactionID(tid))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
}

func testDeleteResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	var frame []byte
	frame, err = genFrame(meInstance, DeleteResponseType, TransactionID(tid), Result(result))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
}

func testSetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.TableSupport {
			continue // TODO: Skip table attributes for now
		} else if attrDef.GetAccess().Contains(me.Write) {
			params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
		}
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, SetRequestType, TransactionID(tid))
	// some frames cannot fit all the attributes
	if err != nil {
		if _, ok := err.(*me.MessageTruncatedError); ok {
			return
		}
	}
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SetRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, *meInstance.GetAttributeValueMap(), msgObj.Attributes)
}

func testSetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(10))  // [0, 9] Not all types will be tested

	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var unsupportedMask uint16
	var failedMask uint16
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.Write) {
			// Random 10% chance this parameter unsupported and
			// 10% it failed
			switch rand.Int31n(5) {
			case 0:
				unsupportedMask |= uint16(1 << (16 - attrDef.Index))
			case 1:
				failedMask |= uint16(1 << (16 - attrDef.Index))
			}
		}
	}
	var frame []byte
	frame, err = genFrame(meInstance, SetResponseType,
		TransactionID(tid), Result(result),
		AttributeExecutionMask(failedMask),
		UnsupportedAttributeMask(unsupportedMask))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SetResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)

	if result == me.AttributeFailure {
		assert.Equal(t, failedMask, msgObj.FailedAttributeMask)
		assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)
	} else {
		assert.Zero(t, msgObj.FailedAttributeMask)
		assert.Zero(t, msgObj.UnsupportedAttributeMask)
	}
}

func testGetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.GetAccess().Contains(me.Read) {
			// Allow 'nil' as parameter value for GetRequests since we only need names
			params.Attributes[attrDef.GetName()] = nil
		}
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, GetRequestType, TransactionID(tid))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)
}

func testGetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap),
	}
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(10))  // [0, 6] Not all types will be tested

	// If success Results selected, set FailIfTruncated 50% of time to test
	// overflow detection and failures periodically.
	failIfTruncated := false
	if result == me.Success && rand.Int31n(2) == 1 {
		failIfTruncated = true
	}
	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var unsupportedMask uint16
	var failedMask uint16
	for _, attrDef := range *managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.Read) {
			// Random 10% chance this parameter unsupported and
			// 10% it failed
			switch rand.Int31n(5) {
			default:
				// TODO: Table attributes not yet supported.  For Table Attributes, figure our a
				//       good way to unit test this and see if that can be extended to a more
				//       general operation that provides the 'get-next' frames to the caller who
				//		 wishes to serialize a table attribute.
				if !attrDef.TableSupport {
					params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
				}
			case 0:
				unsupportedMask |= uint16(1 << (16 - attrDef.Index))
			case 1:
				failedMask |= uint16(1 << (16 - attrDef.Index))
			}
		}
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)

	var frame []byte
	frame, err = genFrame(meInstance, GetResponseType,
		TransactionID(tid), Result(result),
		AttributeExecutionMask(failedMask),
		UnsupportedAttributeMask(unsupportedMask),
		FailIfTruncated(failIfTruncated))

	// TODO: Need to test if err is MessageTruncatedError. Sometimes reported as
	//       a proessing error
	if err != nil {
		if _, ok := err.(*me.MessageTruncatedError); ok {
			return
		}
	}
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetResponse)
	// If requested Result was Success and FailIfTruncated is true, then we may
	// fail (get nil layer) if too many attributes to fit in a frame
	if result == me.Success && msgLayer == nil {
		return // was expected
	}
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)

	switch msgObj.Result {
	default:
		assert.Equal(t, result, msgObj.Result)
		assert.Zero(t, msgObj.FailedAttributeMask)
		assert.Zero(t, msgObj.UnsupportedAttributeMask)

	case me.Success:
		assert.Equal(t, result, msgObj.Result)
		assert.Zero(t, msgObj.FailedAttributeMask)
		assert.Zero(t, msgObj.UnsupportedAttributeMask)
		assert.Equal(t, *meInstance.GetAttributeValueMap(), msgObj.Attributes)

	case me.AttributeFailure:
		// Should have been Success or AttributeFailure to start with
		assert.True(t, result == me.Success || result == me.AttributeFailure)
		assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)

		// Returned may have more bits set in failed mask and less attributes
		// since failIfTruncated is false and we may add more fail attributes
		// since they do not fit
		if failedMask != msgObj.FailedAttributeMask {
			// Expect more bits in returned mask
			assert.True(t, failedMask < msgObj.FailedAttributeMask)
		} else {
			assert.Equal(t, failedMask, msgObj.FailedAttributeMask)
		}
		// Make sure any successful attributes were requested
		meMap := *meInstance.GetAttributeValueMap()
		for name := range msgObj.Attributes {
			getValue, ok := meMap[name]
			assert.True(t, ok)
			assert.NotNil(t, getValue)
		}
	}
}

func testGetAllAlarmsRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	mode := uint8(rand.Int31n(2))          // [0, 1]

	var frame []byte
	frame, err = genFrame(meInstance, GetAllAlarmsRequestType, TransactionID(tid), RetrievalMode(mode))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, mode, msgObj.AlarmRetrievalMode)
}

func testGetAllAlarmsResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1)  // [1, 0xFFFF]
	numOfCommands := uint16(rand.Int31n(5)) // [0, 5)

	var frame []byte
	frame, err = genFrame(meInstance, GetAllAlarmsResponseType, TransactionID(tid),
		SequenceNumberCountOrSize(numOfCommands))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, numOfCommands, msgObj.NumberOfCommands)
}

func testGetAllAlarmsNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]
	sequenceNumber := uint16(rand.Int31n(5)) // [0, 5)

	var frame []byte
	frame, err = genFrame(meInstance, GetAllAlarmsNextRequestType, TransactionID(tid),
		SequenceNumberCountOrSize(sequenceNumber))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsNextRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, sequenceNumber, msgObj.CommandSequenceNumber)
}

func testGetAllAlarmsNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, MibUploadRequestType, TransactionID(tid))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	// TODO: Implement
}

func testMibUploadNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	seqNumber := uint16(rand.Int31n(0xFFFF)) // [0, 0xFFFE]
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]

	var frame []byte
	frame, err = genFrame(meInstance, MibUploadNextRequestType, TransactionID(tid),
		SequenceNumberCountOrSize(seqNumber))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadNextRequestType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, seqNumber, msgObj.CommandSequenceNumber)
	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	// TODO: Since only baseline messages supported, send only one ME
	uploadMe := meInstance

	var frame []byte
	frame, err = genFrame(meInstance, MibUploadNextResponseType, TransactionID(tid), Payload(uploadMe))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, err)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciObj.MessageType)
	assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, managedEntity.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, managedEntity.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, uploadMe.GetClassID(), msgObj.ReportedME.GetClassID())
	assert.Equal(t, uploadMe.GetEntityID(), msgObj.ReportedME.GetEntityID())
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
