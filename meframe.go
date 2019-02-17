/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */
package omci

import (
	"errors"
	"fmt"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

type options struct {
	frameFormat       DeviceIdent
	failIfTruncated   bool
	attributeMask     uint16
	results           me.Results // Common for many responses
	attrExecutionMask uint16     // Create Response Only if results == 3 or
	// Set Response only if results == 0
	unsupportedMask uint16 // Set Response only if results == 9
	sequenceNumber  uint16 // For get-next request frames
}

var defaultFrameOptions = options{
	frameFormat:       BaselineIdent,
	failIfTruncated:   false,
	attributeMask:     0xFFFF,
	results:           me.Success,
	attrExecutionMask: 0,
	unsupportedMask:   0,
	sequenceNumber:    0,
}

// A FrameOption sets options such as frame format, etc.
type FrameOption func(*options)

// FrameFormat determines determines the OMCI message format used on the fiber.
// The default value is BaselineIdent
func FrameFormat(ff DeviceIdent) FrameOption {
	return func(o *options) {
		o.frameFormat = ff
	}
}

// FailIfTruncated determines whether a request to encode a frame that does
// not have enough room for all requested options should fail and return an
// error.
//
// If set to 'false', the behaviour depends on the message type/operation
// requested. The table below provides more information:
//
//   Request Type	Behavour
//	 ------------------------------------------------------------------------
//	 CreateRequest  A single CreateRequest struct is always returned as the
//                  CreateRequest message does not have an attributes Mask
//                  field and a Baseline OMCI message is large enough to
//                  support all Set-By-Create attributes.
//
//   SetRequest		If multiple OMCI frames will be needed to support setting
//					all of the requested attributes, multiple SetRequest
//					structs will be returned with attributes encoded in
//					decreasing Attribute mask bit order. Since this is an
//					operation that should only occur on an OLT, it is the
//					responsibility for the OLT application to clone the OMCI
//					structure returned should it wish to send more than the
//					initial SetRequest in the returned array.
//
//   GetResponse	If multiple OMCI response frames are needed to return
//					all requested attributes, multiple GetResponse structs
//					will be returned. Since this is an operation that should
//					only occur on an ONU, there are several ways in which
//					the responses will be encoded.
//
//					If this is an ME that simply has simple attributes that
//					when combined will exceed the OMCI frame size, the first
//					(and only) GetResponse struct will be encoded with as many
//					attributes as possible and the Results field set to 1001
//					(AttributeFailure) and the FailedAttributeMask field
//					set to the attributes that could not be returned
//
//					If this is an ME with an attribute that is a table, the
//					first GetResponse struct will return the size of the
//					attribute and the following GetNextResponse structs will
//					contain the attribute data. The ONU application is
//					responsible for stashing these extra struct(s) away in
//					anticipation of possible GetNext Requests occuring for
//					the attribute.  See the discussion on Table attributes
//					in the GetResponse section of ITU G.988 for more
//					information.
//
// If set to 'true', no struct(s) are returned and an error is provided.
//
// The default value is 'false'
func FailIfTruncated(f bool) FrameOption {
	return func(o *options) {
		o.failIfTruncated = f
	}
}

// attributeMask determines the attributes to encode into the frame.
// The default value is 0xFFFF which specifies all available attributes
// in the frame
func AttributeMask(m uint16) FrameOption {
	return func(o *options) {
		o.attributeMask = m
	}
}

// AttributeExecutionMask is used by the Create and Set Response frames to indicate
// attributes that failed to be created/set.
func AttributeExecutionMask(m uint16) FrameOption {
	return func(o *options) {
		o.attrExecutionMask = m
	}
}

// AttributeUnsupportedMask is used by the Set Response frames to indicate attributes
// that failed to be set by the ONU due to not being supported
func AttributeUnsupportedMask(m uint16) FrameOption {
	return func(o *options) {
		o.unsupportedMask = m
	}
}

// SequenceNumber is used by the GetNext and MibUploadGetNext request frames
func SequenceNumber(m uint16) FrameOption {
	return func(o *options) {
		o.sequenceNumber = m
	}
}

// ManagedEntity is intended to be a lighter weight version of a specific managed
// entity. It is intended to be used by generated Managed Entity classes as a base
// class which is easier to use within an application outside of just decode and
// serialization of OMCI Packets
type ManagedEntityInstance struct {
	// Only the base class. Defined this way to add EncodeFrame support
	me.ManagedEntity
}

func ManagedEntityToInstance(entity *me.ManagedEntity) (*ManagedEntityInstance, error) {
	omciMe := &ManagedEntityInstance{}
	omciMe.SetManagedEntityDefinition(entity.GetManagedEntityDefinition())
	if err := omciMe.SetEntityID(entity.GetEntityID()); err != nil {
		return nil, err
	}
	for name, value := range *entity.GetAttributeValueMap() {
		if err := omciMe.SetAttribute(name, value); err != nil {
			return nil, err
		}
	}
	return omciMe, nil
}

// EncodeFrame will encode the Managed Entity specific protocol struct and an
// OMCILayer struct. This struct can be provided to the gopacket.SerializeLayers()
// function to be serialized into a buffer for transmission.
func (m *ManagedEntityInstance) EncodeFrame(messageType MessageType, opt ...FrameOption) (*OMCI, gopacket.SerializableLayer, error) {
	// Check for message type support
	msgType := me.MsgType(messageType & me.MsgTypeMask)
	meDefinition := m.GetManagedEntityDefinition()

	if !me.SupportsMsgType(meDefinition, msgType) {
		msg := fmt.Sprintf("managed entity %v does not support %v Message-Type",
			meDefinition.GetName(), msgType)
		return nil, nil, errors.New(msg)
	}
	// Decode options
	opts := defaultFrameOptions
	for _, o := range opt {
		o(&opts)
	}
	// Note: Transaction ID should be set before frame serialization
	omci := &OMCI{
		TransactionID:    0,
		MessageType:      messageType,
		DeviceIdentifier: opts.frameFormat,
	}
	var meInfo interface{}
	var err error

	// Encode message type specific operation
	switch messageType {
	case CreateRequestType:
		meInfo, err = m.createRequestFrame(opts)
	case DeleteRequestType:
		meInfo, err = m.deleteRequestFrame(opts)
	case SetRequestType:
		meInfo, err = m.setRequestFrame(opts)
	case GetRequestType:
		meInfo, err = m.getRequestFrame(opts)
	case GetAllAlarmsRequestType:
		meInfo, err = m.getAllAlarmsRequestFrame(opts)
	case GetAllAlarmsNextRequestType:
		meInfo, err = m.getAllAlarmsNextRequestFrame(opts)
	case MibUploadRequestType:
		meInfo, err = m.mibUploadRequestFrame(opts)
	case MibUploadNextRequestType:
		meInfo, err = m.mibUploadNextRequestFrame(opts)
	case MibResetRequestType:
		meInfo, err = m.mibResetRequestFrame(opts)
	case TestRequestType:
		meInfo, err = m.testRequestFrame(opts)
	case StartSoftwareDownloadRequestType:
		meInfo, err = m.startSoftwareDownloadRequestFrame(opts)
	case DownloadSectionRequestType:
		meInfo, err = m.downloadSectionRequestFrame(opts)
	case EndSoftwareDownloadRequestType:
		meInfo, err = m.endSoftwareDownloadRequestFrame(opts)
	case ActivateSoftwareRequestType:
		meInfo, err = m.activateSoftwareRequestFrame(opts)
	case CommitSoftwareRequestType:
		meInfo, err = m.commitSoftwareRequestFrame(opts)
	case SynchronizeTimeRequestType:
		meInfo, err = m.synchronizeTimeRequestFrame(opts)
	case RebootRequestType:
		meInfo, err = m.rebootRequestFrame(opts)
	case GetNextRequestType:
		meInfo, err = m.getNextRequestFrame(opts)
	case GetCurrentDataRequestType:
		meInfo, err = m.getCurrentDataRequestFrame(opts)
	case SetTableRequestType:
		meInfo, err = m.setTableRequestFrame(opts)

	// Response Frames
	case CreateResponseType:
		meInfo, err = m.createResponseFrame(opts)
	case DeleteResponseType:
		meInfo, err = m.deleteResponseFrame(opts)
	case SetResponseType:
		meInfo, err = m.setResponseFrame(opts)
	case GetResponseType:
		meInfo, err = m.getResponseFrame(opts)
	case GetAllAlarmsResponseType:
		meInfo, err = m.getAllAlarmsResponseFrame(opts)
	case GetAllAlarmsNextResponseType:
		meInfo, err = m.getAllAlarmsNextResponseFrame(opts)
	case MibUploadResponseType:
		meInfo, err = m.mibUploadResponseFrame(opts)
	case MibUploadNextResponseType:
		meInfo, err = m.mibUploadNextResponseFrame(opts)
	case MibResetResponseType:
		meInfo, err = m.mibResetResponseFrame(opts)
	case TestResponseType:
		meInfo, err = m.testResponseFrame(opts)
	case StartSoftwareDownloadResponseType:
		meInfo, err = m.startSoftwareDownloadResponseFrame(opts)
	case DownloadSectionResponseType:
		meInfo, err = m.downloadSectionResponseFrame(opts)
	case EndSoftwareDownloadResponseType:
		meInfo, err = m.endSoftwareDownloadResponseFrame(opts)
	case ActivateSoftwareResponseType:
		meInfo, err = m.activateSoftwareResponseFrame(opts)
	case CommitSoftwareResponseType:
		meInfo, err = m.commitSoftwareResponseFrame(opts)
	case SynchronizeTimeResponseType:
		meInfo, err = m.synchronizeTimeResponseFrame(opts)
	case RebootResponseType:
		meInfo, err = m.rebootResponseFrame(opts)
	case GetNextResponseType:
		meInfo, err = m.getNextResponseFrame(opts)
	case GetCurrentDataResponseType:
		meInfo, err = m.getCurrentDataResponseFrame(opts)
	case SetTableResponseType:
		meInfo, err = m.setTableResponseFrame(opts)

	// Autonomous ONU Frames
	case MessageType(me.AlarmNotification):
		meInfo, err = m.alarmNotificationFrame(opts)
	case MessageType(me.AttributeValueChange):
		meInfo, err = m.attributeValueChangeFrame(opts)
	case MessageType(me.TestResult):
		meInfo, err = m.testResultFrame(opts)

	// Unknown
	default:
		err = errors.New(fmt.Sprintf("message-type: %v/%#x is not supported", messageType, messageType))
	}
	if err != nil {
		return nil, nil, err
	}
	// Some requests return an array of serializable intefaces
	if singleResult, ok := meInfo.(gopacket.SerializableLayer); ok {
		return omci, singleResult, err
	} else if arrayResult, ok := meInfo.([]gopacket.SerializableLayer); ok {
		// TODO: Support this return type
		return omci, arrayResult[0], err
	}
	return nil, nil, errors.New(fmt.Sprintf("unexpected return type' %t", meInfo))
}

// For most all create methods below, error checking for valid masks, attribute
// values, and other fields is left to when the frame is actually serialized.

func (m *ManagedEntityInstance) checkAttributeMask(mask uint16) (uint16, error) {
	if mask&m.GetManagedEntityDefinition().GetAllowedAttributeMask() != mask {
		return 0, errors.New("invalid attribute mask")
	}
	return mask & m.GetManagedEntityDefinition().GetAllowedAttributeMask(), nil
}

// return the maximum space that can be used by attributes
func (m *ManagedEntityInstance) maxPacketAvailable(opt options) uint {
	if opt.frameFormat == BaselineIdent {
		// OMCI Header          - 4 octets
		// Class ID/Instance ID - 4 octets
		// Length field			- 4 octets
		// MIC                  - 4 octets
		return MaxBaselineLength - 16
	}
	// OMCI Header          - 4 octets
	// Class ID/Instance ID - 4 octets
	// Length field			- 4 octets
	// MIC                  - 4 octets
	return MaxExtendedLength - 16
}

func (m *ManagedEntityInstance) createRequestFrame(opt options) (interface{}, error) {
	meLayer := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) createResponseFrame(opt options) (interface{}, error) {
	meLayer := &CreateResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		Result: opt.results,
	}
	if meLayer.Result == me.ParameterError {
		meLayer.AttributeExecutionMask = opt.attrExecutionMask
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) deleteRequestFrame(opt options) (interface{}, error) {
	meLayer := &DeleteRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) deleteResponseFrame(opt options) (interface{}, error) {
	meLayer := &DeleteResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		Result: opt.results,
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) setRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	results := make([]*SetRequest, 0)
	meDefinition := m.GetManagedEntityDefinition()
	attrDefs := *meDefinition.GetAttributeDefinitions()
	attrMap := *m.GetAttributeValueMap()

	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)
	payloadAvailable := int(maxPayload)

	meLayer := &SetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		AttributeMask: 0,
		Attributes:    make(me.AttributeValueMap),
	}
	results = append(results, meLayer)

	for mask != 0 {
		// Iterate down the attributes (Attribute 0 is the ManagedEntity ID)
		var attrRetry bool
		var attrIndex uint
		for attrIndex = 1; attrIndex <= 16; attrIndex++ {
			// Is this attribute requested
			if mask&(1<<(16-attrIndex)) != 0 {
				// Get definitions since we need the name
				attrDef, ok := attrDefs[attrIndex]
				if !ok {
					msg := fmt.Sprintf("Unexpected error, index %v not valued for ME %v",
						attrIndex, meDefinition.GetName())
					return nil, errors.New(msg)
				}
				var attrValue interface{}
				attrValue, ok = attrMap[attrDef.Name]
				if !ok {
					msg := fmt.Sprintf("Unexpected error, attribute %v not provided in ME %v: %v",
						attrDef.GetName(), meDefinition.GetName(), m)
					return nil, errors.New(msg)

				}
				// Is space available?
				if attrDef.Size <= payloadAvailable {
					// Mark bit handled
					mask &= ^(1 << (16 - attrIndex))
					meLayer.AttributeMask |= 1 << (16 - attrIndex)
					meLayer.Attributes[attrDef.Name] = attrValue
					payloadAvailable -= attrDef.Size
					attrRetry = false

				} else if opt.failIfTruncated || attrRetry {
					msg := fmt.Sprintf("out-of-space. Cannot fit attribute %v into SetRequest message",
						attrDef.GetName())
					return nil, errors.New(msg)
				} else {
					// Start another SetRequest frame
					payloadAvailable = int(maxPayload)

					meLayer := &SetRequest{
						MeBasePacket: MeBasePacket{
							EntityClass:    m.GetClassID(),
							EntityInstance: m.GetEntityID(),
						},
						AttributeMask: 0,
						Attributes:    make(me.AttributeValueMap),
					}
					results = append(results, meLayer)
					// Back up indexing by one and retry
					attrRetry = true
					attrIndex--
				}
			}
		}
	}
	if err == nil && len(results) == 0 {
		// TODO: Is a set request with no attributes valid?
		return nil, errors.New("no attributes encoded for SetRequest")
	}
	return results, nil
}

func (m *ManagedEntityInstance) setResponseFrame(opt options) (interface{}, error) {
	meLayer := &SetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		Result: opt.results,
	}
	if meLayer.Result == me.AttributeFailure {
		meLayer.UnsupportedAttributeMask = opt.unsupportedMask
		meLayer.FailedAttributeMask = opt.attrExecutionMask
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) getRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	if mask == 0 {
		// TODO: Is a Get request with no attributes valid?
		return nil, errors.New("no attributes requested for GetRequest")
	}
	meLayer := &GetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		AttributeMask: mask,
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) getResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	if mask == 0 {
		// TODO: Is a Get request with no attributes valid?
		return nil, errors.New("no attributes encoded for Get Response")
	}
	results := make([]*GetResponse, 0)
	meLayer := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		Result:        opt.results,
		AttributeMask: 0,
		Attributes:    make(me.AttributeValueMap),
	}
	if meLayer.Result == me.AttributeFailure {
		meLayer.UnsupportedAttributeMask = opt.unsupportedMask
		meLayer.FailedAttributeMask = opt.attrExecutionMask
	}
	// Encode whatever we can
	if meLayer.Result == me.Success || meLayer.Result == me.AttributeFailure {
		// Encode results
		// Get payload space available
		maxPayload := m.maxPacketAvailable(opt)
		payloadAvailable := int(maxPayload)
		meDefinition := m.GetManagedEntityDefinition()
		attrDefs := *meDefinition.GetAttributeDefinitions()
		attrMap := *m.GetAttributeValueMap()

		results = append(results, meLayer)

		for mask != 0 {
			// Iterate down the attributes (Attribute 0 is the ManagedEntity ID)
			var attrIndex uint
			for attrIndex = 1; attrIndex <= 16; attrIndex++ {
				// Is this attribute requested
				if mask&(1<<(16-attrIndex)) != 0 {
					// Get definitions since we need the name
					attrDef, ok := attrDefs[attrIndex]
					if !ok {
						msg := fmt.Sprintf("Unexpected error, index %v not valued for ME %v",
							attrIndex, meDefinition.GetName())
						return nil, errors.New(msg)
					}
					var attrValue interface{}
					attrValue, ok = attrMap[attrDef.Name]
					if !ok {
						msg := fmt.Sprintf("Unexpected error, attribute %v not provided in ME %v: %v",
							attrDef.GetName(), meDefinition.GetName(), m)
						return nil, errors.New(msg)

					}
					// Is space available?
					if attrDef.Size <= payloadAvailable {
						// Mark bit handled
						mask &= ^(1 << (16 - attrIndex))
						meLayer.AttributeMask |= 1 << (16 - attrIndex)
						meLayer.Attributes[attrDef.Name] = attrValue
						payloadAvailable -= attrDef.Size

						// If it is a table, set up our getNextResponses now
						if attrDef.IsTableAttribute() {
						}
					} else if opt.failIfTruncated {
						msg := fmt.Sprintf("out-of-space. Cannot fit attribute %v into SetRequest message",
							attrDef.GetName())
						return nil, errors.New(msg)
					} else {
						// Add to existing 'failed' mask and update result
						meLayer.FailedAttributeMask |= 1 << (16 - attrIndex)
						meLayer.Result = me.AttributeFailure
					}
				}
			}
		}
	}
	return results, nil
}

func (m *ManagedEntityInstance) getAllAlarmsRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetAllAlarmsRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getAllAlarmsResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetAllAlarmsResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getAllAlarmsNextRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetAllAlarmsNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getAllAlarmsNextResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetAllAlarmsNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) mibUploadRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) mibUploadResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) mibUploadNextRequestFrame(opt options) (interface{}, error) {
	// Common for all MEs
	meLayer := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		CommandSequenceNumber: opt.sequenceNumber,
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) mibUploadNextResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) mibResetRequestFrame(opt options) (interface{}, error) {
	// Common for all MEs
	meLayer := &MibResetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) mibResetResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &MibResetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) alarmNotificationFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &AlarmNotificationMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) attributeValueChangeFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &AttributeValueChangeMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) testRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &TestRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) testResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &TestResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) startSoftwareDownloadRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &StartSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) startSoftwareDownloadResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &StartSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) downloadSectionRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) downloadSectionResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) endSoftwareDownloadRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) endSoftwareDownloadResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) activateSoftwareRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &ActivateSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) activateSoftwareResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &ActivateSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) commitSoftwareRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) commitSoftwareResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) synchronizeTimeRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SynchronizeTimeRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) synchronizeTimeResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SynchronizeTimeResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) rebootRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &RebootRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) rebootResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &RebootResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getNextRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// TODO: For GetNext, we may want to make sure that only 1 attribute is being requested
	// Common for all MEs
	meLayer := &GetNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
		AttributeMask:  mask,
		SequenceNumber: opt.sequenceNumber,
	}
	return meLayer, nil
}

func (m *ManagedEntityInstance) getNextResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) testResultFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &TestResultMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getCurrentDataRequestFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetCurrentDataRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) getCurrentDataResponseFrame(opt options) (interface{}, error) {
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &GetCurrentDataResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) setTableRequestFrame(opt options) (interface{}, error) {
	if opt.frameFormat != ExtendedIdent {
		return nil, errors.New("SetTable message type only supported with Extended OMCI Messaging")
	}
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func (m *ManagedEntityInstance) setTableResponseFrame(opt options) (interface{}, error) {
	if opt.frameFormat != ExtendedIdent {
		return nil, errors.New("SetTable message type only supported with Extended OMCI Messaging")
	}
	mask, err := m.checkAttributeMask(opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SetTableResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
		},
	}
	// Get payload space available
	maxPayload := m.maxPacketAvailable(opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}
