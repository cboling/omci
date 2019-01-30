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
	"encoding/binary"
	"errors"
	"fmt"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

/////////////////////////////////////////////////////////////////////////////
// CreateRequest
type CreateRequest struct {
	MeBasePacket
	Attributes me.AttributeValueMap
}

func (omci *CreateRequest) String() string {
	return fmt.Sprintf("CreateRequest: %v, Attributes: %v", omci.MeBasePacket.String(), omci.Attributes)
}

func (omci *CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !me.SupportsMsgType(meDefinition, me.Create) {
		return me.NewProcessingError("managed entity does not support Create Message-Type")
	}
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= 1 << (15 - uint(index-1))
		}
	}
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(sbcMask, data[4:], p)
	return err
}

func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.MsgLayerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= 1 << (15 - uint(index-1))
		}
	}
	// Attribute serialization
	return meDefinition.SerializeAttributes(omci.Attributes, sbcMask, b)
}

/////////////////////////////////////////////////////////////////////////////
// CreateResponse
type CreateResponse struct {
	MeBasePacket
	Result                 me.Results
	AttributeExecutionMask uint16
}

func (omci *CreateResponse) String() string {
	return fmt.Sprintf("CreateResponse: %v, Result: %d (%v), Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeExecutionMask)
}

func (omci *CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	omci.Result = me.Results(data[4])
	omci.AttributeExecutionMask = binary.BigEndian.Uint16(data[5:])
	return nil
}

func decodeCreateResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.MsgLayerType = LayerTypeCreateResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CreateResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:], omci.AttributeExecutionMask)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteRequest
type DeleteRequest struct {
	MeBasePacket
}

func (omci *DeleteRequest) String() string {
	return fmt.Sprintf("DeleteRequest: %v", omci.MeBasePacket.String())
}

func (omci *DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	return nil
}

func decodeDeleteRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteRequest{}
	omci.MsgLayerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DeleteRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteResponse
type DeleteResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *DeleteResponse) String() string {
	return fmt.Sprintf("DeleteResponse: %v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

func (omci *DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	omci.Result = me.Results(data[4])
	return nil
}

func decodeDeleteResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.MsgLayerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DeleteResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// SetRequest
type SetRequest struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *SetRequest) String() string {
	return fmt.Sprintf("SetRequest: %v, Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
}

func (omci *SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if !me.SupportsAttributeAccess(attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	return nil
}

func decodeSetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.MsgLayerType = LayerTypeSetRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if !me.SupportsAttributeAccess(attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	return meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b)
}

/////////////////////////////////////////////////////////////////////////////
// SetResponse
type SetResponse struct {
	MeBasePacket
	Result                   me.Results
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
}

func (omci *SetResponse) String() string {
	return fmt.Sprintf("SetResponse: %v, Result: %d (%v), Unsupported Mask: %#x, Failed Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.UnsupportedAttributeMask,
		omci.FailedAttributeMask)
}

func (omci *SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	omci.Result = me.Results(data[4])

	if omci.Result == me.AttributeFailure {
		omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[5:7])
		omci.FailedAttributeMask = binary.BigEndian.Uint16(data[7:9])
	}
	return nil
}

func decodeSetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.MsgLayerType = LayerTypeSetResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Set Message-Type")
	}
	bytes, err := b.AppendBytes(5)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:3], omci.UnsupportedAttributeMask)
	binary.BigEndian.PutUint16(bytes[3:5], omci.FailedAttributeMask)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetRequest
type GetRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetRequest) String() string {
	return fmt.Sprintf("GetRequest: %v, Mask: %#x",
		omci.MeBasePacket.String(), omci.AttributeMask)
}
func (omci *GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetRequest{}
	omci.MsgLayerType = LayerTypeGetRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetResponse
type GetResponse struct {
	MeBasePacket
	Result                   me.Results
	AttributeMask            uint16
	Attributes               me.AttributeValueMap
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
}

func (omci *GetResponse) String() string {
	return fmt.Sprintf("GetResponse: %v, Result: %d (%v), Mask: %#x, Unsupported: %#x, Failed: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeMask,
		omci.UnsupportedAttributeMask, omci.FailedAttributeMask, omci.Attributes)
}

func (omci *GetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	omci.Result = me.Results(data[4])
	omci.AttributeMask = binary.BigEndian.Uint16(data[5:7])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[7:32], p)
	if err != nil {
		return err
	}
	// If Attribute failed or Unknown, decode optional attribute mask
	if omci.Result == me.AttributeFailure {
		omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[32:34])
		omci.FailedAttributeMask = binary.BigEndian.Uint16(data[34:36])
	}
	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	return nil
}

func decodeGetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetResponse{}
	omci.MsgLayerType = LayerTypeGetResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support the Get Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:3], omci.AttributeMask)

	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	// Attribute serialization
	err = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b)
	if err != nil {
		return err
	}
	// If Attribute failed or Unknown, decode optional attribute mask
	if omci.Result == me.AttributeFailure {
		bytesLeft := 36 - len(b.Bytes())
		bytes, err = b.AppendBytes(bytesLeft)
		if err != nil {
			return err
		}
		copy(bytes, lotsOfZeros[:])
		binary.BigEndian.PutUint16(bytes[bytesLeft-4:bytesLeft-2], omci.UnsupportedAttributeMask)
		binary.BigEndian.PutUint16(bytes[bytesLeft-2:bytesLeft], omci.FailedAttributeMask)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsRequest struct {
	MeBasePacket
	AlarmRetrievalMode byte
}

func (omci *GetAllAlarmsRequest) String() string {
	return fmt.Sprintf("GetAllAlarmsRequest: %v, Retrieval Mode: %v",
		omci.MeBasePacket.String(), omci.AlarmRetrievalMode)
}

func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.AlarmRetrievalMode = data[4]
	if omci.AlarmRetrievalMode > 1 {
		msg := fmt.Sprintf("invalid Alarm Retrieval Mode for Get All Alarms request: %v, must be 0..1",
			omci.AlarmRetrievalMode)
		return errors.New(msg)
	}
	return nil
}

func decodeGetAllAlarmsRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.AlarmRetrievalMode
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *GetAllAlarmsResponse) String() string {
	return fmt.Sprintf("GetAllAlarmsResponse: %v, NumberOfCommands: %d",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.NumberOfCommands)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *GetAllAlarmsNextRequest) String() string {
	return fmt.Sprintf("GetAllAlarmsNextRequest: %v, Sequence Number: %d",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.CommandSequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextResponse struct {
	MeBasePacket
	AlarmBitMap [28]byte // 224 bits
}

func (omci *GetAllAlarmsNextResponse) String() string {
	return fmt.Sprintf("GetAllAlarmsNextResponse: %v, Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmBitMap)
}

func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	copy(omci.AlarmBitMap[:], data[4:32])
	return nil
}

func decodeGetAllAlarmsNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	bytes, err := b.AppendBytes(28)
	if err != nil {
		return err
	}
	copy(bytes, omci.AlarmBitMap[:])
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadRequest
type MibUploadRequest struct {
	MeBasePacket
}

func (omci *MibUploadRequest) String() string {
	return fmt.Sprintf("MibUploadRequest: %v", omci.MeBasePacket.String())
}

func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	return nil
}

func decodeMibUploadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadRequest{}
	omci.MsgLayerType = LayerTypeMibUploadRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadResponse
type MibUploadResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *MibUploadResponse) String() string {
	return fmt.Sprintf("MibUploadResponse: %v, NumberOfCommands: %#v",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeMibUploadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadResponse{}
	omci.MsgLayerType = LayerTypeMibUploadResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(entity, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.NumberOfCommands)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *MibUploadNextRequest) String() string {
	return fmt.Sprintf("MibUploadNextRequest: %v, SequenceNumber: %v",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload Next request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload Next request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeMibUploadNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextRequest{}
	omci.MsgLayerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB upload
	if !me.SupportsMsgType(entity, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Next Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.CommandSequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextResponse struct {
	MeBasePacket
	ReportedME BaseManagedEntityInstance
}

func (omci *MibUploadNextResponse) String() string {
	return fmt.Sprintf("MibUploadNextResponse: %v, ReportedME: [%v]",
		omci.MeBasePacket.String(), omci.ReportedME)
}

func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MibUploadNext
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload Next response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload Next response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	// Decode reported ME.  If an out-of-range sequence number was sent, this will
	// contain an ME with class ID and entity ID of zero and you should get an
	// error of "managed entity definition not found" returned.
	return omci.ReportedME.DecodeFromBytes(data[4:], p)
}

func decodeMibUploadNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.MsgLayerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(entity, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Next Message-Type")
	}
	return omci.ReportedME.SerializeTo(b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
type MibResetRequest struct {
	MeBasePacket
}

func (omci *MibResetRequest) String() string {
	return fmt.Sprintf("MibResetRequest: %v", omci.MeBasePacket.String())
}

func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		msg := fmt.Sprintf("invalid Entity Class for MIB Reset request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Reset request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.MsgLayerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Add class ID and entity ID
	return omci.MeBasePacket.SerializeTo(b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetResponse
type MibResetResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *MibResetResponse) String() string {
	return fmt.Sprintf("MibResetResponse: %v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return me.NewProcessingError("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for MIB Reset Response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..8", omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeMibResetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.MsgLayerType = LayerTypeMibResetResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
const AlarmBitmapSize = 224

type AlarmNotificationMsg struct {
	MeBasePacket
	AlarmBitmap         [AlarmBitmapSize / 8]byte
	zeroPadding         [3]byte
	AlarmSequenceNumber byte
}

func (omci *AlarmNotificationMsg) String() string {
	return fmt.Sprintf("AlarmNotificationMsg: %v, SequenceNumber: %d, Alarm Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmSequenceNumber, omci.AlarmBitmap)
}

func (omci *AlarmNotificationMsg) IsAlarmActive(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 1, nil
}

func (omci *AlarmNotificationMsg) IsAlarmClear(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 0, nil
}

func (omci *AlarmNotificationMsg) ActivateAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] |= 1 << bit
	return nil
}

func (omci *AlarmNotificationMsg) ClearAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] &= ^(1 << bit)
	return nil
}

func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	//var meDefinition me.IManagedEntityDefinition
	//meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
	//	me.ParamData{EntityID: omci.EntityInstance})
	//if err != nil {
	//	return err
	//}
	// ME needs to support Alarms
	// TODO: Add attribute to ME to specify that alarm is allowed
	//if !me.SupportsMsgType(meDefinition, me.MibReset) {
	//	return me.NewProcesssingError("managed entity does not support MIB Reset Message-Type")
	//}
	for index, octet := range data[4 : (AlarmBitmapSize/8)-4] {
		omci.AlarmBitmap[index] = octet
	}
	padOffset := 4 + (AlarmBitmapSize / 8)
	omci.zeroPadding[0] = data[padOffset]
	omci.zeroPadding[1] = data[padOffset+1]
	omci.zeroPadding[2] = data[padOffset+2]

	omci.AlarmSequenceNumber = data[padOffset+3]
	return nil
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

func (omci *AlarmNotificationMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	//var meDefinition me.IManagedEntityDefinition
	//meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
	//	me.ParamData{EntityID: omci.EntityInstance})
	//if err != nil {
	//	return err
	//}
	// ME needs to support Alarms
	// TODO: Add attribute to ME to specify that alarm is allowed
	//if !me.SupportsMsgType(meDefinition, me.MibReset) {
	//	return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	//}
	bytes, err := b.AppendBytes((AlarmBitmapSize / 8) + 3 + 1)
	if err != nil {
		return err
	}
	for index, octet := range omci.AlarmBitmap {
		bytes[index] = octet
	}
	padOffset := AlarmBitmapSize / 8
	bytes[padOffset] = 0
	bytes[padOffset+1] = 0
	bytes[padOffset+2] = 0
	bytes[padOffset+3] = omci.AlarmSequenceNumber
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// AttributeValueChangeMsg
type AttributeValueChangeMsg struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *AttributeValueChangeMsg) String() string {
	return fmt.Sprintf("AttributeValueChangeMsg: %v, Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
}

func (omci *AttributeValueChangeMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:40], p)
	// TODO: Add support for attributes that can have an AVC associated with them and then add a check here
	// Validate all attributes support AVC
	//for attrName := range omci.Attributes {
	//	attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
	//	if err != nil {
	//		return err
	//	}
	//	if !me.SupportsAttributeAVC(attr) {
	//		msg := fmt.Sprintf("attribute '%v' does not support AVC notifications", attrName)
	//		return me.NewProcessingError(msg)
	//	}
	//}
	return err
}

func decodeAttributeValueChange(data []byte, p gopacket.PacketBuilder) error {
	omci := &AttributeValueChangeMsg{}
	omci.MsgLayerType = LayerTypeAttributeValueChange
	return decodingLayerDecoder(omci, data, p)
}

func (omci *AttributeValueChangeMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// TODO: Add support for attributes that can have an AVC associated with them and then add a check here
	// Validate all attributes support AVC
	//for attrName := range omci.Attributes {
	//	attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
	//	if err != nil {
	//		return err
	//	}
	//	if !me.SupportsAttributeAVC(attr) {
	//		msg := fmt.Sprintf("attribute '%v' does not support AVC notifications", attrName)
	//		return me.NewProcessingError(msg)
	//	}
	//}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	return meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct {
	MeBasePacket
}

func (omci *TestRequest) String() string {
	return fmt.Sprintf("TestRequest: %v", omci.MeBasePacket.String())
}

func (omci *TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // return nil
}

func decodeTestRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestRequest{}
	omci.MsgLayerType = LayerTypeTestRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// TestResponse:		TODO: Not yet implemented
type TestResponse struct {
	MeBasePacket
}

func (omci *TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // return nil
}

func decodeTestResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResponse{}
	omci.MsgLayerType = LayerTypeTestResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct {
	MeBasePacket                // Note: EntityInstance for software download is two specific values
	WindowSize           byte   // Window Size -1
	ImageSize            uint32 // Octets
	NumberOfCircuitPacks byte
	MSBInstance          []uint16 // MSB & LSB of software image instance
}

func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	omci.WindowSize = data[4]
	omci.ImageSize = binary.BigEndian.Uint32(data[5:9])
	omci.NumberOfCircuitPacks = data[9]
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks)
		return me.NewAttributeFailureError(msg)
	}
	omci.MSBInstance = make([]uint16, omci.NumberOfCircuitPacks)
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		omci.MSBInstance[index] = binary.BigEndian.Uint16(data[10+(index*2):])
	}
	return nil
}

func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(entity, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support the SStart Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks)
		return me.NewAttributeFailureError(msg)
	}
	bytes, err := b.AppendBytes(8 + (2 * int(omci.NumberOfCircuitPacks)))
	if err != nil {
		return err
	}
	bytes[4] = omci.WindowSize
	binary.BigEndian.PutUint32(bytes[5:9], omci.ImageSize)
	bytes[1] = omci.NumberOfCircuitPacks
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		binary.BigEndian.PutUint16(bytes[10+(index*2):], omci.MSBInstance[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type downloadResults struct {
	ManagedEntityID uint16 // ME ID of software image entity instance (slot number plus instance 0..1 or 2..254 vendor-specific)
	Result          me.Results
}

type StartSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	WindowSize        byte // Window Size -1
	NumberOfInstances byte
	MeResults         []downloadResults
}

func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.WindowSize = data[5]
	omci.NumberOfInstances = data[6]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]downloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[7+(index*3):])
			omci.MeResults[index].Result = me.Results(data[9+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeStartSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	bytes, err := b.AppendBytes(3 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.WindowSize
	bytes[2] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[3+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[5+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	SectionNumber byte
	SectionData   [29]byte // 0 padding if final transfer requires only a partial block
}

func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Download Section request")
	}
	omci.SectionNumber = data[4]
	copy(omci.SectionData[0:], data[5:])
	return nil
}

func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	bytes, err := b.AppendBytes(1 + 29)
	if err != nil {
		return err
	}
	bytes[0] = omci.SectionNumber
	copy(bytes[1:], omci.SectionData[0:])
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionResponse struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	Result        me.Results
	SectionNumber byte
}

func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.SectionNumber = data[5]
	return nil
}

func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = omci.SectionNumber
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[1] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	CRC32             uint32
	ImageSize         uint32
	NumberOfInstances byte
	ImageInstances    []uint16
}

func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for End Software Download request")
	}
	omci.CRC32 = binary.BigEndian.Uint32(data[4:8])
	omci.ImageSize = binary.BigEndian.Uint32(data[8:12])
	omci.NumberOfInstances = data[13]

	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances)
		return me.NewAttributeFailureError(msg)
	}
	omci.ImageInstances = make([]uint16, omci.NumberOfInstances)

	for index := 0; index < int(omci.NumberOfInstances); index++ {
		omci.ImageInstances[index] = binary.BigEndian.Uint16(data[14+(index*2):])
	}
	return nil
}

func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances)
		return me.NewAttributeFailureError(msg)
	}
	bytes, err := b.AppendBytes(9 + (2 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(bytes[4:8], omci.CRC32)
	binary.BigEndian.PutUint32(bytes[8:12], omci.ImageSize)
	bytes[13] = omci.NumberOfInstances
	for index := 0; index < int(omci.NumberOfInstances); index++ {
		binary.BigEndian.PutUint16(bytes[14+(index*2):], omci.ImageInstances[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	NumberOfInstances byte
	MeResults         []downloadResults
}

func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.NumberOfInstances = data[5]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]downloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[6+(index*3):])
			omci.MeResults[index].Result = me.Results(data[8+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeEndSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for End Download response")
	}
	bytes, err := b.AppendBytes(3 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[2+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[4+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	ActivateFlags byte
}

func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	omci.ActivateFlags = data[4]
	if omci.ActivateFlags > 2 {
		msg := fmt.Sprintf("invalid number of Activation flangs: %v, must be 0..2",
			omci.ActivateFlags)
		return me.NewAttributeFailureError(msg)
	}
	return nil
}

func decodeActivateSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.MsgLayerType = LayerTypeActivateSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.ActivateFlags
	if omci.ActivateFlags > 2 {
		msg := fmt.Sprintf("invalid results for Activate Software request: %v, must be 0..2",
			omci.ActivateFlags)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeActivateSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.MsgLayerType = LayerTypeActivateSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct {
	MeBasePacket
}

func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
	}
	return nil
}

func decodeCommitSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.MsgLayerType = LayerTypeCommitSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareResponse struct {
	MeBasePacket
}

func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	return nil
}

func decodeCommitSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.MsgLayerType = LayerTypeCommitSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassId {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct {
	MeBasePacket
	Year   uint16
	Month  uint8
	Day    uint8
	Hour   uint8
	Minute uint8
	Second uint8
}

func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassId {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time request")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time request")
	}
	omci.Year = binary.BigEndian.Uint16(data[4:6])
	omci.Month = data[6]
	omci.Day = data[7]
	omci.Hour = data[8]
	omci.Minute = data[9]
	omci.Second = data[10]
	return nil
}

func decodeSynchronizeTimeRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SynchronizeTimeRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(7)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.Year)
	bytes[2] = omci.Month
	bytes[3] = omci.Day
	bytes[4] = omci.Hour
	bytes[5] = omci.Minute
	bytes[6] = omci.Second
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeResponse struct {
	MeBasePacket
	Results        me.Results
	SuccessResults uint8 // Only if 'Results' is 0 -> success
}

func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassId {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}
	omci.Results = me.Results(data[4])
	if omci.Results > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..8", omci.Results)
		return errors.New(msg)
	}
	omci.SuccessResults = data[5]
	return nil
}

func decodeSynchronizeTimeResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SynchronizeTimeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// Synchronize Time Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassId {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	numBytes := 2
	if omci.Results != me.Success {
		numBytes = 1
	}
	bytes, err := b.AppendBytes(numBytes)
	if err != nil {
		return err
	}
	bytes[0] = uint8(omci.Results)
	if omci.Results == me.Success {
		bytes[1] = omci.SuccessResults
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct {
	MeBasePacket
	RebootCondition byte
}

func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	omci.RebootCondition = data[4]
	if omci.RebootCondition > 3 {
		msg := fmt.Sprintf("invalid reboot condition code: %v, must be 0..3", omci.RebootCondition)
		return errors.New(msg)
	}
	return nil
}

func decodeRebootRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.MsgLayerType = LayerTypeRebootRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *RebootRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	if omci.RebootCondition > 3 {
		msg := fmt.Sprintf("invalid reboot condition code: %v, must be 0..3", omci.RebootCondition)
		return me.NewAttributeFailureError(msg)
	}
	bytes[0] = omci.RebootCondition
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.Result = me.Results(data[4])
	return nil
}

func decodeRebootResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.MsgLayerType = LayerTypeRebootResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *RebootResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity me.IManagedEntityDefinition
	entity, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct {
	MeBasePacket
	AttributeMask  uint16
	SequenceNumber uint16
}

func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	omci.SequenceNumber = binary.BigEndian.Uint16(data[6:8])
	return nil
}

func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.MsgLayerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	binary.BigEndian.PutUint16(bytes, omci.SequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextResponse struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	// TODO: Validate attributes support 'Read' access ?

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	return nil
}

func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.MsgLayerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support the Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.AttributeMask)
	// TODO: Validate attributes support 'Read' access ?

	// Attribute serialization
	err = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b)
	if err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResultMsg struct {
	MeBasePacket
}

func (omci *TestResultMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // return nil
}

func decodeTestResult(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResultMsg{}
	omci.MsgLayerType = LayerTypeTestResult
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestResultMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me) // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetCurrentDataRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.MsgLayerType = LayerTypeGetCurrentDataRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetCurrentDataRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataResponse struct {
	MeBasePacket
	Result        me.Results
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	return nil
}

func decodeGetCurrentDataResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.MsgLayerType = LayerTypeGetCurrentDataResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetCurrentDataResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	var meDefinition me.IManagedEntityDefinition
	meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support the Get Current Data Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.AttributeMask)

	// Attribute serialization
	err = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b)
	if err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.MsgLayerType = LayerTypeSetTableRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") /// TODO: Fix me when extended messages supported)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableResponse struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.MsgLayerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

/////////////////////////////////////////////////////////////////////////////
//
type UnsupportedMessageTypeResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *UnsupportedMessageTypeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("you should never really decode this")
}

func (omci *UnsupportedMessageTypeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	return nil
}
