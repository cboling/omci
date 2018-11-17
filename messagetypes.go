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
		return errors.New("managed entity does not support Create Message-Type")
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
	AttributeExecutionMask byte
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
		return errors.New("managed entity does not support the Create Message-Type")
	}
	omci.Result = me.Results(data[4])
	omci.AttributeExecutionMask = data[5]
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
		return errors.New("managed entity does not support the Create Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.AttributeExecutionMask
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteRequest
type DeleteRequest struct {
	MeBasePacket
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
		return errors.New("managed entity does not support the Delete Message-Type")
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
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteResponse
type DeleteResponse struct {
	MeBasePacket
	Result me.Results
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
		return errors.New("managed entity does not support the Delete Message-Type")
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
		return errors.New("managed entity does not support the Delete Message-Type")
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
		return errors.New("managed entity does not support Set Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	// Validate all attributes support write
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attr.GetName())
			return errors.New(msg)
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
		return errors.New("managed entity does not support Set Message-Type")
	}
	// Validate all attributes support write
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attr.GetName())
			return errors.New(msg)
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
	FailedAttributeMask      uint16 // TODO: Use this for no-space-left?
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
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	omci.Result = me.Results(data[4])
	omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[5:7])
	omci.FailedAttributeMask = binary.BigEndian.Uint16(data[7:9])
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
		return errors.New("managed entity does not support the Set Message-Type")
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
	Attributes    me.AttributeValueMap
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
		return errors.New("managed entity does not support Get Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	// Validate all attributes support Read
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.GetName())
			return errors.New(msg)
		}
	}
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
		return errors.New("managed entity does not support Get Message-Type")
	}
	// Validate all attributes support read
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.GetName())
			return errors.New(msg)
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
// GetResponse
type GetResponse struct {
	MeBasePacket
	Result                   me.Results
	AttributeMask            uint16
	Attributes               me.AttributeValueMap
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
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
		return errors.New("managed entity does not support Get Message-Type")
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
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.GetName())
			return errors.New(msg)
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
		return errors.New("managed entity does not support the Get Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:3], omci.AttributeMask)

	// Validate all attributes support read
	for index := range omci.Attributes {
		attr, ok := meDefinition.GetAttributeDefinitions()[index]
		if !ok {
			// TODO: add better detail for error message
			return errors.New("attribute not found")
		}
		if !me.SupportsAttributeAccess(attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.GetName())
			return errors.New(msg)
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

func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for Get All Alarms request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for Get All Alarms request")
	}
	omci.AlarmRetrievalMode = data[4]
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
		return errors.New("managed entity does not support the Get All Alarms Message-Type")
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

func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for Get All Alarms response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for Get All Alarms response")
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
		return errors.New("managed entity does not support the Get All Alarms Message-Type")
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
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for Get All Alarms request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for Get All Alarms request")
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
		return errors.New("managed entity does not support the Get All Alarms Next Message-Type")
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
		return errors.New("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for Get All Alarms Next response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for Get All Alarms Next response")
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
		return errors.New("managed entity does not support the Get All Alarms Next Message-Type")
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
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Upload request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Upload request")
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
		return errors.New("managed entity does not support the MIB Upload Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadResponse
type MibUploadResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Upload response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Upload response")
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
		return errors.New("managed entity does not support the MIB Upload Message-Type")
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

func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Upload request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Upload request")
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
		return errors.New("managed entity does not support the MIB Upload Message-Type")
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return errors.New("managed entity does not support MIB Upload Next Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Upload Next response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Upload Next response")
	}
	// Create ME to hold uploaded information

	// TODO: Work on best way to decode the uploaded ME

	//classID := binary.BigEndian.Uint16(data[4:6])
	//entityID := binary.BigEndian.Uint16(data[6:8])
	//omci.uploadedME, err := LoadManagedEntityDefinition(classID, entityIDe)
	//if err != nil {
	//	return err
	//}
	//omci.uploadedME..AttributeMask = binary.BigEndian.Uint16(data[8:10])
	//omci.Attributes = omci.cachedME.Attributes()
	//
	return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
type MibResetRequest struct {
	MeBasePacket
}

func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return errors.New("managed entity does not support Create Message-Type")
	}
	// MIB Reset request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Reset request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset request")
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
}

func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
type AlarmNotificationMsg struct {
	MeBasePacket
}

func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
type AttributeValueChangeMsg struct {
	MeBasePacket
}

func (omci *AttributeValueChangeMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassId {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct {
	MeBasePacket
}

func (omci *TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResponse struct {
	MeBasePacket
}

func (omci *TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct {
	MeBasePacket
}

func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadResponse struct {
	MeBasePacket
}

func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct {
	MeBasePacket
}

func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionResponse struct {
	MeBasePacket
}

func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct {
	MeBasePacket
}

func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadResponse struct {
	MeBasePacket
}

func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct {
	MeBasePacket
}

func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareResponse struct {
	MeBasePacket
}

func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
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
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
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
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct {
	MeBasePacket
}

func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeResponse struct {
	MeBasePacket
}

func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct {
	MeBasePacket
}

func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootResponse struct {
	MeBasePacket
}

func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct {
	MeBasePacket
}

func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextResponse struct {
	MeBasePacket
}

func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
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
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct {
	MeBasePacket
}

func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataResponse struct {
	MeBasePacket
}

func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct {
	MeBasePacket
}

func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableResponse struct {
	MeBasePacket
}

func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // return nil
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
	return errors.New("need to implement") // omci.cachedME.SerializeTo(mask, b)
}
