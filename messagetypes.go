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
	"./generated"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
)

/////////////////////////////////////////////////////////////////////////////
// CreateRequest
type CreateRequestPacket struct {
	generated.CreateRequest
	cachedME
	cachedME generated.IManagedEntity // Cache any ME decoded from the request  (TODO: Should these be public?)
}

func (omci *CreateRequestPacket) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := msgBasePacket.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !generated.SupportsMsgType(omci.cachedME, generated.Create) {
		return errors.New("managed entity does not support Create Message-Type")
	}
	var sbcMask uint16
	for index, attr := range omci.GetAttributes() {
		if generated.SupportsAttributeAccess(attr, generated.SetByCreate) {
			sbcMask |= 1 << (15 - uint(index))
		}
	}
	// Attribute decode
	err = omci.Decode(sbcMask, data[4:], p)
	if err != nil {
		return err
	}
	omci.Attributes = omci.cachedME.GetAttributes()
	return nil
}

func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.layerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var sbcMask uint16
	for index, attr := range omci.cachedME.GetAttributes() {
		if SupportsAttributeAccess(attr, SetByCreate) {
			sbcMask |= 1 << (15 - uint(index))
		}
	}
	// Attribute serialization
	return omci.cachedME.SerializeTo(sbcMask, b)
}

/////////////////////////////////////////////////////////////////////////////
// CreateResponse
//type CreateResponse struct {
//	msgBase
//	Result                 Results
//	AttributeExecutionMask byte
//}

func (omci *CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !SupportsMsgType(entity, Create) {
		return errors.New("managed entity does not support the Create Message-Type")
	}
	omci.Result = Results(data[4])
	omci.AttributeExecutionMask = data[5]
	return nil
}
func decodeCreateResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.layerType = LayerTypeCreateResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CreateResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !SupportsMsgType(entity, Create) {
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
//type DeleteRequest struct {
//	msgBase
//}

func (omci *DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !SupportsMsgType(entity, Delete) {
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	return nil
}

func decodeDeleteRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DeleteRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !SupportsMsgType(entity, Delete) {
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteResponse
//type DeleteResponse struct {
//	msgBase
//	Result Results
//}

func (omci *DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !SupportsMsgType(entity, Delete) {
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	omci.Result = Results(data[4])
	return nil
}

func decodeDeleteResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DeleteResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !SupportsMsgType(entity, Delete) {
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
//type SetRequest struct {
//	msgBase
//	AttributeMask uint16
//	Attributes    []IAttribute // Write attributes
//
//	cachedME IManagedEntity // Cache any ME decoded from the request
//}

func (omci *SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !SupportsMsgType(omci.cachedME, Set) {
		return errors.New("managed entity does not support Set Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	err = omci.cachedME.Decode(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	// Validate all attributes support write
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attr.Name())
			return errors.New(msg)
		}
	}
	omci.Attributes = omci.cachedME.GetAttributes()
	return nil
}

func decodeSetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !SupportsMsgType(omci.cachedME, Set) {
		return errors.New("managed entity does not support Set Message-Type")
	}
	// Validate all attributes support write
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attr.Name())
			return errors.New(msg)
		}
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	return omci.cachedME.SerializeTo(omci.AttributeMask, b)
}

/////////////////////////////////////////////////////////////////////////////
// SetResponse
//type SetResponse struct {
//	msgBase
//	Result                   Results
//	UnsupportedAttributeMask uint16
//	FailedAttributeMask      uint16 // TODO: Use this for no-space-left?
//}

func (omci *SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Delete
	if !SupportsMsgType(entity, Delete) {
		return errors.New("managed entity does not support the Delete Message-Type")
	}
	omci.Result = Results(data[4])
	omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[5:7])
	omci.FailedAttributeMask = binary.BigEndian.Uint16(data[7:9])
	return nil
}

func decodeSetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !SupportsMsgType(entity, Set) {
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
//type GetRequest struct {
//	msgBase
//	AttributeMask uint16
//	Attributes    []IAttribute // Read attributes
//
//	cachedME IManagedEntity // Cache any ME decoded from the request
//}

func (omci *GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !SupportsMsgType(omci.cachedME, Get) {
		return errors.New("managed entity does not support Get Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	err = omci.cachedME.Decode(omci.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	// Validate all attributes support Read
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.Name())
			return errors.New(msg)
		}
	}
	omci.Attributes = omci.cachedME.GetAttributes()
	return nil
}

func decodeGetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Set
	if !SupportsMsgType(omci.cachedME, Get) {
		return errors.New("managed entity does not support Get Message-Type")
	}
	// Validate all attributes support read
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.Name())
			return errors.New(msg)
		}
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	return omci.cachedME.SerializeTo(omci.AttributeMask, b)
}

/////////////////////////////////////////////////////////////////////////////
// GetResponse
//type GetResponse struct {
//	msgBase
//	Result                   Results
//	AttributeMask            uint16
//	Attributes               []IAttribute // Read attributes
//	UnsupportedAttributeMask uint16
//	FailedAttributeMask      uint16
//
//	cachedME IManagedEntity // Cache any ME decoded from the response
//}

func (omci *GetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !SupportsMsgType(omci.cachedME, Get) {
		return errors.New("managed entity does not support Get Message-Type")
	}
	omci.Result = Results(data[4])
	omci.AttributeMask = binary.BigEndian.Uint16(data[5:7])

	// Attribute decode
	err = omci.cachedME.Decode(omci.AttributeMask, data[7:32], p)
	if err != nil {
		return err
	}
	// If Attribute failed or Unknown, decode optional attribute mask
	if omci.Result == AttributeFailure {
		omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[32:34])
		omci.FailedAttributeMask = binary.BigEndian.Uint16(data[34:36])
	}
	// Validate all attributes support read
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.Name())
			return errors.New(msg)
		}
	}
	omci.Attributes = omci.cachedME.GetAttributes()
	return nil
}

func decodeGetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !SupportsMsgType(entity, Get) {
		return errors.New("managed entity does not support the Get Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:3], omci.AttributeMask)

	// Validate all attributes support read
	for _, attr := range omci.cachedME.GetAttributes() {
		if !SupportsAttributeAccess(attr, Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attr.Name())
			return errors.New(msg)
		}
	}
	// Attribute serialization
	err = omci.cachedME.SerializeTo(omci.AttributeMask, b)
	if err != nil {
		return err
	}
	// If Attribute failed or Unknown, decode optional attribute mask
	if omci.Result == AttributeFailure {
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
//type GetAllAlarmsRequest struct {
//	msgBase
//	AlarmRetrievalMode byte
//	cachedME           IManagedEntity // Cache any ME decoded from the request
//}

func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(omci.cachedME, GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(entity, GetAllAlarms) {
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
//type GetAllAlarmsResponse struct {
//	msgBase
//	NumberOfCommands uint16
//	cachedME         IManagedEntity // Cache any ME decoded from the response
//}

func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(omci.cachedME, GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(entity, GetAllAlarms) {
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
//type GetAllAlarmsNextRequest struct {
//	msgBase
//
//	CommandSequenceNumber uint16
//	cachedME              IManagedEntity // Cache any ME decoded from the request
//}

func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(omci.cachedME, GetAllAlarms) {
		return errors.New("managed entity does not support Get All Alarms Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !SupportsMsgType(entity, GetAllAlarmsNext) {
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
//type GetAllAlarmsNextResponse struct {
//	msgBase
//	AlarmBitMap [28]byte       // 224 bits
//	cachedME    IManagedEntity // Cache any ME decoded from the response
//}

func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !SupportsMsgType(omci.cachedME, GetAllAlarmsNext) {
		return errors.New("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms Next
	if !SupportsMsgType(entity, GetAllAlarmsNext) {
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
//type MibUploadRequest struct {
//	msgBase
//	cachedME IManagedEntity // Cache any ME decoded from the request
//}

func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !SupportsMsgType(omci.cachedME, MibUpload) {
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Upload request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Upload request")
	}
	return nil
}

func decodeMibUploadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadRequest{}
	omci.layerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get
	if !SupportsMsgType(entity, MibUpload) {
		return errors.New("managed entity does not support the MIB Upload Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadResponse
//type MibUploadResponse struct {
//	msgBase
//	NumberOfCommands uint16
//	cachedME         IManagedEntity // Cache any ME decoded from the response
//}

func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !SupportsMsgType(omci.cachedME, MibUpload) {
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support MIB Upload
	if !SupportsMsgType(entity, MibUpload) {
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
//type MibUploadNextRequest struct {
//	msgBase
//	CommandSequenceNumber uint16
//
//	cachedME IManagedEntity // Cache any ME decoded from the request
//}

func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(omci.cachedME, MibUploadNext) {
		return errors.New("managed entity does not support MIB Upload Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	var entity IManagedEntity
	entity, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support MIB upload
	if !SupportsMsgType(entity, MibUploadNext) {
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
//type MibUploadNextResponse struct {
//	msgBase
//	cachedME IManagedEntity // Cache any ME decoded from the response
//
//	uploadedME IManagedEntity
//}

func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support Get All Alarms
	if !SupportsMsgType(omci.cachedME, MibUploadNext) {
		return errors.New("managed entity does not support MIB Upload Next Message-Type")
	}
	// Get All Alarms request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
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
	omci.layerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
//type MibResetRequest struct {
//	msgBase
//	cachedME IManagedEntity // Cache any ME decoded from the request
//}

func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	omci.cachedME, err = generated.LoadManagedEntityDefinition(omci.EntityClass,
		generated.ParamData{omci.EntityInstance, nil})
	if err != nil {
		return err
	}
	// ME needs to support MIB reset
	if !SupportsMsgType(omci.cachedME, MibReset) {
		return errors.New("managed entity does not support Create Message-Type")
	}
	// MIB Reset request Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset request")
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.layerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Add class ID and entity ID
	return omci.msgBase.SerializeTo(b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetResponse
//type MibResetResponse struct {
//	msgBase
//}

func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeMibResetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.layerType = LayerTypeMibResetResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
//type AlarmNotificationMsg struct {
//	msgBase
//}

func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.layerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

func (omci *AlarmNotificationMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
//type AttributeValueChangeMsg struct {
//	msgBase
//}

func (omci *AttributeValueChangeMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeAttributeValueChange(data []byte, p gopacket.PacketBuilder) error {
	omci := &AttributeValueChangeMsg{}
	omci.layerType = LayerTypeAttributeValueChange
	return decodingLayerDecoder(omci, data, p)
}

func (omci *AttributeValueChangeMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type TestRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeTestRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestRequest{}
	omci.layerType = LayerTypeTestRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type TestResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeTestResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResponse{}
	omci.layerType = LayerTypeTestResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type StartSoftwareDownloadRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.layerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type StartSoftwareDownloadResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeStartSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.layerType = LayerTypeStartSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type DownloadSectionRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.layerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type DownloadSectionResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.layerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type EndSoftwareDownloadRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.layerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type EndSoftwareDownloadResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeEndSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.layerType = LayerTypeEndSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type ActivateSoftwareRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeActivateSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.layerType = LayerTypeActivateSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type ActivateSoftwareResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeActivateSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.layerType = LayerTypeActivateSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type CommitSoftwareRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeCommitSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.layerType = LayerTypeCommitSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type CommitSoftwareResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeCommitSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.layerType = LayerTypeCommitSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type SynchronizeTimeRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeSynchronizeTimeRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.layerType = LayerTypeSynchronizeTimeRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SynchronizeTimeRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type SynchronizeTimeResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeSynchronizeTimeResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.layerType = LayerTypeSynchronizeTimeResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SynchronizeTimeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type RebootRequest struct {
//	msgBase
//}

func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeRebootRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.layerType = LayerTypeRebootRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *RebootRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type RebootResponse struct {
//	msgBase
//}

func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeRebootResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.layerType = LayerTypeRebootResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *RebootResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type GetNextRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.layerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type GetNextResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.layerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type TestResultMsg struct {
//	msgBase
//	// TODO: implement
//}

func (omci *TestResultMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeTestResult(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResultMsg{}
	omci.layerType = LayerTypeTestResult
	return decodingLayerDecoder(omci, data, p)
}

func (omci *TestResultMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type GetCurrentDataRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeGetCurrentDataRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.layerType = LayerTypeGetCurrentDataRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetCurrentDataRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type GetCurrentDataResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeGetCurrentDataResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.layerType = LayerTypeGetCurrentDataResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *GetCurrentDataResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type SetTableRequest struct {
//	msgBase
//	// TODO: implement
//}

func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.layerType = LayerTypeSetTableRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}

/////////////////////////////////////////////////////////////////////////////
//
//type SetTableResponse struct {
//	msgBase
//	// TODO: implement
//}

func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.msgBase.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // return nil
}

func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.layerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}

func (omci *SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.msgBase.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("TODO: Need to implement") // omci.cachedME.SerializeTo(mask, b)
}
