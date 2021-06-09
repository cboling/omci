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
	"fmt"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

/////////////////////////////////////////////////////////////////////////////
// MibUploadRequest
type MibUploadRequest struct {
	MeBasePacket
}

func (omci *MibUploadRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Request into this layer
func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
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

// SerializeTo provides serialization of an MIB Upload Request message
func (omci *MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
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
	return fmt.Sprintf("%v, NumberOfCommands: %#v",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Response into this layer
func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
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

// SerializeTo provides serialization of an MIB Upload Response message
func (omci *MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
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
	return fmt.Sprintf("%v, SequenceNumberCountOrSize: %v",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Request into this layer
func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
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

// SerializeTo provides serialization of an MIB Upload Next Request message
func (omci *MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
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
	ReportedME me.ManagedEntity
}

func (omci *MibUploadNextResponse) String() string {
	return fmt.Sprintf("%v, ReportedME: [%v]",
		omci.MeBasePacket.String(), omci.ReportedME.String())
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Response into this layer
func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+6)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MibUploadNext
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
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
	return omci.ReportedME.DecodeFromBytes(data[4:], p, byte(MibUploadNextResponseType))
}

func decodeMibUploadNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.MsgLayerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Next Response message
func (omci *MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(entity, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Next Message-Type")
	}
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 8 - 8

	return omci.ReportedME.SerializeTo(b, byte(MibUploadNextResponseType), bytesAvailable, opts)
}
