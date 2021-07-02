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

type MibUploadRequest struct {
	MeBasePacket
}

func (omci *MibUploadRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeMibUploadRequest
func (omci *MibUploadRequest) LayerType() gopacket.LayerType {
	return LayerTypeMibUploadRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibUploadRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeMibUploadRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibUploadRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Request into this layer
func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6
	} else {
		hdrSize = 4
	}
	// TODO: Move following check into DecodeFromBytes once we have a chance to verify
	//       ALL message type settings
	if len(data) < hdrSize {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
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

func decodeMibUploadRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadRequest{}
	omci.MsgLayerType = LayerTypeMibUploadRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Request message
func (omci *MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// Add length if extended ident
	if omci.Extended {
		bytes, err := b.AppendBytes(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, 0)
	}
	return nil
}

type MibUploadResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *MibUploadResponse) String() string {
	return fmt.Sprintf("%v, NumberOfCommands: %#v",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// LayerType returns LayerTypeMibUploadResponse
func (omci *MibUploadResponse) LayerType() gopacket.LayerType {
	return LayerTypeMibUploadResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibUploadResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeMibUploadResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibUploadResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Response into this layer
func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 2
	} else {
		hdrSize = 4 + 2
	}
	// TODO: Move following check into DecodeFromBytes once we have a chance to verify
	//       ALL message type settings
	if len(data) < hdrSize {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
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
	offset := hdrSize - 2
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[offset:])
	return nil
}

func decodeMibUploadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadResponse{}
	omci.MsgLayerType = LayerTypeMibUploadResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeMibUploadResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadResponse{}
	omci.MsgLayerType = LayerTypeMibUploadResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Response message
func (omci *MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header
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
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 2)
	if err != nil {
		return err
	}
	// Add length if extended ident
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 2)
	}
	binary.BigEndian.PutUint16(bytes[offset:], omci.NumberOfCommands)
	return nil
}

type MibUploadNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *MibUploadNextRequest) String() string {
	return fmt.Sprintf("%v, SequenceNumberCountOrSize: %v",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// LayerType returns LayerTypeMibUploadNextRequest
func (omci *MibUploadNextRequest) LayerType() gopacket.LayerType {
	return LayerTypeMibUploadNextRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibUploadNextRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeMibUploadNextRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibUploadNextRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Request into this layer
func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 2
	} else {
		hdrSize = 4 + 2
	}
	// TODO: Move following check into DecodeFromBytes once we have a chance to verify
	//       ALL message type settings
	if len(data) < hdrSize {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
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
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4+offset:])
	return nil
}

func decodeMibUploadNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextRequest{}
	omci.MsgLayerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeMibUploadNextRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextRequest{}
	omci.MsgLayerType = LayerTypeMibUploadNextRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Next Request message
func (omci *MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(2 + offset)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 2)
	}
	binary.BigEndian.PutUint16(bytes[offset:], omci.CommandSequenceNumber)
	return nil
}

type IMibUploadNextResponse interface {
	GetMeBasePacket() *MeBasePacket
	GetMeCount() int
	GetManagedEntity(int) *me.ManagedEntity
	AddManagedEntity(*me.ManagedEntity) error
}

type MibUploadNextResponse struct {
	MeBasePacket
	ReportedME    me.ManagedEntity
	AdditionalMEs []me.ManagedEntity // Valid only for extended message set version
}

type MibUploadNextManageEntity struct {
	AttrSize   uint16 // Size of ME instance attribute values included
	ReportedME me.ManagedEntity
}

func (omci *MibUploadNextResponse) String() string {
	return fmt.Sprintf("%v, ReportedME: [%v]",
		omci.MeBasePacket.String(), omci.ReportedME.String())
}

// LayerType returns LayerTypeMibUploadNextResponse
func (omci *MibUploadNextResponse) LayerType() gopacket.LayerType {
	return LayerTypeMibUploadNextResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibUploadNextResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeMibUploadNextResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibUploadNextResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Response into this layer
func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6
	} else {
		hdrSize = 4
	}
	// TODO: Move following check into DecodeFromBytes once we have a chance to verify
	//       ALL message type settings
	if len(data) < hdrSize {
		p.SetTruncated()
		return errors.New("frame too small: MIB Upload Response message-type header truncated")
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
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
	var offset int
	var attrLen int
	if omci.Extended {
		offset = 2 + 2 // Message Contents length (2) + first ME attribute values len (2)
		attrLen = int(binary.BigEndian.Uint16(data[6:]))

		if len(data[4+offset:]) < 6+attrLen {
			p.SetTruncated()
			return errors.New("frame too small: MIB Upload Response Managed Entity attribute truncated")
		}
	}
	err = omci.ReportedME.DecodeFromBytes(data[4+offset:], p, byte(MibUploadNextResponseType))
	if err != nil || !omci.Extended {
		return err
	}
	// Handle extended message set decode here for additional attributes
	remaining := len(data) - (6 + 8 + attrLen)
	if remaining > 0 {
		offset = 6 + 8 + attrLen
		omci.AdditionalMEs = make([]me.ManagedEntity, 0)
		for remaining > 0 {
			if len(data[offset:]) < 8 {
				p.SetTruncated()
				// TODO: Review all "frame to small" and add an extra hint for developers
				return errors.New("frame too small: MIB Upload Response Managed Entity header truncated")
			}
			additional := me.ManagedEntity{}
			attrLen = int(binary.BigEndian.Uint16(data[offset:]))

			if len(data[offset:]) < 8+attrLen {
				p.SetTruncated()
				return errors.New("frame too small: MIB Upload Response Managed Entity attribute truncated")
			}
			err = additional.DecodeFromBytes(data[offset+2:], p, byte(MibUploadNextResponseType))
			if err != nil {
				return err
			}
			omci.AdditionalMEs = append(omci.AdditionalMEs, additional)
			remaining -= 8 + attrLen
			offset += 8 + attrLen
		}
	}
	return nil
}

func decodeMibUploadNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.MsgLayerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeMibUploadNextResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.MsgLayerType = LayerTypeMibUploadNextResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Next Response message
func (omci *MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header
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
	bytesAvailable := MaxBaselineLength - 8 - 8

	if omci.Extended {
		bytesAvailable = MaxExtendedLength - 10 - 4
	}
	attributeBuffer := gopacket.NewSerializeBuffer()
	attrErr := omci.ReportedME.SerializeTo(attributeBuffer, byte(MibUploadNextResponseType), bytesAvailable, opts)
	if attrErr != nil {
		return attrErr
	}
	var offset int
	if omci.Extended {
		offset = 2 + 2 // Message Contents length (2) + first ME attribute values len (2)
	}
	meLength := len(attributeBuffer.Bytes())
	buf, attrErr := b.AppendBytes(meLength + offset)
	if attrErr != nil {
		return attrErr
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(buf, uint16(meLength+2))
		binary.BigEndian.PutUint16(buf[2:], uint16(meLength-6))
	}
	copy(buf[offset:], attributeBuffer.Bytes())

	if omci.Extended && omci.AdditionalMEs != nil {
		// Handle additional Managed Entities here for the Extended Message set
		bytesAvailable -= 4 + meLength
		length := meLength + 2

		for index, entry := range omci.AdditionalMEs {
			if bytesAvailable <= 8 {
				msg := fmt.Sprintf("not enough space to fit all requested Managed Entities, entry: %v", index)
				attrErr = me.NewMessageTruncatedError(msg)
				if attrErr != nil {
					return attrErr
				}
			}
			attributeBuffer = gopacket.NewSerializeBuffer()
			attrErr = entry.SerializeTo(attributeBuffer, byte(MibUploadNextResponseType), bytesAvailable, opts)
			if attrErr != nil {
				return attrErr
			}
			meLength = len(attributeBuffer.Bytes())
			buf, attrErr = b.AppendBytes(2 + meLength)
			if attrErr != nil {
				return attrErr
			}
			binary.BigEndian.PutUint16(buf, uint16(meLength-6))
			copy(buf[2:], attributeBuffer.Bytes())
			length += 2 + meLength
			bytesAvailable -= 2 + meLength
		}
		msgBuffer := b.Bytes()
		binary.BigEndian.PutUint16(msgBuffer[4:], uint16(length))
	}
	return nil
}
