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
//
type GetNextRequest struct {
	MeBasePacket
	AttributeMask  uint16
	SequenceNumber uint16
}

func (omci *GetNextRequest) String() string {
	return fmt.Sprintf("%v, Attribute Mask: %#x, Sequence Number: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.SequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a Get Next Request into this layer
func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	// TODO: Return error.  Have flag to optionally allow it to be encoded
	// TODO: Check that the attribute is a table attribute.  Issue warning or return error
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	omci.SequenceNumber = binary.BigEndian.Uint16(data[6:8])
	return nil
}

func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.MsgLayerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Request
func (omci *GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	binary.BigEndian.PutUint16(bytes[2:], omci.SequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextResponse struct {
	MeBasePacket
	Result        me.Results
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) String() string {
	return fmt.Sprintf("%v, Result: %v, Attribute Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.AttributeMask, omci.Attributes)
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+3)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[5:7])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[7:], p, byte(GetNextResponseType))
	if err != nil {
		return err
	}
	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	panic("All Managed Entities have an EntityID attribute")
}

func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.MsgLayerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support the Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	binary.BigEndian.PutUint16(bytes[1:3], omci.AttributeMask)

	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	// Attribute serialization
	switch omci.Result {
	default:
		break

	case me.Success:
		// TODO: Only Baseline supported at this time
		bytesAvailable := MaxBaselineLength - 11 - 8

		err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
			byte(GetNextResponseType), bytesAvailable, false)
		if err != nil {
			return err
		}
	}
	return nil
}
