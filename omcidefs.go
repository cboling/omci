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

type IManagedEntityInstance interface {
	me.IManagedEntityDefinition

	GetAttributeMask() uint16
	SetAttributeMask(uint16) error

	GetAttributes() me.AttributeValueMap // TODO: Can we use interface from generated?
	SetAttributes(me.AttributeValueMap) error
}

type BaseManagedEntityInstance struct {
	MEDefinition  me.IManagedEntityDefinition
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (bme *BaseManagedEntityInstance) String() string {
	return fmt.Sprintf("ClassID: %v (%v), EntityID: %v, Mask: %#x, Attributes: %v",
		bme.MEDefinition.GetClassID(), bme.MEDefinition.GetName(),
		bme.MEDefinition.GetEntityID(), bme.AttributeMask, bme.Attributes)
}

func (bme *BaseManagedEntityInstance) GetAttributeMask() uint16 {
	return bme.AttributeMask
}
func (bme *BaseManagedEntityInstance) SetAttributeMask(mask uint16) error {
	if mask|bme.MEDefinition.GetAllowedAttributeMask() != bme.MEDefinition.GetAllowedAttributeMask() {
		return errors.New("invalid attribute mask")
	}
	bme.AttributeMask = mask
	return nil
}

func (bme *BaseManagedEntityInstance) GetAttributes() me.AttributeValueMap {
	return bme.Attributes
}
func (bme *BaseManagedEntityInstance) SetAttributes(attributes me.AttributeValueMap) error {
	// TODO: Validate attributes
	bme.Attributes = attributes
	return nil
}

// DecodeFromBytes is typically used to decode an ME in a message payload for messages
// of type MibUploadNextResponse, AVC Notifications, ...
func (bme *BaseManagedEntityInstance) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 6 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	classID := binary.BigEndian.Uint16(data[0:2])
	entityID := binary.BigEndian.Uint16(data[2:4])
	parameters := me.ParamData{EntityID: entityID}

	msgDef, err := me.LoadManagedEntityDefinition(classID, parameters)
	if err != nil {
		return err
	}
	bme.MEDefinition = msgDef
	bme.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	bme.Attributes, err = msgDef.DecodeAttributes(bme.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	return nil
}

func (bme *BaseManagedEntityInstance) SerializeTo(b gopacket.SerializeBuffer) error {
	// Add class ID and entity ID
	bytes, err := b.AppendBytes(6)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, bme.MEDefinition.GetClassID())
	binary.BigEndian.PutUint16(bytes[2:], bme.MEDefinition.GetEntityID())
	binary.BigEndian.PutUint16(bytes[4:], bme.AttributeMask)

	// TODO: Need to limit number of bytes appended to not exceed packet size
	// Is there space/metadata info in 'b' parameter to allow this?
	err = bme.MEDefinition.SerializeAttributes(bme.Attributes, bme.AttributeMask, b)
	if err != nil {
		return err
	}
	return nil
}
