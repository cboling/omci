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
	me.IManagedEntity

	GetAttributeMask() uint16
	SetAttributeMask(uint16) error

	GetAttributes() me.AttributeValueMap // TODO: Can we use interface from generated?
	SetAttributes(me.AttributeValueMap) error
}

type ManagedEntityInstance struct {
	Entity  	  *me.ManagedEntity
	AttributeMask uint16
}

func (bme *ManagedEntityInstance) String() string {
	return fmt.Sprintf("ClassID: %v (%v), Mask: %#x, Attributes: %v",
		bme.Entity.GetClassID(), bme.Entity.GetName(),
		bme.AttributeMask, bme.Entity.Attributes)
}

func (bme *ManagedEntityInstance) GetAttributeMask() uint16 {
	return bme.AttributeMask
}
func (bme *ManagedEntityInstance) SetAttributeMask(mask uint16) error {
	if mask|bme.Entity.GetAllowedAttributeMask() != bme.Entity.GetAllowedAttributeMask() {
		return errors.New("invalid attribute mask")
	}
	bme.AttributeMask = mask
	return nil
}

func (bme *ManagedEntityInstance) GetAttributes() me.AttributeValueMap {
	return bme.Entity.Attributes
}
func (bme *ManagedEntityInstance) SetAttributes(attributes me.AttributeValueMap) error {
	// TODO: Validate attributes
	bme.Entity.Attributes = attributes
	return nil
}

// DecodeFromBytes is typically used to decode an ME in a message payload for messages
// of type MibUploadNextResponse, AVC Notifications, ...
func (bme *ManagedEntityInstance) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 6 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	classID := binary.BigEndian.Uint16(data[0:2])
	entityID := binary.BigEndian.Uint16(data[2:4])
	parameters := me.ParamData{EntityID: entityID}

	entity, err := me.LoadManagedEntityDefinition(classID, parameters)
	if err != nil {
		return err
	}
	bme.Entity = entity
	bme.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	packetAttributes, err := entity.DecodeAttributes(bme.AttributeMask, data[6:], p)
	if err != nil {
		return err
	}
	for name, value := range packetAttributes {
		bme.Entity.Attributes[name] = value
	}
	return nil
}

func (bme *ManagedEntityInstance) SerializeTo(b gopacket.SerializeBuffer) error {
	// Add class ID and entity ID
	bytes, err := b.AppendBytes(6)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, bme.Entity.GetClassID())
	binary.BigEndian.PutUint16(bytes[2:], bme.Entity.GetEntityID())
	binary.BigEndian.PutUint16(bytes[4:], bme.AttributeMask)

	// TODO: Need to limit number of bytes appended to not exceed packet size
	// Is there space/metadata info in 'b' parameter to allow this?
	err = bme.Entity.SerializeAttributes(bme.Entity.Attributes, bme.AttributeMask, b)
	return err
}
