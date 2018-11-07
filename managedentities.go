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
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"math/bits"
)

type IManagedEntity interface {
	Name() string
	ClassID() uint16
	EntityID() uint16
	MessageTypes() []MsgType
	AttributesMask() uint16
	Attributes() []IAttribute
	Decode(uint16, []byte, gopacket.DecodeFeedback) error
	SerializeTo(uint16, gopacket.SerializeBuffer) error
}

type BaseManagedEntity struct {
	name          string
	classID       uint16
	entityID      uint16
	msgTypes      []MsgType
	attributeMask uint16
	attributeList []IAttribute
}

func (bme *BaseManagedEntity) Name() string             { return bme.name }
func (bme *BaseManagedEntity) ClassID() uint16          { return bme.classID }
func (bme *BaseManagedEntity) EntityID() uint16         { return bme.entityID }
func (bme *BaseManagedEntity) MessageTypes() []MsgType  { return bme.msgTypes }
func (bme *BaseManagedEntity) AttributesMask() uint16   { return bme.attributeMask }
func (bme *BaseManagedEntity) Attributes() []IAttribute { return bme.attributeList }

func (bme *BaseManagedEntity) String() string {
	return fmt.Sprintf("%v: CID: %v (%#x), EID: %v (%#x), Attributes: %v",
		bme.Name(), bme.ClassID(), bme.ClassID(), bme.EntityID(), bme.EntityID(),
		bme.Attributes())
}

func (bme *BaseManagedEntity) Decode(mask uint16, data []byte, df gopacket.DecodeFeedback) error {
	// Validate attribute mask passed in
	if mask&^bme.attributeMask > 0 {
		return errors.New("invalid attribute mask specified") // Unsupported bits set
	}
	// Loop over possible attributes
	for index := 0; index < bits.OnesCount16(bme.attributeMask); index++ {
		// If bit is set, decode that attribute
		if mask&uint16(1<<(15-uint(index))) > 0 {
			// Pull from list
			attribute := bme.attributeList[index]

			// decode & advance data slice if success
			err := attribute.DecodeFromBytes(data, df)
			if err != nil {
				return err
			}
			data = data[attribute.Size():]
		}
	}
	return nil
}

func (bme *BaseManagedEntity) SerializeTo(mask uint16, b gopacket.SerializeBuffer) error {
	// Validate attribute mask passed in
	if mask&^bme.attributeMask > 0 {
		return errors.New("invalid attribute mask specified") // Unsupported bits set
	}
	// Loop over possible attributes
	for index := 0; index < bits.OnesCount16(bme.attributeMask); index++ {
		// If bit is set, decode that attribute
		if mask&uint16(1<<(15-uint(index))) > 0 {
			// Pull from list
			attribute := bme.attributeList[index]

			// encode
			err := attribute.SerializeTo(b)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (bme *BaseManagedEntity) computeAttributeMask() {
	for index := range bme.Attributes() {
		bme.attributeMask |= 1 << (15 - uint(index))
	}
}
