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
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"math/bits"
)

type IManagedEntityPacket interface {
	generated.IManagedEntity

	Decode(uint16, []byte, gopacket.DecodeFeedback) error
	SerializeTo(uint16, gopacket.SerializeBuffer) error
}

type BaseManagedEntityPacket struct {
	generated.BaseManagedEntity                    // Packet info and attribute definition
	PacketAttributes            []IPacketAttribute // Attributes in packet (actual values)
}

//
//func (bme *BaseManagedEntity) GetName() string             { return bme.Name }
//func (bme *BaseManagedEntity) GetClassID() uint16          { return bme.ClassID }
//func (bme *BaseManagedEntity) GetEntityID() uint16         { return bme.EntityID }
//func (bme *BaseManagedEntity) GetMessageTypes() []MsgType  { return bme.MessageTypes }
//func (bme *BaseManagedEntity) GetAttributeMask() uint16    { return bme.AttributeMask }
//func (bme *BaseManagedEntity) GetAttributes() []IAttribute { return bme.Attributes }
//
func (bme *BaseManagedEntityPacket) String() string {
	return fmt.Sprintf("%v: CID: %v (%#x), EID: %v (%#x), Attributes: %v",
		bme.Name, bme.ClassID, bme.ClassID, bme.EntityID, bme.EntityID,
		bme.PacketAttributes)
}

func (bme *BaseManagedEntityPacket) Decode(mask uint16, data []byte, df gopacket.DecodeFeedback) error {
	// Validate attribute mask passed in
	if mask&^bme.AttributeMask > 0 {
		return errors.New("invalid attribute mask specified") // Unsupported bits set
	}
	// Loop over possible attributes
	for index := 0; index < bits.OnesCount16(bme.AttributeMask); index++ {
		// If bit is set, decode that attribute
		if mask&uint16(1<<(15-uint(index))) > 0 {
			// Pull from list
			attribute := bme.PacketAttributes[index]

			// decode & advance data slice if success
			err := attribute.DecodeFromBytes(data, df)
			if err != nil {
				return err
			}
			data = data[attribute.GetSize():]
		}
	}
	return nil
}

func (bme *BaseManagedEntityPacket) SerializeTo(mask uint16, b gopacket.SerializeBuffer) error {
	// Validate attribute mask passed in
	if mask&^bme.AttributeMask > 0 {
		return errors.New("invalid attribute mask specified") // Unsupported bits set
	}
	// Loop over possible attributes
	for index := 0; index < bits.OnesCount16(bme.AttributeMask); index++ {
		// If bit is set, decode that attribute
		if mask&uint16(1<<(15-uint(index))) > 0 {
			// Pull from list
			attribute := bme.PacketAttributes[index]

			// encode
			err := attribute.SerializeTo(b)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//
//func (bme *BaseManagedEntity) ComputeAttributeMask() {
//	for index := range bme.Attributes {
//		bme.AttributeMask |= 1 << (15 - uint(index))
//	}
//}
