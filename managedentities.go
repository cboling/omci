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
	"github.com/google/gopacket"
	"math/bits"
)

// NOTE: This probably deserves to be in subdirectory and focused on ManangedEntity creation
//       and most packet parsing in parent directory if appropriate.

type IManagedEntity interface {
	Name() string
	Attributes() []Attribute
	Decode(uint16, []byte, gopacket.DecodeFeedback) error
}

type baseManagedEntity struct {
	name          string
	attributeMask uint16
	attributeList []Attribute
}

func (bme *baseManagedEntity) Name() string {
	return bme.name
}

func (bme *baseManagedEntity) Attributes() []Attribute {
	return bme.attributeList
}

func (bme *baseManagedEntity) Decode([]byte, gopacket.DecodeFeedback) error {
	return errors.New("decode function was not implemented in derived type")
}

func ManagedEntityDecode(classID uint16, mask uint16, data []byte, df gopacket.DecodeFeedback) (IManagedEntity, error) {
	newMe, err := LoadManagedEntityDefinition(classID)
	if err != nil {
		return nil, err
	}
	return newMe, newMe.Decode(mask, data, df)
}

func LoadManagedEntityDefinition(classID uint16) (IManagedEntity, error) {
	//var newMe IManagedEntity
	//var err error

	// TODO: Need to implement as a lookup map (code-generated)
	if classID == 0x0110 {
		return NewGalEthernetProfile(), nil
	} else {
		// TODO: Support concept of a 'blob-ME' to wrap unknown MEs. Optional?
		return nil, errors.New("unsupported Managed Entity")
	}
	//return newMe, err
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Example ME and others will eventually be 'mostly' auto-generated by the OMCI parser.
// Doing a few by hand to see what functions and properties we need

type GalEthernetProfile struct {
	baseManagedEntity
}

func NewGalEthernetProfile() *GalEthernetProfile {
	base := baseManagedEntity{
		name:          "GalEthernetProfile",
		attributeMask: 0x8000, // Do not count 'Managed entity ID'
		attributeList: make([]Attribute, 0, bits.OnesCount16(0x8000)),
	}
	return &GalEthernetProfile{baseManagedEntity: base}
}

func (gal *GalEthernetProfile) Decode(mask uint16, data []byte, df gopacket.DecodeFeedback) error {
	// TODO: Implement decode as more generalized so code-generated MEs can call

	if mask&^gal.attributeMask > 0 {
		return errors.New("invalid attribute mask") // Unsupported bits set
	}
	for index := 0; index < bits.OnesCount16(gal.attributeMask); index++ {
		if mask&uint16(1<<(15-uint(index))) > 0 {
			attribute, err := gal.AttributeDecode(index, data, df) // TODO: Do something
			if err != nil {
				return err
			}
			gal.attributeList = append(gal.attributeList, attribute)
			data = data[attribute.Size():]
		}
	}
	return errors.New("TODO: Need to implement")
}

func (gal *GalEthernetProfile) AttributeDecode(index int, data []byte, df gopacket.DecodeFeedback) (*Attribute, error) {
	// NOTE: Index 0 is first attribute after the Entity Instance (uint16) in the ME definition
	if index == 0 {
		sizeNeeded := NewMaximumGEMPayloadSize(0).Size()
		if len(data) < sizeNeeded {
			df.SetTruncated()
			return nil, errors.New("frame too small")
		}
		return NewMaximumGEMPayloadSize(binary.BigEndian.Uint16(data[0:])), nil
	}
	return nil, errors.New("TODO: Implement me")
}

// TODO: Is there a way to do something similar to python/scapy and put this inside the GAL struct?
type MaximumGEMPayloadSize struct {
	Attribute
}

func NewMaximumGEMPayloadSize(value uint16) *MaximumGEMPayloadSize {
	base := Attribute{
		name:   "MaximumGEMPayloadSize",
		access: Read | SetByCreate,
		size:   2,
		value:  value,
	}
	return &MaximumGEMPayloadSize{Attribute: base}
}
