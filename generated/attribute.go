/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */
package generated

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	"sort"
	"strings"
)

type AttributeDefinitionMap map[uint]*AttributeDefinition

// AttributeDefinition defines a single specific Managed Entity's attributes
type AttributeDefinition struct {
	Name         string
	Index        uint
	DefValue     interface{} // Note: Not supported yet
	Size         int
	Access       AttributeAccess
	Constraint   func(interface{}) error
	Avc          bool // If true, an AVC notification can occur for the attribute
	Tca          bool // If true, a threshold crossing alert alarm notification can occur for the attribute
	Counter      bool // If true, this attribute is a PM counter
	Optional     bool // If true, attribute is option, else mandatory
	TableSupport bool // If true, attribute is a table
	Deprecated   bool // If true, this attribute is deprecated and only 'read' operations (if-any) performed
}

func (attr *AttributeDefinition) String() string {
	return fmt.Sprintf("Definition: %v (%v): Size: %v, Default: %v, Access: %v",
		attr.GetName(), attr.GetIndex(), attr.GetSize(), attr.GetDefault(), attr.GetAccess())
}
func (attr *AttributeDefinition) GetName() string            { return attr.Name }
func (attr *AttributeDefinition) GetIndex() uint             { return attr.Index }
func (attr *AttributeDefinition) GetDefault() interface{}    { return attr.DefValue }
func (attr *AttributeDefinition) GetSize() int               { return attr.Size }
func (attr *AttributeDefinition) GetAccess() AttributeAccess { return attr.Access }
func (attr *AttributeDefinition) GetConstraints() func(interface{}) error {
	return attr.Constraint
}
func (attr *AttributeDefinition) IsTableAttribute() bool {
	return attr.TableSupport
}

func (attr *AttributeDefinition) Decode(data []byte, df gopacket.DecodeFeedback) (interface{}, error) {
	// Use negative numbers to indicate signed values
	size := attr.GetSize()
	if size < 0 {
		size = -size
	}
	if len(data) < size {
		df.SetTruncated()
		return nil, errors.New("packet too small for field")
	}
	var err error
	switch attr.GetSize() {
	default:
		value := make([]byte, size)
		copy(value, data[:size])
		if attr.GetConstraints() != nil {
			err = attr.GetConstraints()(value)
			if err != nil {
				return nil, err
			}
		}
		return value, err
	case 1:
		value := data[0]
		if attr.GetConstraints() != nil {
			err = attr.GetConstraints()(value)
			if err != nil {
				return nil, err
			}
		}
		return value, err
	case 2:
		value := binary.BigEndian.Uint16(data[0:2])
		if attr.GetConstraints() != nil {
			err = attr.GetConstraints()(value)
			if err != nil {
				return nil, err
			}
		}
		return value, err
	case 4:
		value := binary.BigEndian.Uint32(data[0:4])
		if attr.GetConstraints() != nil {
			err = attr.GetConstraints()(value)
			if err != nil {
				return nil, err
			}
		}
		return value, err
	case 8:
		value := binary.BigEndian.Uint64(data[0:8])
		if attr.GetConstraints() != nil {
			err = attr.GetConstraints()(value)
			if err != nil {
				return nil, err
			}
		}
		return value, err
	}
}

func (attr *AttributeDefinition) SerializeTo(value interface{}, b gopacket.SerializeBuffer) error {
	// TODO: Check to see if space in buffer here !!!!
	bytes, err := b.AppendBytes(attr.GetSize())
	if err != nil {
		return err
	}
	switch attr.GetSize() {
	default:
		copy(bytes, value.([]byte))
	case 1:
		switch value.(type) {
		case int:
			bytes[0] = byte(value.(int))
		default:
			bytes[0] = value.(byte)
		}
	case 2:
		switch value.(type) {
		case int:
			binary.BigEndian.PutUint16(bytes, uint16(value.(int)))
		default:
			binary.BigEndian.PutUint16(bytes, value.(uint16))
		}
	case 4:
		switch value.(type) {
		case int:
			binary.BigEndian.PutUint32(bytes, uint32(value.(int)))
		default:
			binary.BigEndian.PutUint32(bytes, value.(uint32))
		}
	case 8:
		switch value.(type) {
		case int:
			binary.BigEndian.PutUint64(bytes, uint64(value.(int)))
		default:
			binary.BigEndian.PutUint64(bytes, value.(uint64))
		}
	}
	return nil
}

// GetAttributeDefinitionByName searches the attribute definition map for the
// attribute with the specified name (case insensitive)
func GetAttributeDefinitionByName(attrMap *AttributeDefinitionMap, name string) (*AttributeDefinition, error) {
	nameLower := strings.ToLower(name)
	for _, attrVal := range *attrMap {
		if nameLower == strings.ToLower(attrVal.GetName()) {
			return attrVal, nil
		}
	}
	return nil, errors.New("attribute not found")
}

// GetAttributeDefinitionMapKeys is a convenience functions since we may need to
// iterate a map in key index order. Maps in Go since v1.0 the iteration order
// of maps have been randomized.
func GetAttributeDefinitionMapKeys(attrMap AttributeDefinitionMap) []uint {
	var keys []uint
	for k := range attrMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// GetAttributeBitmap is a convenience functions to scan a list of attributes
// and return the bitmask that represents them
func GetAttributeBitmap(attrMap AttributeDefinitionMap, attributes mapset.Set) (uint16, error) {
	var mask uint16
	for k, def := range attrMap {
		if attributes.Contains(def.Name) {
			mask |= 1 << uint16(16-k)
			attributes.Remove(def.Name)
		}
	}
	if attributes.Cardinality() > 0 {
		return 0, errors.New(fmt.Sprintf("unsupported attributes: %v", attributes))
	}
	return mask, nil
}

///////////////////////////////////////////////////////////////////////
// Packet definitions for attributes of various types/sizes

func ByteField(name string, defVal uint16, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         1,
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

func Uint16Field(name string, defVal uint16, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         2,
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

func Uint32Field(name string, defVal uint16, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         4,
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

func Uint64Field(name string, defVal uint16, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         8,
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

func MultiByteField(name string, size uint, defVal []byte, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         int(size),
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

// Notes on various OMCI ME Table attribute fields.  This comment will eventually be
// removed once a good table solution is implemented.  These are not all the MEs with
// table attributes, but probably ones I care about to support initially.
//
//   ME                     Notes
//  --------------------------------------------------------------------------------------------
//	Port-mapping package -> Combined Port table -> N * 25 sized rows (port (1) + ME(2) * 12)
//  ONU Remote Debug     -> Reply table (N bytes)
//  ONU3-G               -> Status snapshot recordtable M x N bytes
//  MCAST Gem interworkTP-> IPv4 multicast adress table (12*n) (two 2 byte fields, two 4 byte fields)
//                          IPv6 multicast adress table (24*n) (various sub-fields)
//  L2 mcast gem TP      -> MCAST MAC addr filtering table (11 * n) (various sub-fields)
//  MAC Bridge Port Filt -> MAC Filter table (8 * n) (3 fields, some are bits)      *** BITS ***
//  MAC Bridge Port data -> Bridge Table (8*M) (vaius fields, some are bits)        *** BITS ***
//  VLAN tagging filter  -> Rx Vlan tag op table (16 * n) Lots of bit fields        *** BITS ***
//  MCAST operations profile
//  MCAST Subscriber config info
//  MCAST subscriber monitor
//  OMCI                -> Two tables (N bytes and 2*N bytes)
//  General pupose buffer   -> N bytes
//  Enhanced security control (17 * N bytes), (16 * P Bytes) , (16 * Q bytes), and more...
//
// An early example of info to track
//
type TableInfo struct {
	DefValue interface{}
	Size     int
}

// Now the field
func TableField(name string, tableInfo TableInfo, access AttributeAccess,
	avc bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     tableInfo.DefValue,
		Size:         tableInfo.Size, //Number of elements
		Access:       access,
		Avc:          avc,
		Counter:      false,
		TableSupport: true,
		Optional:     optional,
	}
}

func UnknownField(name string, defVal uint16, access AttributeAccess, avc bool,
	counter bool, optional bool, index uint) *AttributeDefinition {
	return &AttributeDefinition{
		Name:         name,
		Index:        index,
		DefValue:     defVal,
		Size:         99999999,
		Access:       access,
		Avc:          avc,
		Counter:      counter,
		TableSupport: false,
		Optional:     optional,
	}
}

///////////////////////////////////////////////////////////////////////
// Attribute Name to Value    (Interfaced defined in generated subdirectory)

type AttributeValueMap map[string]interface{}
