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
	"github.com/google/gopacket"
)

// Attribute represents a single specific Managed Entity attribute
type IAttribute interface {
	// Name is the attribute name
	Name() string
	Size() int
	Default() interface{}
	Access() AttributeAccess
	Value() (interface{}, error)
	DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
	SerializeTo(gopacket.SerializeBuffer) error
}

// Attribute represents a single specific Managed Entity attribute
type Attribute struct {
	name       string
	defValue   interface{}
	size       int
	access     AttributeAccess
	value      interface{}
	constraint func(interface{}) error
	avc        bool // If true, an AVC notification can occur for the attribute
	tca        bool // If true, a threshold crossing alert alarm notification can occur for the attribute
	counter    bool // If true, this attribute is a PM counter
	optional   bool // If true, attribute is option, else mandatory
	deprecated bool //  If true, this attribute is deprecated and only 'read' operations (if-any) performed
}

func (attr *Attribute) String() string {
	return fmt.Sprintf("%v: Size: %v, Default: %v, Access: %v",
		attr.Name(), attr.Size(), attr.Default(), attr.Access())
}
func (attr *Attribute) Name() string            { return attr.name }
func (attr *Attribute) Default() interface{}    { return attr.defValue }
func (attr *Attribute) Size() int               { return attr.size }
func (attr *Attribute) Access() AttributeAccess { return attr.access }
func (attr *Attribute) Value() (interface{}, error) {
	// TODO: Better way to detect not-initialized and no default available?
	return attr.value, nil
}

func (attr *Attribute) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Use negative numbers to indicate signed values
	size := attr.Size()
	if size < 0 {
		size = -size
	}
	if len(data) < size {
		df.SetTruncated()
		return errors.New("packet too small for field")
	}
	var err error
	switch attr.Size() {
	default:
		return errors.New("unknown attribute size")
	case 1:
		attr.value = data[0]
		if attr.constraint != nil {
			err = attr.constraint(attr.value)
		}
		return err
	case 2:
		attr.value = binary.BigEndian.Uint16(data[0:])
		if attr.constraint != nil {
			err = attr.constraint(attr.value)
		}
		return err
	case 4:
		attr.value = binary.BigEndian.Uint32(data[0:])
		if attr.constraint != nil {
			err = attr.constraint(attr.value)
		}
		return err
	case 8:
		attr.value = binary.BigEndian.Uint64(data[0:])
		if attr.constraint != nil {
			err = attr.constraint(attr.value)
		}
		return err
	}
}

func (attr *Attribute) SerializeTo(b gopacket.SerializeBuffer) error {
	// TODO: Check to see if space in buffer here !!!!
	bytes, err := b.AppendBytes(attr.Size())
	if err != nil {
		return err
	}
	switch attr.Size() {
	default:
		return errors.New("unknown attribute size")
	case 1:
		bytes[0] = attr.value.(byte)
	case 2:
		binary.BigEndian.PutUint16(bytes, attr.value.(uint16))
	case 4:
		binary.BigEndian.PutUint32(bytes, attr.value.(uint32))
	case 8:
		binary.BigEndian.PutUint64(bytes, attr.value.(uint64))
	}
	return nil
}

///////////////////////////////////////////////////////////////////////
//
type ByteField struct {
	Attribute
}

func NewByteField(name string, defVal uint16, access AttributeAccess) *ByteField {
	return &ByteField{
		Attribute: Attribute{name: name, defValue: defVal, size: 1, access: access},
	}
}

type Uint16Field struct {
	Attribute
}

func NewUint16Field(name string, defVal uint16, access AttributeAccess) *Uint16Field {
	return &Uint16Field{
		Attribute: Attribute{name: name, defValue: defVal, size: 2, access: access},
	}
}

type Uint32Field struct {
	Attribute
}

func NewSUint32Field(name string, defVal uint16, access AttributeAccess) *Uint32Field {
	return &Uint32Field{
		Attribute: Attribute{name: name, defValue: defVal, size: 4, access: access},
	}
}

type Uint64Field struct {
	Attribute
}

func NewSUint64Field(name string, defVal uint16, access AttributeAccess) *Uint64Field {
	return &Uint64Field{
		Attribute: Attribute{name: name, defValue: defVal, size: 8, access: access},
	}
}
