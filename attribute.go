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
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
)

// TODO: Support encode/decode in this file
// Attribute represents a single specific Managed Entity attribute
type IPacketAttribute interface {
	generated.IAttribute

	DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
	SerializeTo(gopacket.SerializeBuffer) error
}

// Attribute represents a single specific Managed Entity attribute
type PacketAttribute struct {
	generated.Attribute
}

//func (attr *Attribute) String() string {
//	return fmt.Sprintf("%v: Size: %v, Default: %v, Access: %v",
//		attr.Name(), attr.Size(), attr.Default(), attr.Access())
//}
//func (attr *Attribute) Name() string            { return attr.name }
//func (attr *Attribute) Default() interface{}    { return attr.defValue }
//func (attr *Attribute) Size() int               { return attr.size }
//func (attr *Attribute) Access() AttributeAccess { return attr.access }
//func (attr *Attribute) Value() (interface{}, error) {
//	// TODO: Better way to detect not-initialized and no default available?
//	return attr.value, nil
//}
//
func (attr *PacketAttribute) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Use negative numbers to indicate signed values
	size := attr.GetSize()
	if size < 0 {
		size = -size
	}
	if len(data) < size {
		df.SetTruncated()
		return errors.New("packet too small for field")
	}
	var err error
	switch attr.GetSize() {
	default:
		return errors.New("unknown attribute size")
	case 1:
		attr.Value = data[0]
		if attr.Constraint != nil {
			err = attr.Constraint(attr.Value)
		}
		return err
	case 2:
		attr.Value = binary.BigEndian.Uint16(data[0:2])
		if attr.Constraint != nil {
			err = attr.Constraint(attr.Value)
		}
		return err
	case 4:
		attr.Value = binary.BigEndian.Uint32(data[0:4])
		if attr.Constraint != nil {
			err = attr.Constraint(attr.Value)
		}
		return err
	case 8:
		attr.Value = binary.BigEndian.Uint64(data[0:8])
		if attr.Constraint != nil {
			err = attr.Constraint(attr.Value)
		}
		return err
	}
}

func (attr *PacketAttribute) SerializeTo(b gopacket.SerializeBuffer) error {
	// TODO: Check to see if space in buffer here !!!!
	bytes, err := b.AppendBytes(attr.Size())
	if err != nil {
		return err
	}
	switch attr.GetSize() {
	default:
		return errors.New("unknown attribute size")
	case 1:
		bytes[0] = attr.Value.(byte)
	case 2:
		binary.BigEndian.PutUint16(bytes, attr.Value.(uint16))
	case 4:
		binary.BigEndian.PutUint32(bytes, attr.Value.(uint32))
	case 8:
		binary.BigEndian.PutUint64(bytes, attr.Value.(uint64))
	}
	return nil
}

//
/////////////////////////////////////////////////////////////////////////
////
//type ByteField struct {
//	Attribute
//}
//
//func NewByteField(name string, defVal uint16, access AttributeAccess) *ByteField {
//	return &ByteField{
//		Attribute: Attribute{name: name, defValue: defVal, size: 1, access: access},
//	}
//}
//
//type Uint16Field struct {
//	Attribute
//}
//
//func NewUint16Field(name string, defVal uint16, access AttributeAccess) *Uint16Field {
//	return &Uint16Field{
//		Attribute: Attribute{name: name, defValue: defVal, size: 2, access: access},
//	}
//}
//
//type Uint32Field struct {
//	Attribute
//}
//
//func NewUint32Field(name string, defVal uint16, access AttributeAccess) *Uint32Field {
//	return &Uint32Field{
//		Attribute: Attribute{name: name, defValue: defVal, size: 4, access: access},
//	}
//}
//
//type Uint64Field struct {
//	Attribute
//}
//
//func NewSUint64Field(name string, defVal uint16, access AttributeAccess) *Uint64Field {
//	return &Uint64Field{
//		Attribute: Attribute{name: name, defValue: defVal, size: 8, access: access},
//	}
//}
//
//// TODO: UnknownField is just a placeholder to catch unhandled Attribute sizes/structs
//type UnknownField struct {
//	Attribute
//}
//
//func NewUnknownField(name string, defVal uint16, access AttributeAccess) *UnknownField {
//	return &UnknownField{
//		Attribute: Attribute{name: name, defValue: defVal, size: 99999999, access: access},
//	}
//}
