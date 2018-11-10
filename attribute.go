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
	"fmt"
	"github.com/google/gopacket"
)

///////////////////////////////////////////////////////////////////////
// Attribute Value   (Interfaced defined in generated subdirectory)

// AttributeValue provides the value for a single specific Managed Entity attribute
type AttributeValue struct {
	Name   string
	Index  int
	Value  interface{}
}

func (attr *AttributeValue) String() string {
	val, err := attr.GetValue()
	return fmt.Sprintf("Value: %v, Index: %v, Value: %v, Error: %v",
		attr.GetName(), attr.GetIndex(), val, err)
}
func (attr *AttributeValue) GetName() string  { return attr.Name }
func (attr *AttributeValue) GetIndex() int    { return attr.Index }
func (attr *AttributeValue) GetValue() (interface{}, error) {
	// TODO: Better way to detect not-initialized and no default available?
	return attr.Value, nil
}

func (attr *AttributeValue) Decode(data []byte, def generated.IAttributeDefinition, df gopacket.DecodeFeedback) error {
	// Use negative numbers to indicate signed values
	size := def.GetSize()
	if size < 0 {
		size = -size
	}
	if len(data) < size {
		df.SetTruncated()
		return errors.New("packet too small for field")
	}
	var err error
	switch def.GetSize() {
	default:
		return errors.New("unknown attribute size")
	case 1:
		attr.Value = data[0]
		if def.GetConstraints() != nil {
			err = def.GetConstraints()(attr.Value)
		}
		return err
	case 2:
		attr.Value = binary.BigEndian.Uint16(data[0:2])
		if def.GetConstraints() != nil {
			err = def.GetConstraints()(attr.Value)
		}
		return err
	case 4:
		attr.Value = binary.BigEndian.Uint32(data[0:4])
		if def.GetConstraints() != nil {
			err = def.GetConstraints()(attr.Value)
		}
		return err
	case 8:
		attr.Value = binary.BigEndian.Uint64(data[0:8])
		if def.GetConstraints() != nil {
			err = def.GetConstraints()(attr.Value)
		}
		return err
	}
}

func (attr *AttributeValue) SerializeTo(b gopacket.SerializeBuffer, def generated.IAttributeDefinition) error {
	// TODO: Check to see if space in buffer here !!!!
	bytes, err := b.AppendBytes(def.GetSize())
	if err != nil {
		return err
	}
	switch def.GetSize() {
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
