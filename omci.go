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

type DeviceIdent byte

var (
	LayerTypeOMCI gopacket.LayerType
)

func init() {
	LayerTypeOMCI = gopacket.RegisterLayerType(1000,
		gopacket.LayerTypeMetadata{
			Name:    "Frame",
			Decoder: gopacket.DecodeFunc(decodeOMCI),
		})
}

const (
	// Device Identifiers
	_                        = iota
	OMCIBaseline DeviceIdent = 0x0A // All G-PON OLTs and ONUs support the baseline message set
	OMCIExtended             = 0x0B
)

func (di DeviceIdent) String() string {
	switch di {
	default:
		return "Unknown"
	case OMCIBaseline:
		return "Baseline"
	case OMCIExtended:
		return "Extended"
	}
}

// Frame defines the Baseline (not extended) protocol. Extended will be added once
// I can get basic working (and layered properly).  See ITU-T G.988 11/2017 section
// A.3 for more information
type Frame struct {
	//layers.BaseLayer
	TransactionID    uint16
	MessageType      MsgType
	DeviceIdentifier DeviceIdent
	EntityClass      uint16
	EntityInstance   uint16
	Length           []byte // Extended only, Octets (8:10)
	Payload          []byte // Octets 8:39 (baseline), 10:++ (extended)
	//Trailer	     []byte      // Octets 40:47
}

func (omci *Frame) String() string {
	return fmt.Sprintf("Frame %v: (%v/%v)", omci.MessageType,
		omci.EntityClass, omci.EntityInstance)
}

// LayerType returns LayerTypeOMCI
func (omci *Frame) LayerType() gopacket.LayerType {
	return LayerTypeOMCI
}

func (omci *Frame) LayerContents() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, omci.TransactionID)
	b[2] = byte(omci.MessageType)
	b[3] = byte(omci.DeviceIdentifier)
	binary.BigEndian.PutUint16(b[4:6], omci.EntityClass)
	binary.BigEndian.PutUint16(b[6:8], omci.EntityInstance)
	return b
}

func (omci *Frame) LayerPayload() []byte {
	return omci.Payload
}

func (omci *Frame) CanDecode() gopacket.LayerClass {
	return LayerTypeOMCI
}

//func (omci *Frame) LayerContents() []byte { return omci.TransactionID }

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *Frame) NextLayerType() gopacket.LayerType {
	switch omci.DeviceIdentifier {
	case OMCIBaseline:
		return LayerTypeOMCIBaselineMessage

	case OMCIExtended:
		return LayerTypeOMCIExtendedMessage
	}
	return gopacket.LayerTypeZero
}

func decodeOMCI(data []byte, p gopacket.PacketBuilder) error {
	omci := &Frame{}
	return omci.DecodeFromBytes(data, p)
}

func (omci *Frame) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 8 {
		return errors.New("frame header too small")
	}
	omci.TransactionID = binary.BigEndian.Uint16(data[0:2])
	omci.MessageType = MsgType(data[2])
	omci.DeviceIdentifier = DeviceIdent(data[3])
	omci.EntityClass = binary.BigEndian.Uint16(data[4:6])
	omci.EntityInstance = binary.BigEndian.Uint16(data[6:8])

	p.AddLayer(&Frame{binary.BigEndian.Uint16(data[0:2]),
		MsgType(data[2]), DeviceIdent(data[3]),
		binary.BigEndian.Uint16(data[4:6]),
		binary.BigEndian.Uint16(data[6:8]),
		data[8:]})
	//return p.NextDecoder(LayerTypeOMCIPayload)
	return p.NextDecoder(omci.NextLayerType())
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (omci *Frame) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) Frame Header is 8 octets, 10
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.TransactionID)
	bytes[2] = byte(omci.MessageType)
	bytes[3] = byte(omci.DeviceIdentifier)
	binary.BigEndian.PutUint16(bytes[4:], omci.EntityClass)
	binary.BigEndian.PutUint16(bytes[6:], omci.EntityInstance)

	length := 48 // TODO: Only Baseline Messages currently supported
	padding, err := b.AppendBytes(length - 8)
	if err != nil {
		return err
	}
	copy(padding, lotsOfZeros[:])
	return nil
}

// hacky way to zero out memory... there must be a better way?
var lotsOfZeros [48]byte
