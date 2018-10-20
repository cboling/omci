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
			Name:    "OMCI",
			Decoder: gopacket.DecodeFunc(decodeOMCI),
		})
}

const (
	// Device Identifiers
	_                         = iota
	BaselineIdent DeviceIdent = 0x0A // All G-PON OLTs and ONUs support the baseline message set
	ExtendedIdent             = 0x0B
)

func (di DeviceIdent) String() string {
	switch di {
	default:
		return "Unknown"

	case BaselineIdent:
		return "Baseline"

	case ExtendedIdent:
		return "Extended"
	}
}

// MaxBaselineLength is the maximum number of octets allowed in an OMCI Baseline
// message.  Depending on the adapter, it may or may not include the
const MaxBaselineLength = 48

// MaxExtendedLength is the maximum number of octets allowed in an OMCI Extended
// message (including header).
const MaxExtendedLength = 1980

// OMCI defines the common protocol. Extended will be added once
// I can get basic working (and layered properly).  See ITU-T G.988 11/2017 section
// A.3 for more information
type OMCI struct {
	//layers.BaseLayer
	TransactionID    uint16
	MessageType      uint8
	DeviceIdentifier DeviceIdent
	EntityClass      uint16
	EntityInstance   uint16
}

type BaselineMessage struct {
	OMCI
	Payload []byte // Octets 8:39 (baseline)
	MIC     uint32 // Octets 44:47 (baseline)
}

type ExtendedMessage struct {
	OMCI
	Length  uint16 // Octets (8:10)
	Payload []byte // 10:++ (extended)
	MIC     uint32
}

/////////////////////////////////////////////////////////////////////////////
//   Baseline Message encode / decode

func (omci *OMCI) String() string {
	return fmt.Sprintf("OMCI %v: (%v/%v)", omci.MessageType,
		omci.EntityClass, omci.EntityInstance)
}

// LayerType returns LayerTypeOMCI
func (omci *OMCI) LayerType() gopacket.LayerType {
	return LayerTypeOMCI
}

func (omci *OMCI) LayerContents() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, omci.TransactionID)
	b[2] = omci.MessageType
	b[3] = byte(omci.DeviceIdentifier)
	binary.BigEndian.PutUint16(b[4:6], omci.EntityClass)
	binary.BigEndian.PutUint16(b[6:8], omci.EntityInstance)
	return b
}

func (omci *OMCI) CanDecode() gopacket.LayerClass {
	return LayerTypeOMCI
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *OMCI) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func decodeOMCI(data []byte, p gopacket.PacketBuilder) error {
	// Allow baseline messages without Length & MIC, but no less
	if len(data) < MaxBaselineLength-8 {
		return errors.New("frame header too small")
	}
	switch DeviceIdent(data[3]) {
	default:
		return errors.New("unsupported message type")

	case BaselineIdent:
		omci := &BaselineMessage{}
		return omci.DecodeFromBytes(data, p)

	case ExtendedIdent:
		omci := &ExtendedMessage{}
		return omci.DecodeFromBytes(data, p)
	}
}

//func calculateMic(data []byte) uint32 {
//	// TODO: Implement this if needed.
//	return 0
//}

/////////////////////////////////////////////////////////////////////////////
//   Baseline Message encode / decode

func (omci *BaselineMessage) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < MaxBaselineLength-4 {
		return errors.New("frame too small")
	}
	omci.TransactionID = binary.BigEndian.Uint16(data[0:2])
	omci.MessageType = data[2]
	omci.DeviceIdentifier = DeviceIdent(data[3])
	omci.EntityClass = binary.BigEndian.Uint16(data[4:6])
	omci.EntityInstance = binary.BigEndian.Uint16(data[6:8])

	if len(data) >= MaxBaselineLength {
		omci.MIC = binary.BigEndian.Uint32(data[MaxBaselineLength-4 : MaxBaselineLength])

		//if omci.MIC != calculateMic(data[0:40]) {
		//	return errors.New("invalid MIC")
		//}
	}
	decoder, err := MsgTypeToStructDecoder(omci.MessageType)
	if err != nil {
		return err
	}
	// Decode the message part
	err = decoder(data, p)

	return p.NextDecoder(omci.NextLayerType())
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (omci *BaselineMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.TransactionID)
	bytes[2] = byte(omci.MessageType)
	bytes[3] = byte(omci.DeviceIdentifier)
	binary.BigEndian.PutUint16(bytes[4:], omci.EntityClass)
	binary.BigEndian.PutUint16(bytes[6:], omci.EntityInstance)

	padding, err := b.AppendBytes(MaxBaselineLength - 8)
	if err != nil {
		return err
	}
	copy(padding, lotsOfZeros[:])

	//encoder, err := MsgTypeToStructEncoder(omci.MessageType)
	//if err != nil {
	//	return err
	//}
	// Serialize the message type part
	//err = encoder.SerializeTo(b, opts)
	// TODO: Implement serialization

	// TODO: Calculate MIC

	binary.BigEndian.PutUint32(bytes[MaxBaselineLength-4:], omci.MIC)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//   Extended Message encode / decode

func (omci *ExtendedMessage) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 10 {
		return errors.New("frame too small")
	}
	omci.TransactionID = binary.BigEndian.Uint16(data[0:2])
	omci.MessageType = data[2]
	omci.DeviceIdentifier = DeviceIdent(data[3])
	omci.EntityClass = binary.BigEndian.Uint16(data[4:6])
	omci.EntityInstance = binary.BigEndian.Uint16(data[6:8])
	omci.Length = binary.BigEndian.Uint16(data[8:10])

	if len(data) < int(omci.Length)+10 {
		// TODO: Set truncated?
		return errors.New("frame too small")
	}
	if len(data) >= int(omci.Length)+10+4 {
		offset := 10 + int(omci.Length)
		omci.MIC = binary.BigEndian.Uint32(data[offset : offset+4])

		//if omci.MIC != calculateMic(data[0:offset]) {
		//	return errors.New("invalid MIC")
		//}
	}
	// TODO: Add payload decode

	return p.NextDecoder(omci.NextLayerType())
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (omci *ExtendedMessage) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	bytes, err := b.PrependBytes(10)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.TransactionID)
	bytes[2] = byte(omci.MessageType)
	bytes[3] = byte(omci.DeviceIdentifier)
	binary.BigEndian.PutUint16(bytes[4:], omci.EntityClass)
	binary.BigEndian.PutUint16(bytes[6:], omci.EntityInstance)
	binary.BigEndian.PutUint16(bytes[8:], omci.Length)

	length := int(omci.Length)
	padding, err := b.AppendBytes(length + 4)
	if err != nil {
		return err
	}
	copy(padding, lotsOfZeros[:])

	// TODO: Serialize Payload

	// TODO: Calculate MIC
	binary.BigEndian.PutUint32(bytes[length:], omci.MIC)
	return nil
}

// hacky way to zero out memory... there must be a better way?
var lotsOfZeros [MaxExtendedLength]byte // Extended OMCI messages may be up to 1980 bytes long, including headers
