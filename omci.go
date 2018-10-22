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
	"github.com/google/gopacket/layers"
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
	layers.BaseLayer
	TransactionID    uint16
	MessageType      uint8
	DeviceIdentifier DeviceIdent
	Payload          []byte
	padding          []byte
	Length           uint16
	MIC              uint32
}

func (omci *OMCI) String() string {
	msgType := MsgType(omci.MessageType & MsgTypeMask)
	if isAutonomousNotification(msgType) {
		return fmt.Sprintf("OMCI: Type: %v:", msgType)
	} else if omci.MessageType&AK == AK {
		return fmt.Sprintf("OMCI: Type: %v Response", msgType)
	}
	return fmt.Sprintf("OMCI: Type: %v Request", msgType)
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
		//omci := &BaselineMessage{}
		omci := &OMCI{}
		return omci.DecodeFromBytes(data, p)

	case ExtendedIdent:
		//omci := &ExtendedMessage{}
		omci := &OMCI{}
		return omci.DecodeFromBytes(data, p)
	}
}

func calculateMic([]byte) uint32 {
	return 0 // TODO: Implement this if needed.
}

/////////////////////////////////////////////////////////////////////////////
//   Baseline Message encode / decode

func (omci *OMCI) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 10 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	omci.TransactionID = binary.BigEndian.Uint16(data[0:])
	omci.MessageType = data[2]
	omci.DeviceIdentifier = DeviceIdent(data[3])

	// Decode length
	var payloadOffset int
	var micOffset int
	if omci.DeviceIdentifier == BaselineIdent {
		omci.Length = MaxBaselineLength - 8
		payloadOffset = 8
		micOffset = MaxBaselineLength - 4

		if len(data) >= micOffset {
			length := binary.BigEndian.Uint32(data[micOffset-4:])
			if uint16(length) != omci.Length {
				return errors.New("invalid baseline message length")
			}
		}
	} else {
		payloadOffset = 10
		omci.Length = binary.BigEndian.Uint16(data[8:10])
		micOffset = int(omci.Length) + payloadOffset

		if int(omci.Length) > len(data)+payloadOffset-4 {
			p.SetTruncated()
			return errors.New("extended frame too small")
		}
	}
	// Extract MIC if present in the data
	if len(data) >= micOffset+4 {
		omci.MIC = binary.BigEndian.Uint32(data[micOffset:])
	}
	omci.BaseLayer = layers.BaseLayer{data[:4], data[4:]}
	p.AddLayer(omci)
	nextLayer, err := MsgTypeToNextLayer(omci.MessageType)
	if err != nil {
		return err
	}
	return p.NextDecoder(nextLayer)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (omci *OMCI) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.TransactionID)
	bytes[2] = byte(omci.MessageType)
	bytes[3] = byte(omci.DeviceIdentifier)
	return nil
}

// hacky way to zero out memory... there must be a better way?
var lotsOfZeros [MaxExtendedLength]byte // Extended OMCI messages may be up to 1980 bytes long, including headers
