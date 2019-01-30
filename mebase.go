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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MeBasePacket struct {
	EntityClass    uint16
	EntityInstance uint16 // TODO: Change attribute values to map and move this into the map

	gopacket.Layer
	layers.BaseLayer
	MsgLayerType gopacket.LayerType
}

func (msg *MeBasePacket) String() string {
	return fmt.Sprintf("ClassID: %d, InstanceId: %d/(%#x), LayerType: %d (%d)",
		msg.EntityClass, msg.EntityInstance, msg.EntityInstance, msg.LayerType(),
		msg.MsgLayerType)
}

func (msg *MeBasePacket) CanDecode() gopacket.LayerClass {
	return msg.MsgLayerType
}

// Layer Interface implementations
func (msg *MeBasePacket) LayerType() gopacket.LayerType {
	return msg.MsgLayerType
}
func (msg *MeBasePacket) LayerContents() []byte {
	return msg.Contents
}
func (msg *MeBasePacket) LayerPayload() []byte {
	return msg.Payload
}

// layerDecodingLayer Interface implementations
func (msg *MeBasePacket) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}
func (msg *MeBasePacket) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Note: Base OMCI frame already checked for frame with at least 10 octets
	msg.EntityClass = binary.BigEndian.Uint16(data[0:])
	msg.EntityInstance = binary.BigEndian.Uint16(data[2:])
	msg.BaseLayer = layers.BaseLayer{Contents: data[:4], Payload: data[4:]}
	return nil
}
func (msg *MeBasePacket) SerializeTo(b gopacket.SerializeBuffer) error {
	// Add class ID and entity ID
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, msg.EntityClass)
	binary.BigEndian.PutUint16(bytes[2:], msg.EntityInstance)
	return nil
}

type layerDecodingLayer interface {
	gopacket.Layer
	DecodeFromBytes([]byte, gopacket.PacketBuilder) error
	NextLayerType() gopacket.LayerType
}

func decodingLayerDecoder(d layerDecodingLayer, data []byte, p gopacket.PacketBuilder) error {
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	next := d.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
