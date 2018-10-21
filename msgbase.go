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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

type msgBase struct {
	layerType gopacket.LayerType
	layers.BaseLayer
	EntityClass    uint16
	EntityInstance uint16
}

func (msg *msgBase) String() string {
	// TODO: Lookup ClassID Name and add to output
	return fmt.Sprintf("ClassID: %v (0x%x), EntityID: %v (0x%x)",
		msg.EntityClass, msg.EntityClass, msg.EntityInstance, msg.EntityInstance)
}
func (msg *msgBase) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }
func (msg *msgBase) LayerType() gopacket.LayerType     { return msg.layerType }
func (msg *msgBase) CanDecode() gopacket.LayerClass    { return msg.layerType }
func (msg *msgBase) LayerPayload() []byte              { return nil }
