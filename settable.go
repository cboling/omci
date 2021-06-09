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
	"errors"
	"fmt"
	"github.com/google/gopacket"
)

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Set Table Request into this layer
func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+2)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.MsgLayerType = LayerTypeSetTableRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Request
func (omci *SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") /// TODO: Fix me when extended messages supported)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableResponse struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Set Table Response into this layer
func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+1)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.MsgLayerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Response
func (omci *SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}
