/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)

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

package omci

import (
	"errors"
	"fmt"
	me "github.com/cboling/omci/v2/generated"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type UnknownAttributeInfo struct {
	EntityClass    me.ClassID
	EntityInstance uint16
	AttributeMask  uint16
	AttributeData  []byte
	ErrorType      me.AttributeErrorType
}
type UnknownAttributes struct {
	// Each Attributes entry relates one or more unknown attributes to a specific managed
	// entity. For message types such as MIB Upload Next responses, there may be multiple
	// Managed Entities in a single response if the Extended Message set is being used. This
	// error condition is specified with the ErrorType of "UnknownAttribute"
	//
	// For MIB Upload Next responses, the error type "InvalidTableAttributes" indicates
	// the the response has a table attribute encoded which is in violation of G.988 but
	// has been seen with more than one ONU vendor.
	Attributes []UnknownAttributeInfo

	gopacket.Layer
	layers.BaseLayer
	MsgLayerType gopacket.LayerType
}

func (msg *UnknownAttributes) String() string {
	return fmt.Sprintf("unknown or invalid table attributes, %v Managed Entities", len(msg.Attributes))
}

// LayerType returns LayerTypeGetNextResponse
func (msg *UnknownAttributes) LayerType() gopacket.LayerType {
	return LayerTypeUnknownAttributes
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (msg *UnknownAttributes) CanDecode() gopacket.LayerClass {
	return LayerTypeUnknownAttributes
}

// LayerContents returns the bytes of the packet layer.
func (msg *UnknownAttributes) LayerContents() []byte {
	return msg.Contents
}

// LayerPayload returns the bytes contained within the packet layer
func (msg *UnknownAttributes) LayerPayload() []byte {
	return msg.Payload
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (msg *UnknownAttributes) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (msg *UnknownAttributes) DecodeFromBytes(_ []byte, _ gopacket.PacketBuilder) error {
	// This is not a real layer. It is used to pass on relaxed decode error information
	// as an ErrorLayer
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func decodeUnknownAttributes(_ []byte, _ gopacket.PacketBuilder) error {
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func (msg *UnknownAttributes) Error() error {
	return fmt.Errorf("%v managed entities with unknown or invalid table attributes detected during decode",
		len(msg.Attributes))
}

func newUnknownAttributesLayer(prevLayer gopacket.Layer, errInfo []me.IRelaxedDecodeError, p gopacket.PacketBuilder) error {
	// Add the previous layer
	p.AddLayer(prevLayer)

	// Append unknown attributes layer and also set ErrorLayer

	errLayer := &UnknownAttributes{
		Attributes:   make([]UnknownAttributeInfo, 0),
		MsgLayerType: LayerTypeUnknownAttributes,
	}
	for _, item := range errInfo {
		unknown, ok := item.(*me.UnknownAttributeDecodeError)
		if !ok {
			return fmt.Errorf("only UnknownAttributeDecodeError information can be encoded. Found %T",
				unknown)
		}
		data := UnknownAttributeInfo{
			EntityClass:    unknown.EntityClass,
			EntityInstance: unknown.EntityInstance,
			AttributeMask:  unknown.AttributeMask,
			ErrorType:      unknown.ErrorType,
		}
		if unknown.Contents != nil {
			data.AttributeData = make([]byte, len(unknown.Contents))
			copy(data.AttributeData, unknown.Contents)
		}
		errLayer.Attributes = append(errLayer.Attributes, data)
	}
	p.AddLayer(errLayer)
	p.SetErrorLayer(errLayer)

	// Return a valid error so that packet decoding stops
	return errLayer.Error()
}

func (info *UnknownAttributeInfo) Error() error {
	return fmt.Errorf("%v detected during attribute decode. Attribute Mask: 0x%04x",
		info.ErrorType, info.AttributeMask)
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

type UnknownAlarms struct {
	InvalidAlarmData []byte

	gopacket.Layer
	layers.BaseLayer
	MsgLayerType gopacket.LayerType
}

func (msg *UnknownAlarms) String() string {
	return "invalid alarm bits detected or alarm not supported"
}

// LayerType returns LayerTypeGetNextResponse
func (msg *UnknownAlarms) LayerType() gopacket.LayerType {
	return LayerTypeUnknownAlarm
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (msg *UnknownAlarms) CanDecode() gopacket.LayerClass {
	return LayerTypeUnknownAlarm
}

// LayerContents returns the bytes of the packet layer.
func (msg *UnknownAlarms) LayerContents() []byte {
	return msg.Contents
}

// LayerPayload returns the bytes contained within the packet layer
func (msg *UnknownAlarms) LayerPayload() []byte {
	return msg.Payload
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (msg *UnknownAlarms) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (msg *UnknownAlarms) DecodeFromBytes(_ []byte, _ gopacket.PacketBuilder) error {
	// This is not a real layer. It is used to pass on relaxed decode error information
	// as an ErrorLayer
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func decodeUnknownAlarms(_ []byte, _ gopacket.PacketBuilder) error {
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func (msg *UnknownAlarms) Error() error {
	return errors.New("invalid alarm bits detected or alarm not supported")
}

func newUnknownAlarmsLayer(prevLayer gopacket.Layer, errInfo me.IRelaxedDecodeError, p gopacket.PacketBuilder) error {
	// Add the previous layer
	p.AddLayer(prevLayer)

	// Add unknown alarm error layer and also set ErrorLayer
	unknown, ok := errInfo.(*me.UnknownAlarmDecodeError)
	if !ok {
		return fmt.Errorf("only UnknownAlarmsError information can be encoded. Found %T",
			unknown)
	}
	errLayer := &UnknownAlarms{
		InvalidAlarmData: unknown.Contents,
		MsgLayerType:     LayerTypeUnknownAlarm,
	}
	p.AddLayer(errLayer)
	p.SetErrorLayer(errLayer)

	// Return a valid error so that packet decoding stops
	return errLayer.Error()
}
