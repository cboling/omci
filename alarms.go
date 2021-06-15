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
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

type GetAllAlarmsRequest struct {
	MeBasePacket
	AlarmRetrievalMode byte
}

func (omci *GetAllAlarmsRequest) String() string {
	return fmt.Sprintf("%v, Retrieval Mode: %v",
		omci.MeBasePacket.String(), omci.AlarmRetrievalMode)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Request into this layer
func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+1)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.AlarmRetrievalMode = data[4]
	if omci.AlarmRetrievalMode > 1 {
		msg := fmt.Sprintf("invalid Alarm Retrieval Mode for Get All Alarms request: %v, must be 0..1",
			omci.AlarmRetrievalMode)
		return errors.New(msg)
	}
	return nil
}

func decodeGetAllAlarmsRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Request message
func (omci *GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.AlarmRetrievalMode
	return nil
}

type GetAllAlarmsResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *GetAllAlarmsResponse) String() string {
	return fmt.Sprintf("%v, NumberOfCommands: %d",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Response into this layer
func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Response message
func (omci *GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.NumberOfCommands)
	return nil
}

type GetAllAlarmsNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *GetAllAlarmsNextRequest) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Request into this layer
func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Request message
func (omci *GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.CommandSequenceNumber)
	return nil
}

type GetAllAlarmsNextResponse struct {
	MeBasePacket
	AlarmEntityClass    me.ClassID
	AlarmEntityInstance uint16
	AlarmBitMap         [28]byte // 224 bits
}

func (omci *GetAllAlarmsNextResponse) String() string {
	return fmt.Sprintf("%v, CID: %v, EID: (%d/%#x), Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmEntityClass, omci.AlarmEntityInstance,
		omci.AlarmEntityInstance, omci.AlarmBitMap)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Response into this layer
func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4+28)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.AlarmEntityClass = me.ClassID(binary.BigEndian.Uint16(data[4:6]))
	omci.AlarmEntityInstance = binary.BigEndian.Uint16(data[6:8])

	copy(omci.AlarmBitMap[:], data[8:36])
	return nil
}

func decodeGetAllAlarmsNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Response message
func (omci *GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	bytes, err := b.AppendBytes(2 + 2 + 28)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], uint16(omci.AlarmEntityClass))
	binary.BigEndian.PutUint16(bytes[2:], omci.AlarmEntityInstance)
	copy(bytes[4:], omci.AlarmBitMap[:])
	return nil
}

const AlarmBitmapSize = 224

type AlarmNotificationMsg struct {
	MeBasePacket
	AlarmBitmap         [AlarmBitmapSize / 8]byte
	zeroPadding         [3]byte // Note: This zero padding is not present in the Extended Message Set
	AlarmSequenceNumber byte
}

func (omci *AlarmNotificationMsg) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d, Alarm Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmSequenceNumber, omci.AlarmBitmap)
}

func (omci *AlarmNotificationMsg) IsAlarmActive(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return false, omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		msg := "managed entity does not support Alarm notifications"
		return false, errors.New(msg)
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 1, nil
}

func (omci *AlarmNotificationMsg) IsAlarmClear(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return false, omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return false, errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 0, nil
}

func (omci *AlarmNotificationMsg) ActivateAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] |= 1 << bit
	return nil
}

func (omci *AlarmNotificationMsg) ClearAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] &= ^(1 << bit)
	return nil
}

// DecodeFromBytes decodes the given bytes of an Alarm Notification into this layer
func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+28)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// Is this an unsupported or vendor specific ME.  If so, it is not an error to decode
	// the alarms.  We just cannot provide any alarm names.  Handle decode here.
	classSupport := meDefinition.GetClassSupport()
	isUnsupported := classSupport == me.UnsupportedManagedEntity ||
		classSupport == me.UnsupportedVendorSpecificManagedEntity

	mapOffset := 4
	if omci.Extended {
		mapOffset = 6
		if len(data) < 6+28+1 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
	}
	// Look for a non-nil/not empty Alarm Map to determine if this ME supports alarms
	if alarmMap := meDefinition.GetAlarmMap(); isUnsupported || (alarmMap != nil && len(alarmMap) > 0) {
		for index, octet := range data[mapOffset : (AlarmBitmapSize/8)-mapOffset] {
			omci.AlarmBitmap[index] = octet
		}
		if omci.Extended {
			omci.AlarmSequenceNumber = data[mapOffset+(AlarmBitmapSize/8)]
		} else {
			padOffset := mapOffset + (AlarmBitmapSize / 8)
			omci.zeroPadding[0] = data[padOffset]
			omci.zeroPadding[1] = data[padOffset+1]
			omci.zeroPadding[2] = data[padOffset+2]
			omci.AlarmSequenceNumber = data[padOffset+3]
		}
		return nil
	}
	return me.NewProcessingError("managed entity does not support alarm notifications")
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

func decodeAlarmNotificationExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Alarm Notification message
func (omci *AlarmNotificationMsg) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	// TODO: Support of encoding AlarmNotification into supported types not yet supported
	//meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
	//	me.ParamData{EntityID: omci.EntityInstance})
	//if omciErr.StatusCode() != me.Success {
	//	return omciErr.GetError()
	//}
	//if !me.SupportsMsgType(meDefinition, me.AlarmNotification) {
	//	return me.NewProcessingError("managed entity does not support Alarm Notification Message-Type")
	//}
	if omci.Extended {
		bytes, err := b.AppendBytes(2 + (AlarmBitmapSize / 8) + 1)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16((AlarmBitmapSize/8)+1))

		for index, octet := range omci.AlarmBitmap {
			bytes[2+index] = octet
		}
		bytes[2+(AlarmBitmapSize/8)] = omci.AlarmSequenceNumber
	} else {
		bytes, err := b.AppendBytes((AlarmBitmapSize / 8) + 3 + 1)
		if err != nil {
			return err
		}
		for index, octet := range omci.AlarmBitmap {
			bytes[index] = octet
		}
		padOffset := AlarmBitmapSize / 8
		bytes[padOffset] = 0
		bytes[padOffset+1] = 0
		bytes[padOffset+2] = 0
		bytes[padOffset+3] = omci.AlarmSequenceNumber
	}
	return nil
}
