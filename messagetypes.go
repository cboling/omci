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
	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

// NOTE: All encoder/decoders here work

// Decoder is an interface for logic to decode a packet layer.  Users may
// implement a Decoder to handle their own strange packet types, or may use one
// of the many decoders available in the 'layers' subpackage to decode things
// for them.
type Decoder interface {
	// Decode decodes the bytes of a packet, sending decoded values and other
	// information to PacketBuilder, and returning an error if unsuccessful.  See
	// the PacketBuilder documentation for more details.
	Decode(*OMCI, []byte, gopacket.PacketBuilder) error
}

// DecodeFunc wraps a function to make it a Decoder.
type DecodeFunc func(*OMCI, []byte, gopacket.PacketBuilder) error

// Encoder is an interface for logic to serialize an objct to a packet.
type Encoder interface {
	// Name is the attribute name
	SerializeTo(gopacket.SerializeBuffer, gopacket.SerializeOptions) error
}

// EncodeFunc wraps a function to make it a Encoder.
//type EncodeFunc func(gopacket.SerializeBuffer, gopacket.SerializeOptions) error
//
//var msgTypeDecoderMapping map[byte]DecodeFunc
//var msgTypeEncoderMapping map[byte]EncodeFunc
//
//var nextLayerMapping map[byte]gopacket.LayerType

var LayerTypeMibResetRequest gopacket.LayerType

func init() {
	LayerTypeMibResetRequest = gopacket.RegisterLayerType(1000+int(MibReset)|int(AR),
		gopacket.LayerTypeMetadata{
			Name:    "MibResetRequest",
			Decoder: gopacket.DecodeFunc(decodeMibResetRequest),
		})

	//nextLayerMapping = make(map[byte]gopacket.LayerType)
	//nextLayerMapping[byte(MibReset)|AR] = LayerTypeMibResetRequest
	//
	///////////////////////////////////////////////////////////////////////////
	//// Decoder mappings
	//msgTypeDecoderMapping = make(map[byte]DecodeFunc)
	//msgTypeDecoderMapping[byte(Create)|AR] = DecodeFunc(CreateRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Create)|AK] = DecodeFunc(CreateResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(Delete)|AR] = DecodeFunc(DeleteRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Delete)|AK] = DecodeFunc(DeleteResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(Set)|AR] = DecodeFunc(SetRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Set)|AK] = DecodeFunc(SetResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(Get)|AR] = DecodeFunc(GetRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Get)|AK] = DecodeFunc(GetResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(GetAllAlarms)|AR] = DecodeFunc(GetAllAlarmsRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(GetAllAlarms)|AK] = DecodeFunc(GetAllAlarmsResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(GetAllAlarmsNext)|AR] = DecodeFunc(GetAllAlarmsNextRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(GetAllAlarmsNext)|AK] = DecodeFunc(GetAllAlarmsNextResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(MibUpload)|AR] = DecodeFunc(MibUploadRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(MibUpload)|AK] = DecodeFunc(MibUploadResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(MibUploadNext)|AR] = DecodeFunc(MibUploadNextRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(MibUploadNext)|AK] = DecodeFunc(MibUploadNextResponseDecodeFromBytes)
	//
	////msgTypeDecoderMapping[byte(MibReset)|AR] = DecodeFunc(MibResetRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(MibReset)|AK] = DecodeFunc(MibResetResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(Test)|AR] = DecodeFunc(TestRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Test)|AK] = DecodeFunc(TestRequestDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(StartSoftwareDownload)|AR] = DecodeFunc(StartSoftwareDownloadRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(StartSoftwareDownload)|AK] = DecodeFunc(StartSoftwareDownloadResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(DownloadSection)|AR] = DecodeFunc(DownloadSectionRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(DownloadSection)|AK] = DecodeFunc(DownloadSectionResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(EndSoftwareDownload)|AR] = DecodeFunc(EndSoftwareDownloadRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(EndSoftwareDownload)|AK] = DecodeFunc(EndSoftwareDownloadResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(ActivateSoftware)|AR] = DecodeFunc(ActivateSoftwareRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(ActivateSoftware)|AK] = DecodeFunc(ActivateSoftwareResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(CommitSoftware)|AR] = DecodeFunc(CommitSoftwareRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(CommitSoftware)|AK] = DecodeFunc(CommitSoftwareResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(SynchronizeTime)|AR] = DecodeFunc(SynchronizeTimeRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(SynchronizeTime)|AK] = DecodeFunc(SynchronizeTimeResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(Reboot)|AR] = DecodeFunc(RebootRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(Reboot)|AK] = DecodeFunc(RebootResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(GetNext)|AR] = DecodeFunc(GetNextRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(GetNext)|AK] = DecodeFunc(GetNextResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(GetCurrentData)|AR] = DecodeFunc(GetCurrentDataRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(GetCurrentData)|AK] = DecodeFunc(GetCurrentDataResponseDecodeFromBytes)
	//
	//msgTypeDecoderMapping[byte(SetTable)|AR] = DecodeFunc(SetTableRequestDecodeFromBytes)
	//msgTypeDecoderMapping[byte(SetTable)|AK] = DecodeFunc(SetTableResponseDecodeFromBytes)
	//
	//// Autonomous notifications
	//msgTypeDecoderMapping[byte(AlarmNotification)|AK] = DecodeFunc(AlarmNotificationMsgDecodeFromBytes)
	//msgTypeDecoderMapping[byte(AttributeValueChange)|AK] = DecodeFunc(AttributeValueChangeMsgDecodeFromBytes)
	//msgTypeDecoderMapping[byte(TestResult)|AK] = DecodeFunc(TestResultMsgDecodeFromBytes)
	//
	//////////////////////////////////////////////////////////////////////////
	//// Encoder mappings
	//msgTypeEncoderMapping = make(map[byte]EncodeFunc)
	//
	//msgTypeEncoderMapping[byte(Create)|AR] = EncodeFunc(CreateRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Create)|AK] = EncodeFunc(CreateResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(Delete)|AR] = EncodeFunc(DeleteRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Delete)|AK] = EncodeFunc(DeleteResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(Set)|AR] = EncodeFunc(SetRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Set)|AK] = EncodeFunc(SetResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(Get)|AR] = EncodeFunc(GetRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Get)|AK] = EncodeFunc(GetResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(GetAllAlarms)|AR] = EncodeFunc(GetAllAlarmsRequestSerializeTo)
	//msgTypeEncoderMapping[byte(GetAllAlarms)|AK] = EncodeFunc(GetAllAlarmsResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(GetAllAlarmsNext)|AR] = EncodeFunc(GetAllAlarmsNextRequestSerializeTo)
	//msgTypeEncoderMapping[byte(GetAllAlarmsNext)|AK] = EncodeFunc(GetAllAlarmsNextResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(MibUpload)|AR] = EncodeFunc(MibUploadRequestSerializeTo)
	//msgTypeEncoderMapping[byte(MibUpload)|AK] = EncodeFunc(MibUploadResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(MibUploadNext)|AR] = EncodeFunc(MibUploadNextRequestSerializeTo)
	//msgTypeEncoderMapping[byte(MibUploadNext)|AK] = EncodeFunc(MibUploadNextResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(MibReset)|AR] = EncodeFunc(MibResetRequestSerializeTo)
	//msgTypeEncoderMapping[byte(MibReset)|AK] = EncodeFunc(MibResetResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(Test)|AR] = EncodeFunc(TestRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Test)|AK] = EncodeFunc(TestResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(StartSoftwareDownload)|AR] = EncodeFunc(StartSoftwareDownloadRequestSerializeTo)
	//msgTypeEncoderMapping[byte(StartSoftwareDownload)|AK] = EncodeFunc(StartSoftwareDownloadResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(DownloadSection)|AR] = EncodeFunc(DownloadSectionRequestSerializeTo)
	//msgTypeEncoderMapping[byte(DownloadSection)|AK] = EncodeFunc(DownloadSectionResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(EndSoftwareDownload)|AR] = EncodeFunc(EndSoftwareDownloadRequestSerializeTo)
	//msgTypeEncoderMapping[byte(EndSoftwareDownload)|AK] = EncodeFunc(EndSoftwareDownloadResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(ActivateSoftware)|AR] = EncodeFunc(ActivateSoftwareRequestSerializeTo)
	//msgTypeEncoderMapping[byte(ActivateSoftware)|AK] = EncodeFunc(ActivateSoftwareResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(CommitSoftware)|AR] = EncodeFunc(CommitSoftwareRequestSerializeTo)
	//msgTypeEncoderMapping[byte(CommitSoftware)|AK] = EncodeFunc(CommitSoftwareResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(SynchronizeTime)|AR] = EncodeFunc(SynchronizeTimeRequestSerializeTo)
	//msgTypeEncoderMapping[byte(SynchronizeTime)|AK] = EncodeFunc(SynchronizeTimeResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(Reboot)|AR] = EncodeFunc(RebootRequestSerializeTo)
	//msgTypeEncoderMapping[byte(Reboot)|AK] = EncodeFunc(RebootResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(GetNext)|AR] = EncodeFunc(GetNextRequestSerializeTo)
	//msgTypeEncoderMapping[byte(GetNext)|AK] = EncodeFunc(GetNextResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(GetCurrentData)|AR] = EncodeFunc(GetCurrentDataRequestSerializeTo)
	//msgTypeEncoderMapping[byte(GetCurrentData)|AK] = EncodeFunc(GetCurrentDataResponseSerializeTo)
	//
	//msgTypeEncoderMapping[byte(SetTable)|AR] = EncodeFunc(SetTableRequestSerializeTo)
	//msgTypeEncoderMapping[byte(SetTable)|AK] = EncodeFunc(SetTableResponseSerializeTo)
	//
	//// Autonomous notifications
	//msgTypeEncoderMapping[byte(AlarmNotification)|AK] = EncodeFunc(AlarmNotificationMsgSerializeTo)
	//msgTypeEncoderMapping[byte(AttributeValueChange)|AK] = EncodeFunc(AttributeValueChangeMsgSerializeTo)
	//msgTypeEncoderMapping[byte(TestResult)|AK] = EncodeFunc(TestResultMsgSerializeTo)
}

type Results byte

// MsgType represents a OMCI message-type
type MsgType byte

const (
	// AK (Bit 6), indicates whether this message is an AK to an action request.
	// If a message is an AK, this bit is set to 1. If the message is not a
	// response to a command, this bit is set to 0. In messages sent by the OLT,
	// this bit is always 0.
	AK byte = 0x20

	// AR (Bit 7), acknowledge request, indicates whether the message requires an
	// AK. An AK is a response to an action request, not a link layer handshake.
	// If an AK is expected, this bit is set to 1. If no AK is expected, this bit
	// is 0. In messages sent by the ONU, this bit is always 0
	AR byte = 0x40

	// MsgTypeMask provides a mask to get the base message type
	MsgTypeMask = 0x1F
)

const (
	// Message Types
	_                             = iota
	Create                MsgType = 4
	Delete                        = 6
	Set                           = 8
	Get                           = 9
	GetAllAlarms                  = 11
	GetAllAlarmsNext              = 12
	MibUpload                     = 13
	MibUploadNext                 = 14
	MibReset                      = 15
	AlarmNotification             = 16
	AttributeValueChange          = 17
	Test                          = 18
	StartSoftwareDownload         = 19
	DownloadSection               = 20
	EndSoftwareDownload           = 21
	ActivateSoftware              = 22
	CommitSoftware                = 23
	SynchronizeTime               = 24
	Reboot                        = 25
	GetNext                       = 26
	TestResult                    = 27
	GetCurrentData                = 28
	SetTable                      = 29 // Defined in Extended Message Set Only
)

func (mt MsgType) String() string {
	switch mt {
	default:
		return "Unknown"
	case Create:
		return "Create"
	case Delete:
		return "Delete"
	case Set:
		return "Set"
	case Get:
		return "Get"
	case GetAllAlarms:
		return "Get All Alarms"
	case GetAllAlarmsNext:
		return "Get All Alarms Next"
	case MibUpload:
		return "MIB Upload"
	case MibUploadNext:
		return "MIB Upload Next"
	case MibReset:
		return "MIB Reset"
	case AlarmNotification:
		return "Alarm Notification"
	case AttributeValueChange:
		return "Attribute Value Change"
	case Test:
		return "Test"
	case StartSoftwareDownload:
		return "Start Software Download"
	case DownloadSection:
		return "Download Section"
	case EndSoftwareDownload:
		return "EndSoftware Download"
	case ActivateSoftware:
		return "Activate Software"
	case CommitSoftware:
		return "Commit Software"
	case SynchronizeTime:
		return "Synchronize Time"
	case Reboot:
		return "Reboot"
	case GetNext:
		return "Get Next"
	case TestResult:
		return "Test Result"
	case GetCurrentData:
		return "Get Current Data"
	case SetTable:
		return "Set Table"
	}
}

const (
	// Response status codes
	_                        = iota
	Success          Results = 0 // command processed successfully
	ProcessingError          = 1 // command processing error
	NotSupported             = 2 // command not supported
	ParameterError           = 3 // parameter error
	UnknownEntity            = 4 // unknown managed entity
	UnknownInstance          = 5 // unknown managed entity instance
	DeviceBusy               = 6 // device busy
	InstanceExists           = 7 // instance exists
	AttributeFailure         = 9 // Attribute(s) failed or unknown
)

var allNotificationTypes = [...]MsgType{
	AlarmNotification,
	AttributeValueChange,
	TestResult,
}

func isAutonomousNotification(mt MsgType) bool {
	for _, m := range allNotificationTypes {
		if mt == m {
			return true
		}
	}
	return false
}

func (rc Results) String() string {
	switch rc {
	default:
		return "Unknown"
	case Success:
		return "Success"
	case ProcessingError:
		return "Processing Error"
	case NotSupported:
		return "Not Supported"
	case ParameterError:
		return "Parameter Error"
	case UnknownEntity:
		return "Unknown Entity"
	case UnknownInstance:
		return "Unknown Instance"
	case DeviceBusy:
		return "Device Busy"
	case InstanceExists:
		return "Instance Exists"
	case AttributeFailure:
		return "Attribute Failure"
	}
}

/////////////////////////////////////////////////////////////////////////////
//
//func MsgTypeToStructDecoder(mt byte) (DecodeFunc, error) {
//	decoder, ok := msgTypeDecoderMapping[mt]
//	if ok {
//		return decoder, nil
//	}
//	return nil, errors.New("unknown message type")
//}
//
//func MsgTypeToStructEncoder(mt byte) (interface{}, error) {
//	encoder, ok := msgTypeEncoderMapping[mt]
//	if ok {
//		return encoder, nil
//	}
//	return nil, errors.New("unknown message type")
//}
//
//func MsgTypeToNextLayer(mt byte) (gopacket.LayerType, error) {
//	nextLayer, ok := nextLayerMapping[mt]
//	if ok {
//		return nextLayer, nil
//	}
//	return gopacket.LayerTypeZero, errors.New("unknown message type")
//}

/////////////////////////////////////////////////////////////////////////////
//
type CreateRequest struct {
	// Attributes for a create are the set-by-create values for the ME in the
	// order that they are defined for the ME
	Attributes []Attribute
	padding    []byte
}

func CreateRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CreateRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CreateResponse struct {
	Results                      byte
	ParameterErrorAttributesMask uint16
	padding                      []byte
}

func CreateResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CreateResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DeleteRequest struct{ Dummy byte }

func DeleteRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func DeleteRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DeleteResponse struct{ Dummy byte }

func DeleteResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func DeleteResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetRequest struct{ Dummy byte }

func SetRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func SetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetResponse struct{ Dummy byte }

func SetResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func SetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetRequest struct{ Dummy byte }

func GetRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetResponse struct{ Dummy byte }

func GetResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsRequest struct{ Dummy byte }

func GetAllAlarmsRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsResponse struct{ Dummy byte }

func GetAllAlarmsResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsNextRequest struct{ Dummy byte }

func GetAllAlarmsNextRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsNextResponse struct{ Dummy byte }

func GetAllAlarmsNextResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadRequest struct{ Dummy byte }

func MibUploadRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadResponse struct{ Dummy byte }

func MibUploadResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct{ Dummy byte }

func MibUploadNextRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadNextResponse struct{ Dummy byte }

func MibUploadNextResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
type MibResetRequest struct {
	msgBase
}

//func (omci *MibResetRequest) LayerType() gopacket.LayerType { return LayerTypeMibResetRequest }
//func (omci *MibResetRequest) CanDecode() gopacket.LayerClass {return LayerTypeMibResetRequest }
//func (omci *MibResetRequest) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}

	// MIB Reset request Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset request")
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.layerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

//func MibResetRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
//
//	//omci.EntityClass = binary.BigEndian.Uint16(data[4:6])
//	//omci.EntityInstance = binary.BigEndian.Uint16(data[6:8])
//
//	return errors.New("TODO: Not yet implemented")
//}

func MibResetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibResetResponse struct {
	padding []byte
}

func MibResetResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func MibResetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//

type AlarmNotificationMsg struct{ Dummy byte }

func AlarmNotificationMsgDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func AlarmNotificationMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//

type AttributeValueChangeMsg struct{ Dummy byte }

func AttributeValueChangeMsgDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func AttributeValueChangeMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct{ Dummy byte }

func TestRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type TestResponse struct{ Dummy byte }

func TestResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct{ Dummy byte }

func StartSoftwareDownloadRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func StartSoftwareDownloadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type StartSoftwareDownloadResponse struct{ Dummy byte }

func StartSoftwareDownloadResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func StartSoftwareDownloadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct{ Dummy byte }

func DownloadSectionRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func DownloadSectionRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DownloadSectionResponse struct{ Dummy byte }

func DownloadSectionResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func DownloadSectionResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct{ Dummy byte }

func EndSoftwareDownloadRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func EndSoftwareDownloadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type EndSoftwareDownloadResponse struct{ Dummy byte }

func EndSoftwareDownloadResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func EndSoftwareDownloadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct{ Dummy byte }

func ActivateSoftwareRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func ActivateSoftwareRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type ActivateSoftwareResponse struct{ Dummy byte }

func ActivateSoftwareResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func ActivateSoftwareResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct{ Dummy byte }

func CommitSoftwareRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CommitSoftwareRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CommitSoftwareResponse struct{ Dummy byte }

func CommitSoftwareResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CommitSoftwareResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct{ Dummy byte }

func SynchronizeTimeRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SynchronizeTimeRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SynchronizeTimeResponse struct{ Dummy byte }

func SynchronizeTimeResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SynchronizeTimeResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct{ Dummy byte }

func RebootRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func RebootRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type RebootResponse struct{ Dummy byte }

func RebootResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func RebootResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct{ Dummy byte }

func GetNextRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetNextResponse struct{ Dummy byte }

func GetNextResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResultMsg struct{ Dummy byte }

func TestResultMsgDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestResultMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct{ Dummy byte }

func GetCurrentDataRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetCurrentDataRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetCurrentDataResponse struct{ Dummy byte }

func GetCurrentDataResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetCurrentDataResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct{ Dummy byte }

func SetTableRequestDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SetTableRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetTableResponse struct{ Dummy byte }

func SetTableResponseDecodeFromBytes(omci *OMCI, data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SetTableResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}
