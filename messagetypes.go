package omci

import (
	"errors"
	"github.com/google/gopacket"
)

var msgTypeDecoderMapping map[byte]interface{}
var msgTypeEncoderMapping map[byte]interface{}

func init() {

	msgTypeDecoderMapping = make(map[byte]interface{})
	msgTypeDecoderMapping[byte(Create)|0x00] = CreateRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Create)|0x20] = CreateResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(MibReset)|0x00] = MibResetRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(MibReset)|0x20] = MibResetResponse.DecodeFromBytes

	msgTypeEncoderMapping = make(map[byte]interface{})
	msgTypeEncoderMapping[byte(Create)|0x00] = CreateRequest.SerializeTo
	msgTypeEncoderMapping[byte(Create)|0x20] = CreateResponse.SerializeTo

	msgTypeEncoderMapping[byte(MibReset)|0x00] = MibResetRequest.SerializeTo
	msgTypeEncoderMapping[byte(MibReset)|0x20] = MibResetResponse.SerializeTo
}

type Results byte

// MsgType represents a Frame message-type
type MsgType byte

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
		return "Attribute  Failure"
	}
}

type CreateRequest struct {
	// Attributes for a create are the set-by-create values for the ME in the
	// order that they are defined for the ME
	Attributes []Attribute
	padding    []byte
}

func (msg CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CreateResponse struct {
	Results                      byte
	ParameterErrorAttributesMask uint16
	padding                      []byte
}

func (msg CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CreateResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibResetRequest struct {
	padding []byte
}

func (msg MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibResetResponse struct {
	padding []byte
}

func (msg MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

func MsgTypeToStructDecoder(mt byte) (interface{}, error) {
	decoder, ok := msgTypeDecoderMapping[mt]
	if ok {
		return decoder, nil
	}
	return nil, errors.New("Unknown Message Type")

}

func MsgTypeToStructEncoder(mt byte) (interface{}, error) {
	decoder, ok := msgTypeEncoderMapping[mt]
	if ok {
		return decoder, nil
	}
	return nil, errors.New("Unknown Message Type")

}
