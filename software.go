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

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct {
	MeBasePacket                // Note: EntityInstance for software download is two specific values
	WindowSize           byte   // Window Size -1
	ImageSize            uint32 // Octets
	NumberOfCircuitPacks byte
	CircuitPacks         []uint16 // MSB & LSB of software image instance
}

func (omci *StartSoftwareDownloadRequest) String() string {
	return fmt.Sprintf("%v, Window Size: %v, Image Size: %v, # Circuit Packs: %v",
		omci.MeBasePacket.String(), omci.WindowSize, omci.ImageSize, omci.NumberOfCircuitPacks)
}

// DecodeFromBytes decodes the given bytes of a Start Software Download Request into this layer
func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	omci.WindowSize = data[4]
	omci.ImageSize = binary.BigEndian.Uint32(data[5:9])
	omci.NumberOfCircuitPacks = data[9]
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	omci.CircuitPacks = make([]uint16, omci.NumberOfCircuitPacks)
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		omci.CircuitPacks[index] = binary.BigEndian.Uint16(data[10+(index*2):])
	}
	return nil
}

func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Start Software Download Request message
func (omci *StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(entity, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support the SStart Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	bytes, err := b.AppendBytes(6 + (2 * int(omci.NumberOfCircuitPacks)))
	if err != nil {
		return err
	}
	bytes[0] = omci.WindowSize
	binary.BigEndian.PutUint32(bytes[1:], omci.ImageSize)
	bytes[5] = omci.NumberOfCircuitPacks
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		binary.BigEndian.PutUint16(bytes[6+(index*2):], omci.CircuitPacks[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadResults struct {
	ManagedEntityID uint16 // ME ID of software image entity instance (slot number plus instance 0..1 or 2..254 vendor-specific)
	Result          me.Results
}

func (dr *DownloadResults) String() string {
	return fmt.Sprintf("ME: %v (%#x), Results: %d (%v)", dr.ManagedEntityID, dr.ManagedEntityID,
		dr.Result, dr.Result)
}

type StartSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	WindowSize        byte // Window Size -1
	NumberOfInstances byte
	MeResults         []DownloadResults
}

func (omci *StartSoftwareDownloadResponse) String() string {
	return fmt.Sprintf("%v, Results: %v, Window Size: %v, # of Instances: %v, ME Results: %v",
		omci.MeBasePacket.String(), omci.Result, omci.WindowSize, omci.NumberOfInstances, omci.MeResults)
}

// DecodeFromBytes decodes the given bytes of a Start Software Download Response into this layer
func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+3)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.WindowSize = data[5]
	omci.NumberOfInstances = data[6]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[7+(index*3):])
			omci.MeResults[index].Result = me.Results(data[9+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeStartSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Start Software Download Response message
func (omci *StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	bytes, err := b.AppendBytes(3 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.WindowSize
	bytes[2] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[3+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[5+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

// DownloadSectionRequest data is bound by the message set in use. For the
// Baseline message set use MaxDownloadSectionLength and for the Extended message
// set, MaxDownloadSectionExtendedLength is provided
type DownloadSectionRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	SectionNumber byte
	SectionData   []byte // 0 padding if final transfer requires only a partial block for baseline set
}

func (omci *DownloadSectionRequest) String() string {
	return fmt.Sprintf("%v, Section #: %v, Data Length: %v",
		omci.MeBasePacket.String(), omci.SectionNumber, len(omci.SectionData))
}

// DecodeFromBytes decodes the given bytes of a Download Section Request into this layer
func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section request")
	}
	if omci.Extended {
		if len(data) < 7 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		if len(data[7:]) > MaxDownloadSectionExtendedLength {
			return errors.New(fmt.Sprintf("software image data too large. Received %v, Max: %v",
				len(data[7:]), MaxDownloadSectionExtendedLength))
		}
		omci.SectionData = make([]byte, len(data[7:]))
		omci.SectionNumber = data[6]
		copy(omci.SectionData, data[7:])
	} else {
		if len(data[5:]) != MaxDownloadSectionLength {
			p.SetTruncated()
			return errors.New(fmt.Sprintf("software image size invalid. Received %v, Expected: %v",
				len(data[5:]), MaxDownloadSectionLength))
		}
		omci.SectionData = make([]byte, MaxDownloadSectionLength)
		omci.SectionNumber = data[4]
		copy(omci.SectionData, data[5:])
	}
	return nil
}

func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeDownloadSectionRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Request message
func (omci *DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	sectionLength := len(omci.SectionData)
	if omci.Extended {
		if sectionLength > MaxDownloadSectionExtendedLength {
			msg := fmt.Sprintf("invalid Download Section data length, must be <= %v, received: %v",
				MaxDownloadSectionExtendedLength, sectionLength)
			return me.NewProcessingError(msg)
		}
		// Append section data
		bytes, err := b.AppendBytes(3 + sectionLength)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(1+sectionLength))
		bytes[2] = omci.SectionNumber
		copy(bytes[3:], omci.SectionData)
	} else {
		if sectionLength > MaxDownloadSectionLength {
			msg := fmt.Sprintf("invalid Download Section data length, must be <= %v, received: %v",
				MaxDownloadSectionLength, sectionLength)
			return me.NewProcessingError(msg)
		}
		// Append section data
		bytes, err := b.AppendBytes(1 + MaxDownloadSectionLength)
		if err != nil {
			return err
		}
		bytes[0] = omci.SectionNumber
		copy(bytes[1:], omci.SectionData)

		// Zero extended if needed
		if sectionLength < MaxDownloadSectionLength {
			copy(omci.SectionData[sectionLength:], lotsOfZeros[:MaxDownloadSectionLength-sectionLength])
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionResponse struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	Result        me.Results
	SectionNumber byte
}

func (omci *DownloadSectionResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Section #: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.SectionNumber)
}

// DecodeFromBytes decodes the given bytes of a Download Section Response into this layer
func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	if omci.Extended {
		if len(data) < 8 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.Result = me.Results(data[6])
		omci.SectionNumber = data[7]
	} else {
		omci.Result = me.Results(data[4])
		omci.SectionNumber = data[5]
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeDownloadSectionResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Response message
func (omci *DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	if omci.Extended {
		bytes, err := b.AppendBytes(4)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(2))
		bytes[2] = byte(omci.Result)
		bytes[3] = omci.SectionNumber
	} else {
		bytes, err := b.AppendBytes(2)
		if err != nil {
			return err
		}
		bytes[0] = byte(omci.Result)
		bytes[1] = omci.SectionNumber
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	CRC32             uint32
	ImageSize         uint32
	NumberOfInstances byte
	ImageInstances    []uint16
}

func (omci *EndSoftwareDownloadRequest) String() string {
	return fmt.Sprintf("%v, CRC: %#x, Image Size: %v, Number of Instances: %v, Instances: %v",
		omci.MeBasePacket.String(), omci.CRC32, omci.ImageSize, omci.NumberOfInstances, omci.ImageInstances)
}

// DecodeFromBytes decodes the given bytes of an End Software Download Request into this layer
func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+7)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download request")
	}
	omci.CRC32 = binary.BigEndian.Uint32(data[4:8])
	omci.ImageSize = binary.BigEndian.Uint32(data[8:12])
	omci.NumberOfInstances = data[12]

	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances))
	}
	omci.ImageInstances = make([]uint16, omci.NumberOfInstances)

	for index := 0; index < int(omci.NumberOfInstances); index++ {
		omci.ImageInstances[index] = binary.BigEndian.Uint16(data[13+(index*2):])
	}
	return nil
}

func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an End Software Download Request message
func (omci *EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances))
	}
	bytes, err := b.AppendBytes(9 + (2 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(bytes[0:4], omci.CRC32)
	binary.BigEndian.PutUint32(bytes[4:8], omci.ImageSize)
	bytes[8] = omci.NumberOfInstances
	for index := 0; index < int(omci.NumberOfInstances); index++ {
		binary.BigEndian.PutUint16(bytes[9+(index*2):], omci.ImageInstances[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	NumberOfInstances byte
	MeResults         []DownloadResults
}

func (omci *EndSoftwareDownloadResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Number of Instances: %v, ME Results: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.NumberOfInstances, omci.MeResults)
}

// DecodeFromBytes decodes the given bytes of an End Software Download Response into this layer
func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.NumberOfInstances = data[5]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[6+(index*3):])
			omci.MeResults[index].Result = me.Results(data[8+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeEndSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an End Software Download Response message
func (omci *EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Download response")
	}
	bytes, err := b.AppendBytes(2 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[2+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[4+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	ActivateFlags byte
}

func (omci *ActivateSoftwareRequest) String() string {
	return fmt.Sprintf("%v, Flags: %#x",
		omci.MeBasePacket.String(), omci.ActivateFlags)
}

// DecodeFromBytes decodes the given bytes of an Activate Software Request into this layer
func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	omci.ActivateFlags = data[4]
	if omci.ActivateFlags > 2 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Activation flangs: %v, must be 0..2",
			omci.ActivateFlags))
	}
	return nil
}

func decodeActivateSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.MsgLayerType = LayerTypeActivateSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Activate Software message
func (omci *ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.ActivateFlags
	if omci.ActivateFlags > 2 {
		msg := fmt.Sprintf("invalid results for Activate Software request: %v, must be 0..2",
			omci.ActivateFlags)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *ActivateSoftwareResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// DecodeFromBytes decodes the given bytes of an Activate Softwre Response into this layer
func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeActivateSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.MsgLayerType = LayerTypeActivateSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Activate Software Response message
func (omci *ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct {
	MeBasePacket
}

func (omci *CommitSoftwareRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Commit Software Request into this layer
func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
	}
	return nil
}

func decodeCommitSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.MsgLayerType = LayerTypeCommitSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Commit Software Request message
func (omci *CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *CommitSoftwareResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Commit Softwar Response into this layer
func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Commit Software
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Commit Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeCommitSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.MsgLayerType = LayerTypeCommitSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Commit Software Response message
func (omci *CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Commit Software
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Commit Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}
