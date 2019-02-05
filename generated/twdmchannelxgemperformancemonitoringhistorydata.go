/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
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
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */
package generated

import "github.com/deckarep/golang-set"

const TwdmChannelXgemPerformanceMonitoringHistoryDataClassId uint16 = 445

// TwdmChannelXgemPerformanceMonitoringHistoryData (class ID #445) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type TwdmChannelXgemPerformanceMonitoringHistoryData struct {
	BaseManagedEntityDefinition
}

// NewTwdmChannelXgemPerformanceMonitoringHistoryData (class ID 445 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewTwdmChannelXgemPerformanceMonitoringHistoryData(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "TwdmChannelXgemPerformanceMonitoringHistoryData",
		ClassID:  445,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetCurrentData,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, Read|SetByCreate, false, false, false, false),
			1:  ByteField("IntervalEndTime", 0, Read, false, false, false, false),
			2:  Uint16Field("ThresholdData64BItId", 0, Read|SetByCreate|Write, false, false, false, false),
			3:  Uint64Field("TotalTransmittedXgemFrames", 0, Read, false, false, false, false),
			4:  Uint64Field("TransmittedXgemFramesWithLfBitNotSet", 0, Read, false, false, false, false),
			5:  Uint64Field("TotalReceivedXgemFrames", 0, Read, false, false, false, false),
			6:  Uint64Field("ReceivedXgemFramesWithXgemHeaderHecErrors", 0, Read, false, false, false, false),
			7:  Uint64Field("FsWordsLostToXgemHeaderHecErrors", 0, Read, false, false, false, false),
			8:  Uint64Field("XgemEncryptionKeyErrors", 0, Read, false, false, false, false),
			9:  Uint64Field("TotalTransmittedBytesInNonIdleXgemFrames", 0, Read, false, false, false, false),
			10: Uint64Field("TotalReceivedBytesInNonIdleXgemFrames", 0, Read, false, false, false, false),
		},
	}
	entity.computeAttributeMask()
	return &TwdmChannelXgemPerformanceMonitoringHistoryData{entity}, nil
}
