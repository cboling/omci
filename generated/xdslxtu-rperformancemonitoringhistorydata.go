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

const XdslXtuRPerformanceMonitoringHistoryDataClassId ClassID = ClassID(113)

var xdslxturperformancemonitoringhistorydataBME *ManagedEntityDefinition

// XdslXtuRPerformanceMonitoringHistoryData (class ID #113) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type XdslXtuRPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdslxturperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "XdslXtuRPerformanceMonitoringHistoryData",
		ClassID: 113,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFF0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  Uint16Field("LossOfFrameSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint16Field("LossOfSignalSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint16Field("LossOfPowerSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint16Field("ErroredSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint16Field("SeverelyErroredSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint16Field("FecSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint16Field("UnavailableSeconds", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint16Field("LeftrDefectSeconds", 0, mapset.NewSetWith(Read), false, false, true, false, 10),
			11: Uint32Field("ErrorFreeBitsCounter", 0, mapset.NewSetWith(Read), false, false, true, false, 11),
			12: Uint32Field("MinimumErrorFreeThroughputMineftr", 0, mapset.NewSetWith(Read), false, false, true, false, 12),
		},
	}
}

// NewXdslXtuRPerformanceMonitoringHistoryData (class ID 113 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslXtuRPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(xdslxturperformancemonitoringhistorydataBME, params...)
}
