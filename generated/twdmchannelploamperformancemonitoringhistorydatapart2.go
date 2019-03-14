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

const TwdmChannelPloamPerformanceMonitoringHistoryDataPart2ClassId ClassID = ClassID(447)

var twdmchannelploamperformancemonitoringhistorydatapart2BME *ManagedEntityDefinition

// TwdmChannelPloamPerformanceMonitoringHistoryDataPart2 (class ID #447) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type TwdmChannelPloamPerformanceMonitoringHistoryDataPart2 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	twdmchannelploamperformancemonitoringhistorydatapart2BME = &ManagedEntityDefinition{
		Name:    "TwdmChannelPloamPerformanceMonitoringHistoryDataPart2",
		ClassID: 447,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetCurrentData,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("SystemProfileMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("ChannelProfileMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("BurstProfileMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("AssignOnuIdMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("UnsatisfiedAdjustTxWavelengthRequests", 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("DeactivateOnuIdMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("DisableSerialNumberMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("RequestRegistrationMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field("AssignAllocIdMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field("KeyControlMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field("SleepAllowMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("TuningControlRequestMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 14),
			15: Uint32Field("TuningControlCompleteDMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 15),
			16: Uint32Field("CalibrationRequestMessageCount", 0, mapset.NewSetWith(Read), false, false, false, 16),
		},
	}
}

// NewTwdmChannelPloamPerformanceMonitoringHistoryDataPart2 (class ID 447 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewTwdmChannelPloamPerformanceMonitoringHistoryDataPart2(params ...ParamData) (*ManagedEntity, error) {
	return NewManagedEntity(twdmchannelploamperformancemonitoringhistorydatapart2BME, params...)
}
