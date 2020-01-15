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

// FastXtuCPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity FAST xTU-C performance monitoring history data
const FastXtuCPerformanceMonitoringHistoryDataClassID ClassID = ClassID(437)

var fastxtucperformancemonitoringhistorydataBME *ManagedEntityDefinition

// FastXtuCPerformanceMonitoringHistoryData (class ID #437)
//	This ME collects PM data on the xTU C to xTU R path as seen from the xTU-C. Instances of this ME
//	are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME is associated with an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the PPTP xDSL UNI part 1. (R, set-
//			by-create) (mandatory) (2 bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1 byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contain PM threshold values. (R, W, set-by-create) (mandatory) (2 bytes)
//
//		Successful Fra Counter
//			Successful FRA counter: This attribute counts the successful FRA primitives (success_FRA). The
//			successful FRA primitive (success_FRA) is defined in clause 11.3.1.6 of [ITU-T G.9701]. See
//			clause 7.7.22 of [ITU-T G.997.2]. (R) (mandatory) (4-bytes)
//
//		Successful Rpa Counter
//			Successful RPA counter: This attribute counts the successful RPA primitives (success_RPA). The
//			successful RPA primitive (success_RPA) is defined in clause 11.3.1.6 of [ITU-T G.9701]. See
//			clause 7.7.23 of [ITU-T G.997.2] (R) (optional) (4 bytes)
//
//		Successful Tiga Counter
//			Successful TIGA counter: This attribute counts the successful TIGA primitives (success_TIGA).
//			The successful TIGA primitive (success_TIGA) is defined in clause 11.3.1.6 of [ITU-T G.9701].
//			Reported only with the near-end measured time, invalid data flag and timestamp. See clause
//			7.7.24 of [ITUT-G.997.2] (R) (optional) (4 bytes)
//
type FastXtuCPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	fastxtucperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "FastXtuCPerformanceMonitoringHistoryData",
		ClassID: 437,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field("SuccessfulFraCounter", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint32Field("SuccessfulRpaCounter", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, true, false, 4),
			5: Uint32Field("SuccessfulTigaCounter", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, true, false, 5),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewFastXtuCPerformanceMonitoringHistoryData (class ID 437) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewFastXtuCPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*fastxtucperformancemonitoringhistorydataBME, params...)
}
