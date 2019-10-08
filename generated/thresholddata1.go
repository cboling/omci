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

// ThresholdData1ClassId is the 16-bit ID for the OMCI
// Managed entity Threshold data 1
const ThresholdData1ClassId ClassID = ClassID(273)

var thresholddata1BME *ManagedEntityDefinition

// ThresholdData1 (class ID #273)
//	Threshold data are partitioned into two MEs for historical reasons. An instance of this ME,
//	together with an optional instance of the threshold data 2 ME, contains threshold values for
//	counters in PM history data MEs.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be related to multiple instances of PM history data type MEs.////		Paired instances of threshold data 1 ME and threshold data 2 ME are implicitly linked together
//		through a common ME ID.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Threshold Value_1
//			Threshold value-1: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_2
//			Threshold value-2: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_3
//			Threshold value-3: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_4
//			Threshold value-4: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_5
//			Threshold value-5: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_6
//			Threshold value-6: (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Threshold Value_7
//			Threshold value-7: (R,-W, setbycreate) (mandatory) (4-bytes)
//
type ThresholdData1 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	thresholddata1BME = &ManagedEntityDefinition{
		Name:    "ThresholdData1",
		ClassID: 273,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFE00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: Uint32Field("ThresholdValue1", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: Uint32Field("ThresholdValue2", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: Uint32Field("ThresholdValue3", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
			4: Uint32Field("ThresholdValue4", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 4),
			5: Uint32Field("ThresholdValue5", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 5),
			6: Uint32Field("ThresholdValue6", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 6),
			7: Uint32Field("ThresholdValue7", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 7),
		},
	}
}

// NewThresholdData1 (class ID 273 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewThresholdData1(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*thresholddata1BME, params...)
}
