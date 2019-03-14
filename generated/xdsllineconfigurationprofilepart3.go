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

const XdslLineConfigurationProfilePart3ClassId ClassID = ClassID(106)

var xdsllineconfigurationprofilepart3BME *ManagedEntityDefinition

// XdslLineConfigurationProfilePart3 (class ID #106) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type XdslLineConfigurationProfilePart3 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdsllineconfigurationprofilepart3BME = &ManagedEntityDefinition{
		Name:    "XdslLineConfigurationProfilePart3",
		ClassID: 106,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("LoopDiagnosticsModeForcedLdsf", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  ByteField("AutomodeColdStartForced", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  ByteField("L2Atpr", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  ByteField("L2Atprt", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  ByteField("ForceInpDownstream", 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
			6:  ByteField("ForceInpUpstream", 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7:  ByteField("UpdateRequestFlagForNearEndTestParameters", 0, mapset.NewSetWith(Read, Write), true, false, true, 7),
			8:  ByteField("UpdateRequestFlagForFarEndTestParameters", 0, mapset.NewSetWith(Read, Write), true, false, true, 8),
			9:  Uint16Field("InmInterArrivalTimeOffsetUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 9),
			10: ByteField("InmInterArrivalTimeStepUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 10),
			11: ByteField("InmClusterContinuationValueUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 11),
			12: ByteField("InmEquivalentInpModeUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 12),
			13: Uint16Field("InmInterArrivalTimeOffsetDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 13),
			14: ByteField("InmInterArrivalTimeStepDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 14),
			15: ByteField("InmClusterContinuationValueDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 15),
			16: ByteField("InmEquivalentInpModeDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, 16),
		},
	}
}

// NewXdslLineConfigurationProfilePart3 (class ID 106 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineConfigurationProfilePart3(params ...ParamData) (*ManagedEntity, error) {
	return NewManagedEntity(xdsllineconfigurationprofilepart3BME, params...)
}
