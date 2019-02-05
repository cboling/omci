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

const XdslLineConfigurationProfilePart3ClassId uint16 = 106

// XdslLineConfigurationProfilePart3 (class ID #106) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type XdslLineConfigurationProfilePart3 struct {
	BaseManagedEntityDefinition
}

// NewXdslLineConfigurationProfilePart3 (class ID 106 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineConfigurationProfilePart3(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "XdslLineConfigurationProfilePart3",
		ClassID:  106,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, Read|SetByCreate, false, false, false, false),
			1:  ByteField("LoopDiagnosticsModeForcedLdsf", 0, Read|SetByCreate|Write, false, false, false, false),
			2:  ByteField("AutomodeColdStartForced", 0, Read|SetByCreate|Write, false, false, false, false),
			3:  ByteField("L2Atpr", 0, Read|SetByCreate|Write, false, false, false, false),
			4:  ByteField("L2Atprt", 0, Read|SetByCreate|Write, false, false, false, false),
			5:  ByteField("ForceInpDownstream", 0, Read|Write, false, false, false, false),
			6:  ByteField("ForceInpUpstream", 0, Read|Write, false, false, false, false),
			7:  ByteField("UpdateRequestFlagForNearEndTestParameters", 0, Read|Write, true, false, false, true),
			8:  ByteField("UpdateRequestFlagForFarEndTestParameters", 0, Read|Write, true, false, false, true),
			9:  Uint16Field("InmInterArrivalTimeOffsetUpstream", 0, Read|Write, false, false, false, true),
			10: ByteField("InmInterArrivalTimeStepUpstream", 0, Read|Write, false, false, false, true),
			11: ByteField("InmClusterContinuationValueUpstream", 0, Read|Write, false, false, false, true),
			12: ByteField("InmEquivalentInpModeUpstream", 0, Read|Write, false, false, false, true),
			13: Uint16Field("InmInterArrivalTimeOffsetDownstream", 0, Read|Write, false, false, false, true),
			14: ByteField("InmInterArrivalTimeStepDownstream", 0, Read|Write, false, false, false, true),
			15: ByteField("InmClusterContinuationValueDownstream", 0, Read|Write, false, false, false, true),
			16: ByteField("InmEquivalentInpModeDownstream", 0, Read|Write, false, false, false, true),
		},
	}
	entity.computeAttributeMask()
	return &XdslLineConfigurationProfilePart3{entity}, nil
}
