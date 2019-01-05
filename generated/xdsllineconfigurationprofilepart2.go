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

const XdslLineConfigurationProfilePart2ClassId uint16 = 105

// XdslLineConfigurationProfilePart2 (class ID #105) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type XdslLineConfigurationProfilePart2 struct {
	BaseManagedEntityDefinition
}

// NewXdslLineConfigurationProfilePart2 (class ID 105 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineConfigurationProfilePart2(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "XdslLineConfigurationProfilePart2",
		ClassID:  105,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
			Create,
			Delete,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read|SetByCreate),
			1: Uint16Field("DownstreamMinimumTimeIntervalForUpshiftRateAdaptation", 0, Read|Write|SetByCreate),
			2: Uint16Field("UpstreamMinimumTimeIntervalForUpshiftRateAdaptation", 0, Read|Write|SetByCreate),
			3: Uint16Field("DownstreamDownshiftNoiseMargin", 0, Read|Write|SetByCreate),
			4: Uint16Field("UpstreamDownshiftNoiseMargin", 0, Read|Write|SetByCreate),
			5: Uint16Field("DownstreamMinimumTimeIntervalForDownshiftRateAdaptation", 0, Read|Write|SetByCreate),
			6: Uint16Field("UpstreamMinimumTimeIntervalForDownshiftRateAdaptation", 0, Read|Write|SetByCreate),
			7: ByteField("XtuImpedanceStateForced", 0, Read|Write|SetByCreate),
			8: ByteField("L0Time", 0, Read|Write|SetByCreate),
			9: ByteField("L2Time", 0, Read|Write|SetByCreate),
			10: Uint16Field("DownstreamMaximumNominalPowerSpectralDensity", 0, Read|Write|SetByCreate),
			11: Uint16Field("UpstreamMaximumNominalPowerSpectralDensity", 0, Read|Write|SetByCreate),
			12: ByteField("DownstreamMaximumNominalAggregateTransmitPower", 0, Read|Write|SetByCreate),
			13: ByteField("UpstreamMaximumNominalAggregateTransmitPower", 0, Read|Write|SetByCreate),
			14: Uint16Field("UpstreamMaximumAggregateReceivePower", 0, Read),
			15: ByteField("Vdsl2TransmissionSystemEnabling", 0, Read|Write|SetByCreate),
		},
	}
	entity.computeAttributeMask()
	return &XdslLineConfigurationProfilePart2{entity}, nil
}
