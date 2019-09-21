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

const XdslLineInventoryAndStatusDataPart2ClassId ClassID = ClassID(101)

var xdsllineinventoryandstatusdatapart2BME *ManagedEntityDefinition

// XdslLineInventoryAndStatusDataPart2 (class ID #101) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type XdslLineInventoryAndStatusDataPart2 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdsllineinventoryandstatusdatapart2BME = &ManagedEntityDefinition{
		Name:    "XdslLineInventoryAndStatusDataPart2",
		ClassID: 101,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  MultiByteField("XdslTransmissionSystem", 7, nil, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  ByteField("LinePowerManagementState", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3:  Uint16Field("DownstreamLineAttenuation", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint16Field("UpstreamLineAttenuation", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint16Field("DownstreamSignalAttenuation", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint16Field("UpstreamSignalAttenuation", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint16Field("DownstreamSnrRatioMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint16Field("UpstreamSnrMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint32Field("DownstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint32Field("UpstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
			11: Uint16Field("DownstreamActualPowerSpectrumDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 11),
			12: Uint16Field("UpstreamActualPowerSpectrumDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 12),
			13: Uint16Field("DownstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 13),
			14: Uint16Field("UpstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 14),
			15: ByteField("InitializationLastStateTransmittedDownstream", 0, mapset.NewSetWith(Read), false, false, false, false, 15),
			16: ByteField("InitializationLastStateTransmittedUpstream", 0, mapset.NewSetWith(Read), false, false, false, false, 16),
		},
	}
}

// NewXdslLineInventoryAndStatusDataPart2 (class ID 101 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineInventoryAndStatusDataPart2(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(xdsllineinventoryandstatusdatapart2BME, params...)
}
