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

const VoipFeatureAccessCodesClassId uint16 = 147

// VoipFeatureAccessCodes (class ID #147) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type VoipFeatureAccessCodes struct {
	BaseManagedEntityDefinition
}

// NewVoipFeatureAccessCodes (class ID 147 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewVoipFeatureAccessCodes(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "VoipFeatureAccessCodes",
		ClassID:  147,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, Read, false, false, false, false),
			1:  MultiByteField("CancelCallWaiting", 5, nil, Read|Write, false, false, false, true),
			2:  MultiByteField("CallHold", 5, nil, Read|Write, false, false, false, true),
			3:  MultiByteField("CallPark", 5, nil, Read|Write, false, false, false, true),
			4:  MultiByteField("CallerIdActivate", 5, nil, Read|Write, false, false, false, true),
			5:  MultiByteField("CallerIdDeactivate", 5, nil, Read|Write, false, false, false, true),
			6:  MultiByteField("DoNotDisturbActivation", 5, nil, Read|Write, false, false, false, true),
			7:  MultiByteField("DoNotDisturbDeactivation", 5, nil, Read|Write, false, false, false, true),
			8:  MultiByteField("DoNotDisturbPinChange", 5, nil, Read|Write, false, false, false, true),
			9:  MultiByteField("EmergencyServiceNumber", 5, nil, Read|Write, false, false, false, true),
			10: MultiByteField("IntercomService", 5, nil, Read|Write, false, false, false, true),
			11: MultiByteField("UnattendedBlindCallTransfer", 5, nil, Read|Write, false, false, false, true),
			12: MultiByteField("AttendedCallTransfer", 5, nil, Read|Write, false, false, false, true),
		},
	}
	entity.computeAttributeMask()
	return &VoipFeatureAccessCodes{entity}, nil
}
