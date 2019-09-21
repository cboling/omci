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

const MacBridgeConfigurationDataClassId ClassID = ClassID(46)

var macbridgeconfigurationdataBME *ManagedEntityDefinition

// MacBridgeConfigurationData (class ID #46) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type MacBridgeConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	macbridgeconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "MacBridgeConfigurationData",
		ClassID: 46,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0XFF00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: MultiByteField("BridgeMacAddress", 6, nil, mapset.NewSetWith(Read), false, false, false, false, 1),
			2: Uint16Field("BridgePriority", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3: Uint64Field("DesignatedRoot", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4: Uint32Field("RootPathCost", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5: ByteField("BridgePortCount", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6: Uint16Field("RootPortNum", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7: Uint16Field("HelloTime", 0, mapset.NewSetWith(Read), false, false, true, false, 7),
			8: Uint16Field("ForwardDelay", 0, mapset.NewSetWith(Read), false, false, true, false, 8),
		},
	}
}

// NewMacBridgeConfigurationData (class ID 46 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewMacBridgeConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(macbridgeconfigurationdataBME, params...)
}
