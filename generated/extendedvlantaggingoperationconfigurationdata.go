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

const ExtendedVlanTaggingOperationConfigurationDataClassId ClassID = ClassID(171)

var extendedvlantaggingoperationconfigurationdataBME *ManagedEntityDefinition

// ExtendedVlanTaggingOperationConfigurationData (class ID #171) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type ExtendedVlanTaggingOperationConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	extendedvlantaggingoperationconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "ExtendedVlanTaggingOperationConfigurationData",
		ClassID: 171,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
		),
		AllowedAttributeMask: 0XFF00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: ByteField("AssociationType", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: Uint16Field("ReceivedFrameVlanTaggingOperationTableMaxSize", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3: Uint16Field("InputTpid", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 3),
			4: Uint16Field("OutputTpid", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 4),
			5: ByteField("DownstreamMode", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 5),
			6: TableField("ReceivedFrameVlanTaggingOperationTable", TableInfo{nil, 16}, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7: Uint16Field("AssociatedMePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 7),
			8: MultiByteField("DscpToPBitMapping", 24, nil, mapset.NewSetWith(Read, Write), false, false, true, false, 8),
		},
	}
}

// NewExtendedVlanTaggingOperationConfigurationData (class ID 171 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewExtendedVlanTaggingOperationConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(extendedvlantaggingoperationconfigurationdataBME, params...)
}
