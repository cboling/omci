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

// OmciClassID is the 16-bit ID for the OMCI
// Managed entity OMCI
const OmciClassID ClassID = ClassID(287)

var omciBME *ManagedEntityDefinition

// Omci (class ID #287)
//	This ME describes the ONU's general level of support for OMCI MEs and messages. This ME is not
//	included in an MIB upload.
//
//	Relationships
//		One instance exists in the ONU. The ME entities are related to the OMCI entity.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. There is only
//			one instance, number 0. (R) (mandatory) (2-bytes)
//
//		Me Type Table
//			ME type table: This attribute lists the ME classes supported by the ONU. Each entry contains the
//			ME class value (see Table 11.2.4-1) of an ME type. (R) (mandatory) (2 * N bytes, where N is the
//			number of entries in the list.)
//
//		Message Type Table
//			Message type table: This attribute is a list of message types (MTs) supported by the ONU. Each
//			entry contains the MT of an OMCI message (see Table-11.2.2-1). (R) (mandatory) (M bytes, where M
//			is the number of entries in the list.)
//
type Omci struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	omciBME = &ManagedEntityDefinition{
		Name:    "Omci",
		ClassID: 287,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetNext,
		),
		AllowedAttributeMask: 0xc000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: TableField("MeTypeTable", TableInfo{0, 2}, mapset.NewSetWith(Read), false, false, false, 1),
			2: TableField("MessageTypeTable", TableInfo{0, 1}, mapset.NewSetWith(Read), false, false, false, 2),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewOmci (class ID 287) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewOmci(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*omciBME, params...)
}
