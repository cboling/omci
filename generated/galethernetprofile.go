/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
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

// GalEthernetProfileClassID is the 16-bit ID for the OMCI
// Managed entity GAL Ethernet profile
const GalEthernetProfileClassID = ClassID(272) // 0x0110

var galethernetprofileBME *ManagedEntityDefinition

// GalEthernetProfile (Class ID: #272 / 0x0110)
//	This ME organizes data that describe the gigabit-capable passive optical network transmission
//	convergence layer (GTC) adaptation layer processing functions of the ONU for Ethernet services.
//	It is used with the GEM IW TP ME.
//
//	Instances of this ME are created and deleted on request of the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the GEM IW TP ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Maximum Gem Payload Size
//			This attribute defines the maximum payload size generated in the associated GEM IW TP ME. (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
type GalEthernetProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const GalEthernetProfile_MaximumGemPayloadSize = "MaximumGemPayloadSize"

func init() {
	galethernetprofileBME = &ManagedEntityDefinition{
		Name:    "GalEthernetProfile",
		ClassID: GalEthernetProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0x8000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: Uint16Field(GalEthernetProfile_MaximumGemPayloadSize, UnsignedIntegerAttributeType, 0x8000, 48, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewGalEthernetProfile (class ID 272) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewGalEthernetProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*galethernetprofileBME, params...)
}
