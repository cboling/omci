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

// PhysicalPathTerminationPointLctUniClassID is the 16-bit ID for the OMCI
// Managed entity Physical path termination point LCT UNI
const PhysicalPathTerminationPointLctUniClassID = ClassID(83) // 0x0053

var physicalpathterminationpointlctuniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointLctUni (Class ID: #83 / 0x0053)
//	This ME models debug access to the ONU from any physical or logical port, for example, via a
//	dedicated LCT UNI, via ordinary subscriber UNIs, or via the IP host config ME.
//
//	The ONU automatically creates an instance of this ME per port:
//
//	o	when the ONU has an LCT port built into its factory configuration;
//
//	o	when a cardholder is provisioned to expect a circuit pack of the LCT type;
//
//	o	when a cardholder provisioned for plug-and-play is equipped with a circuit pack of the LCT
//	type;
//
//	NOTE - The installation of a plug-and-play card may indicate the presence of LCT ports via
//	equipment ID as well as its type, and indeed may cause the ONU to instantiate a port-mapping
//	package that specifies LCT ports.
//
//	o	when the ONU supports debug access through some other physical or logical means.
//
//	The ONU automatically deletes an instance of this ME when a cardholder is neither provisioned to
//	expect an LCT circuit pack, nor is it equipped with an LCT circuit pack, or if the ONU is
//	reconfigured in such a way that it no longer supports debug access.
//
//	LCT instances are not reported during an MIB upload.
//
//	Relationships
//		An instance of this ME is associated with an instance of a real or virtual circuit pack ME
//		classified as an LCT type. An instance of this ME may also be associated with the ONU as a
//		whole, if the ONU supports debug access through means other than a dedicated physical LCT port.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. This 2-byte number indicates the
//			physical position of the UNI. The first byte is the slot ID (defined in clause 9.1.5). The
//			second byte is the port ID, with the range 1..255. If the LCT UNI is associated with the ONU as
//			a whole, its ME ID should be 0. (R) (mandatory) (2 bytes)
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. Administrative
//			state is described generically in clause-A.1.6. The LCT has additional administrative state
//			behaviour. When the administrative state is set to lock, debug access through all physical or
//			logical means is blocked, except that the operation of a possible ONU remote debug ME is not
//			affected. Administrative lock of ME instance 0 overrides administrative lock of any other PPTP
//			LCT UNIs that may exist. (R, W) (mandatory) (1-byte)
//
type PhysicalPathTerminationPointLctUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const PhysicalPathTerminationPointLctUni_AdministrativeState = "AdministrativeState"

func init() {
	physicalpathterminationpointlctuniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointLctUni",
		ClassID: PhysicalPathTerminationPointLctUniClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0x8000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField(PhysicalPathTerminationPointLctUni_AdministrativeState, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewPhysicalPathTerminationPointLctUni (class ID 83) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewPhysicalPathTerminationPointLctUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointlctuniBME, params...)
}
