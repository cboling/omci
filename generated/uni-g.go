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

// UniGClassId is the 16-bit ID for the OMCI
// Managed entity UNI-G
const UniGClassId ClassID = ClassID(264)

var unigBME *ManagedEntityDefinition

// UniG (class ID #264)
//	This ME organizes data associated with UNIs supported by GEM. One instance of the UNI-G ME
//	exists for each UNI supported by the ONU.
//
//	The ONU automatically creates or deletes instances of this ME upon the creation or deletion of a
//	real or virtual circuit pack ME, one per port.
//
//	Relationships
//		An instance of the UNI-G ME exists for each instance of a PPTP ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of a PPTP. (R) (mandatory) (2-bytes)
//
//		Deprecated
//			Deprecated:	This attribute is not used. It should be set to 0 by the OLT and ignored by the ONU.
//			(R,-W) (mandatory) (2-bytes)
//
//		Administrative State
//			NOTE - PPTP MEs also have an administrative state attribute. The user port is unlocked only if
//			both administrative state attributes are set to unlocked. It is recommended that this attribute
//			not be used: that the OLT set it to 0 and that the ONU ignore it.
//
//		Management Capability
//			(R) (optional) (1-byte)
//
//		Non_Omci Management Identifier
//			Non-OMCI management identifier: If a PPTP can be managed either directly by the OMCI or a non-
//			OMCI management environment, this attribute specifies how it is in fact to be managed. This
//			attribute is either 0 (default-=-OMCI management), or it is a pointer to a VEIP, which in turn
//			links to a non-OMCI management environment. (R,-W) (optional) (2-bytes)
//
//		Relay Agent Options
//			2/3/4:atm/123.4567
//
type UniG struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	unigBME = &ManagedEntityDefinition{
		Name:    "UniG",
		ClassID: 264,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0XF800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: Uint16Field("Deprecated", 0, mapset.NewSetWith(Read, Write), false, false, false, true, 1),
			2: ByteField("AdministrativeState", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 2),
			3: ByteField("ManagementCapability", 0, mapset.NewSetWith(Read), false, false, true, false, 3),
			4: Uint16Field("NonOmciManagementIdentifier", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 4),
			5: Uint16Field("RelayAgentOptions", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 5),
		},
	}
}

// NewUniG (class ID 264 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewUniG(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*unigBME, params...)
}
