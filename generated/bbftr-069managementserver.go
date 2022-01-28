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

// BbfTr069ManagementServerClassID is the 16-bit ID for the OMCI
// Managed entity BBF TR-069 management server
const BbfTr069ManagementServerClassID = ClassID(340) // 0x0154

var bbftr069managementserverBME *ManagedEntityDefinition

// BbfTr069ManagementServer (Class ID: #340 / 0x0154)
//	If functions within the ONU are managed by [BBF TR-069], this ME allows OMCI configuration of
//	the autoconfiguration server (ACS) URL and related authentication information for an ACS
//	connection initiated by the ONU. [BBF TR-069] supports other means to discover its ACS, so not
//	all BBF-TR069-compatible ONUs necessarily support this ME. Furthermore, even if the ONU does
//	support this ME, some operators may choose not to use it.
//
//	An ONU that supports OMCI configuration of ACS information automatically creates instances of
//	this ME.
//
//	Relationships
//		An instance of the BBF TR-069 management server ME exists for each instance of a BBF TR-069
//		management domain within the ONU.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of a VEIP that links to the BBF TR-069 management domain. (R)
//			(mandatory) (2-bytes)
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. When the
//			administrative state is locked, the functions of this ME are disabled. BBF TR-069 connectivity
//			to an ACS may be possible through means that do not depend on this ME. The default value of this
//			attribute is locked. (R,W) (mandatory) (1-byte)
//
//		Acs Network Address
//			This attribute points to an instance of a network address ME that contains URL and
//			authentication information associated with the ACS URL. (R, W) (mandatory) (2 bytes)
//
//		Associated Tag
//			This attribute is a TCI value for BBF TR-069 management traffic passing through the VEIP. A TCI,
//			comprising user priority, CFI and VID, is represented by 2-bytes. The value 0xFFFF specifies
//			that BBF TR-069 management traffic passes through the VEIP with neither a VLAN nor a priority
//			tag. (R, W) (mandatory) (2-bytes)
//
type BbfTr069ManagementServer struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const BbfTr069ManagementServer_AdministrativeState = "AdministrativeState"
const BbfTr069ManagementServer_AcsNetworkAddress = "AcsNetworkAddress"
const BbfTr069ManagementServer_AssociatedTag = "AssociatedTag"

func init() {
	bbftr069managementserverBME = &ManagedEntityDefinition{
		Name:    "BbfTr069ManagementServer",
		ClassID: BbfTr069ManagementServerClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xe000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField(BbfTr069ManagementServer_AdministrativeState, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: Uint16Field(BbfTr069ManagementServer_AcsNetworkAddress, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
			3: Uint16Field(BbfTr069ManagementServer_AssociatedTag, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, false, false, 3),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewBbfTr069ManagementServer (class ID 340) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewBbfTr069ManagementServer(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*bbftr069managementserverBME, params...)
}
