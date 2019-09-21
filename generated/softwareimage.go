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

const SoftwareImageClassId ClassID = ClassID(7)

var softwareimageBME *ManagedEntityDefinition

// SoftwareImage (class ID #7) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type SoftwareImage struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	softwareimageBME = &ManagedEntityDefinition{
		Name:    "SoftwareImage",
		ClassID: 7,
		MessageTypes: mapset.NewSetWith(
			ActivateSoftware,
			CommitSoftware,
			DownloadSection,
			EndSoftwareDownload,
			Get,
			StartSoftwareDownload,
		),
		AllowedAttributeMask: 0XFC00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: MultiByteField("Version", 14, nil, mapset.NewSetWith(Read), true, false, false, false, 1),
			2: ByteField("IsCommitted", 0, mapset.NewSetWith(Read), true, false, false, false, 2),
			3: ByteField("IsActive", 0, mapset.NewSetWith(Read), true, false, false, false, 3),
			4: ByteField("IsValid", 0, mapset.NewSetWith(Read), true, false, false, false, 4),
			5: MultiByteField("ProductCode", 25, nil, mapset.NewSetWith(Read), true, false, true, false, 5),
			6: MultiByteField("ImageHash", 16, nil, mapset.NewSetWith(Read), true, false, true, false, 6),
		},
	}
}

// NewSoftwareImage (class ID 7 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewSoftwareImage(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(softwareimageBME, params...)
}
