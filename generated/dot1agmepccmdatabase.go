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

const Dot1AgMepCcmDatabaseClassId ClassID = ClassID(304)

var dot1agmepccmdatabaseBME *ManagedEntityDefinition

// Dot1AgMepCcmDatabase (class ID #304) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type Dot1AgMepCcmDatabase struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	dot1agmepccmdatabaseBME = &ManagedEntityDefinition{
		Name:    "Dot1AgMepCcmDatabase",
		ClassID: 304,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetNext,
		),
		AllowedAttributeMask: 0XFFF0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  TableField("Rmep1DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, false, false, 1),
			2:  TableField("Rmep2DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 2),
			3:  TableField("Rmep3DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 3),
			4:  TableField("Rmep4DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 4),
			5:  TableField("Rmep5DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 5),
			6:  TableField("Rmep6DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 6),
			7:  TableField("Rmep7DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 7),
			8:  TableField("Rmep8DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 8),
			9:  TableField("Rmep9DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 9),
			10: TableField("Rmep10DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 10),
			11: TableField("Rmep11DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 11),
			12: TableField("Rmep12DatabaseTable", TableInfo{nil, 0}, mapset.NewSetWith(Read), false, true, false, 12),
		},
	}
}

// NewDot1AgMepCcmDatabase (class ID 304 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewDot1AgMepCcmDatabase(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(dot1agmepccmdatabaseBME, params...)
}
