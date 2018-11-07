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
 *              https://github.com/cboling/OMCI-parser
 */
package generated

import (
	"../../omci"
)

type PhysicalPathTerminationPointXdslUniPart2 struct {
	omci.BaseManagedEntity
}

func NewPhysicalPathTerminationPointXdslUniPart2(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "PhysicalPathTerminationPointXdslUniPart2",
		classID:  99,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel0Downstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel1Downstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel2Downstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel3Downstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel0Upstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel1Upstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel2Upstream", 0, omci.Read|omci.Write),
			omci.NewUint16Field("XdslChannelConfigurationProfileForBearerChannel3Upstream", 0, omci.Read|omci.Write),
		},
	}
	entity.computeAttributeMask()
	return &PhysicalPathTerminationPointXdslUniPart2{entity}, nil
}
