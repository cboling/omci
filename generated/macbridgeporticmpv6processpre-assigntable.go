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

type MacBridgePortIcmpv6ProcessPreAssignTable struct {
	omci.BaseManagedEntity
}

func NewMacBridgePortIcmpv6ProcessPreAssignTable(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "MacBridgePortIcmpv6ProcessPreAssignTable",
		classID:  348,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Get,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read),
			omci.NewByteField("Icmpv6ErrorMessagesProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("Icmpv6InformationalMessagesProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("RouterSolicitationProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("RouterAdvertisementProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("NeighbourSolicitationProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("NeighbourAdvertisementProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("RedirectProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("MulticastListenerQueryProcessing", 0, omci.Read|omci.Write),
			omci.NewByteField("UnknownIcmpv6Processing", 0, omci.Read|omci.Write),
		},
	}
	entity.computeAttributeMask()
	return &MacBridgePortIcmpv6ProcessPreAssignTable{entity}, nil
}
