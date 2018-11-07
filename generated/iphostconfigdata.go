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

type IpHostConfigData struct {
	omci.BaseManagedEntity
}

func NewIpHostConfigData(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "IpHostConfigData",
		classID:  134,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read),
			omci.NewByteField("IpOptions", 0, omci.Read|omci.Write),
			omci.NewUnknownField("MacAddress", 0, omci.Read),
			omci.NewUnknownField("OnuIdentifier", 0, omci.Read|omci.Write),
			omci.NewUint32Field("IpAddress", 0, omci.Read|omci.Write),
			omci.NewUint32Field("Mask", 0, omci.Read|omci.Write),
			omci.NewUint32Field("Gateway", 0, omci.Read|omci.Write),
			omci.NewUint32Field("PrimaryDns", 0, omci.Read|omci.Write),
			omci.NewUint32Field("SecondaryDns", 0, omci.Read|omci.Write),
			omci.NewUint32Field("CurrentAddress", 0, omci.Read),
			omci.NewUint32Field("CurrentMask", 0, omci.Read),
			omci.NewUint32Field("CurrentGateway", 0, omci.Read),
			omci.NewUint32Field("CurrentPrimaryDns", 0, omci.Read),
			omci.NewUint32Field("CurrentSecondaryDns", 0, omci.Read),
			omci.NewUnknownField("DomainName", 0, omci.Read),
			omci.NewUnknownField("HostName", 0, omci.Read),
			omci.NewUint16Field("RelayAgentOptions", 0, omci.Read|omci.Write),
		},
	}
	entity.computeAttributeMask()
	return &IpHostConfigData{entity}, nil
}
