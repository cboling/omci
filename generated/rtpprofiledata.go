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

type RtpProfileData struct {
	omci.BaseManagedEntity
}

func NewRtpProfileData(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "RtpProfileData",
		classID:  143,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
			omci.Create,
			omci.Delete,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read|omci.SetByCreate),
			omci.NewUint16Field("LocalPortMin", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewUint16Field("LocalPortMax", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewByteField("DscpMark", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewByteField("PiggybackEvents", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewByteField("ToneEvents", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewByteField("DtmfEvents", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewByteField("CasEvents", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewUint16Field("IpHostConfigPointer", 0, omci.Read|omci.Write),
		},
	}
	entity.computeAttributeMask()
	return &RtpProfileData{entity}, nil
}
