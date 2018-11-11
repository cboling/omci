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
 *
 */
package omci

import (
	"./generated"
	"github.com/stretchr/testify/assert"
	"testing"
)
// TODO: Move test of generated items to Generated...

var allMsgTypes = [...]generated.MsgType{
	generated.Create,
	generated.Delete,
	generated.Set,
	generated.Get,
	generated.GetAllAlarms,
	generated.GetAllAlarmsNext,
	generated.MibUpload,
	generated.MibUploadNext,
	generated.MibReset,
	generated.AlarmNotification,
	generated.AttributeValueChange,
	generated.Test,
	generated.StartSoftwareDownload,
	generated.DownloadSection,
	generated.EndSoftwareDownload,
	generated.ActivateSoftware,
	generated.CommitSoftware,
	generated.SynchronizeTime,
	generated.Reboot,
	generated.GetNext,
	generated.TestResult,
	generated.GetCurrentData,
	generated.SetTable}

var allResults = [...]generated.Results{
	generated.Success,
	generated.ProcessingError,
	generated.NotSupported,
	generated.ParameterError,
	generated.UnknownEntity,
	generated.UnknownInstance,
	generated.DeviceBusy,
	generated.InstanceExists}

// MibResetRequestTest tests decode/encode of a MIB Reset Request
func TestMsgTypeStrings(t *testing.T) {
	for _, msg := range allMsgTypes {
		strMsg := msg.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

func TestResultsStrings(t *testing.T) {
	for _, code := range allResults {
		strMsg := code.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}
