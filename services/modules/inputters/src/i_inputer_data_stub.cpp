/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "i_inputer_data_stub.h"

#include "ipc_object_stub.h"
#include "message_parcel.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "iremote_inputer_data.h"

#define LOG_LABEL UserIam::Common::LABEL_PIN_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace PinAuth {
void IInputerDataStub::HandlerOnSetData(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    uint64_t subType = data.ReadUint64();
    std::vector<uint8_t> param;
    data.ReadUInt8Vector(&param);
    OnSetData(subType, param);
}

int32_t IInputerDataStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("start, code = %{public}u", code);
    if (IInputerDataStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not equal");
        return UserAuth::FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(IRemoteInputerData::ON_SET_DATA):
            HandlerOnSetData(data, reply);
            return UserAuth::SUCCESS;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
