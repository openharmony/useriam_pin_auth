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

#ifndef INPUTER_SET_DATA_PROXY_H
#define INPUTER_SET_DATA_PROXY_H

#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"

#include "inputer_set_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class InputerSetDataProxy : public IRemoteProxy<InputerSetData>, public NoCopyable {
public:
    explicit InputerSetDataProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<InputerSetData>(impl)
    {
    }
    ~InputerSetDataProxy() override = default;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data, uint32_t pinLength, int32_t errorCode) override;

private:
    static inline BrokerDelegator<InputerSetDataProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // INPUTER_SET_DATA_PROXY_H