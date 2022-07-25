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

#ifndef PIN_AUTH_DRIVER_HDI
#define PIN_AUTH_DRIVER_HDI


#include <vector>
#include <iauth_driver_hdi.h>
#include "iremote_broker.h"
#include "iauth_executor_hdi.h"
#include "v1_0/pin_auth_interface_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace PinHdi = OHOS::HDI::PinAuth::V1_0;
class PinAuthDriverHdi : public UserIAM::UserAuth::IAuthDriverHdi, public NoCopyable {
public:
    PinAuthDriverHdi() = default;
    virtual ~PinAuthDriverHdi() = default;
    void GetExecutorList(std::vector<std::shared_ptr<UserIAM::UserAuth::IAuthExecutorHdi>> &executorList);
};
} // PinAuth
} // UserIam
} // OHOS

#endif // PIN_AUTH_DRIVER_HDI