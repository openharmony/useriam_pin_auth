/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "pin_auth_collector_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_icollector_executor_fuzzer.h"
#include "mock_iexecutor_callback_fuzzer.h"

#include "pin_auth_collector_hdi.h"
#include "pin_auth_hdi.h"

#define LOG_TAG "PIN_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {

const uint64_t SCHEDULE_ID = 123;
auto executorProxy_ = sptr<ICollector>(new (std::nothrow) MockICollectorExecutorFuzzer);
std::shared_ptr<PinAuthCollectorHdi> hdi_(nullptr);
std::shared_ptr<UserAuth::IExecuteCallback> iExecutorCallback_ = Common::MakeShared<MockIExecutorCallbackFuzzer>();

void InitPinAuthCollectorHdi(Parcel &parcel)
{
    hdi_ = Common::MakeShared<PinAuthCollectorHdi>(parcel.ReadBool() ? nullptr : executorProxy_);
}

void FuzzGetExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserAuth::ExecutorInfo info;
    if (hdi_ != nullptr) {
        hdi_->GetExecutorInfo(info);
    }
    IAM_LOGI("end");
}

void FuzzOnRegisterFinish(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;
    FillFuzzUint64Vector(parcel, templateIdList);
    FillFuzzUint8Vector(parcel, frameworkPublicKey);
    FillFuzzUint8Vector(parcel, extraInfo);
    if (hdi_ != nullptr) {
        hdi_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzSendMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t srcRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    if (hdi_ != nullptr) {
        hdi_->SendMessage(SCHEDULE_ID, srcRole, msg);
    }
    IAM_LOGI("end");
}

void FuzzCollect(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    UserAuth::CollectParam parm = {
        .tokenId = parcel.ReadUint32(),
        .collectorTokenId = parcel.ReadUint32(),
        .extraInfo = extraInfo,
    };
    if (hdi_ != nullptr) {
        hdi_->Collect(SCHEDULE_ID, parm, iExecutorCallback_);
    }
    IAM_LOGI("end");
}

void FuzzOnSetData(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t authSubType = parcel.ReadUint32();
    std::vector<uint8_t> data;
    int32_t errorCode = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, data);
    if (hdi_ != nullptr) {
        hdi_->OnSetData(SCHEDULE_ID, authSubType, data, errorCode);
    }
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    if (hdi_ != nullptr) {
        hdi_->Cancel(SCHEDULE_ID);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorInfo);
FuzzFunc *g_fuzzFuncs[] = {FuzzGetExecutorInfo, FuzzOnRegisterFinish, FuzzSendMessage, FuzzCollect,
    FuzzOnSetData, FuzzCancel};

void PinAuthCollectorHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    InitPinAuthCollectorHdi(parcel);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::PinAuth::PinAuthCollectorHdiFuzzTest(data, size);
    return 0;
}
