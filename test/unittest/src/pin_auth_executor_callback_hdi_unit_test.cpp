/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_manager.h"
#include "iam_common_defines.h"
#include "mock_iall_in_one_executor.h"
#include "mock_icollector_executor.h"
#include "mock_iexecute_callback.h"
#include "mock_inputer_get_data.h"

#define LOG_TAG "PIN_AUTH_SA"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::UserAuth;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
class PinAuthExecutorCallbackHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthExecutorCallbackHdiUnitTest ::SetUpTestCase()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::TearDownTestCase()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::SetUp()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::TearDown()
{
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnGetData_005, TestSize.Level0)
{
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi = MakeShared<PinAuthCollectorHdi>(nullptr);
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    uint64_t authSubType = 0;
    uint32_t algoVersion = 0;
    std::vector<uint8_t> challenge = {1, 2, 3, 4, 5};
    std::string pinComplexityReg = {};

    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthCollectorHdi, executorParam, GET_DATA_MODE_COLLECTOR_PIN_AUTH);
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    callbackHdi.tokenId_ = tempTokenId;
    PinAuthManager::GetInstance().pinAuthInputerMap_.emplace(tempTokenId, inputer);
    callbackHdi.pinAuthAllInOneHdi_ = nullptr;
    callbackHdi.pinAuthCollectorHdi_ = nullptr;
    EXPECT_EQ(callbackHdi.OnGetData(algoParameter, authSubType, algoVersion, challenge, pinComplexityReg), HDF_FAILURE);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnGetData_004, TestSize.Level0)
{
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi = MakeShared<PinAuthCollectorHdi>(nullptr);
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    uint64_t authSubType = 0;
    uint32_t algoVersion = 0;
    std::vector<uint8_t> challenge = {1, 2, 3, 4, 5};
    std::string pinComplexityReg = {};

    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthCollectorHdi, executorParam, GET_DATA_MODE_COLLECTOR_PIN_AUTH);
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    callbackHdi.tokenId_ = tempTokenId;
    PinAuthManager::GetInstance().pinAuthInputerMap_.emplace(tempTokenId, inputer);
    EXPECT_EQ(callbackHdi.OnGetData(algoParameter, authSubType, algoVersion, challenge, pinComplexityReg), HDF_SUCCESS);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnGetData_003, TestSize.Level0)
{
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    uint64_t authSubType = 0;
    uint32_t algoVersion = 0;
    std::vector<uint8_t> challenge = {1, 2, 3, 4, 5};
    std::string pinComplexityReg = {};

    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    callbackHdi.tokenId_ = tempTokenId;
    PinAuthManager::GetInstance().pinAuthInputerMap_.emplace(tempTokenId, inputer);
    
    EXPECT_EQ(callbackHdi.OnGetData(algoParameter, authSubType, algoVersion, challenge, pinComplexityReg), HDF_SUCCESS);
}


HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnGetData_002, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);

    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    auto executeCallback = MakeShared<MockIExecuteCallback>();
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    callbackHdi.frameworkCallback_ = Common::MakeShared<MockIExecuteCallback>();
    EXPECT_EQ(callbackHdi.ConvertResultCode(SYSTEM_ERROR_CODE_BEGIN), GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_ConvertResultCode_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    auto executeCallback = MakeShared<MockIExecuteCallback>();
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    callbackHdi.frameworkCallback_ = Common::MakeShared<MockIExecuteCallback>();
    EXPECT_EQ(callbackHdi.ConvertResultCode(SYSTEM_ERROR_CODE_BEGIN), GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnMessage_001, TestSize.Level0)
{
    auto executeCallback = MakeShared<MockIExecuteCallback>();
    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    int32_t tip = 0;
    callbackHdi.frameworkCallback_ = Common::MakeShared<MockIExecuteCallback>();
    EXPECT_EQ(callbackHdi.OnMessage(tip, msg), HDF_SUCCESS);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnTip_001, TestSize.Level0)
{
    auto executeCallback = MakeShared<MockIExecuteCallback>();
    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4, 5};
    int32_t tip = 0;
    callbackHdi.frameworkCallback_ = Common::MakeShared<MockIExecuteCallback>();
    EXPECT_EQ(callbackHdi.OnTip(tip, extraInfo), HDF_SUCCESS);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnGetData_001, TestSize.Level0)
{
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    auto executorProxy = new (std::nothrow) MockIAllInOneExecutor();
    std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(executorProxy);
    const uint32_t tempTokenId = 123;
    const uint64_t tempScheduleId = 1;
    const UserAuth::ExecutorParam executorParam = {
        .tokenId = tempTokenId,
        .authIntent = 0,
        .scheduleId = tempScheduleId,
    };
    PinAuthExecutorCallbackHdi callbackHdi(
        executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    uint64_t authSubType = 0;
    uint32_t algoVersion = 0;
    std::vector<uint8_t> challenge = {1, 2, 3, 4, 5};
    std::string pinComplexityReg = {};
    EXPECT_EQ(callbackHdi.OnGetData(algoParameter, authSubType, algoVersion, challenge, pinComplexityReg),
        HDF_SUCCESS);
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnResult_001, TestSize.Level0)
{
    static const std::map<ResultCode, IamResultCode> data = {{SUCCESS, IamResultCode::SUCCESS},
        {FAIL, IamResultCode::FAIL}, {GENERAL_ERROR, IamResultCode::GENERAL_ERROR},
        {CANCELED, IamResultCode::CANCELED}, {TIMEOUT, IamResultCode::TIMEOUT},
        {BUSY, IamResultCode::BUSY},
        {INVALID_PARAMETERS, IamResultCode::INVALID_PARAMETERS},
        {LOCKED, IamResultCode::LOCKED}};

    for (const auto &pair : data) {
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        std::vector<uint8_t> testExtraInfo = {1, 2, 3, 4, 5, 6};
        EXPECT_CALL(*executeCallback, OnResult(_, _))
            .Times(Exactly(3))
            .WillRepeatedly([&pair, &testExtraInfo](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_TRUE(result == pair.second);
                EXPECT_TRUE(testExtraInfo.size() == extraInfo.size());
                EXPECT_TRUE(std::equal(extraInfo.begin(), extraInfo.end(), testExtraInfo.begin()));
            });
        std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(nullptr);
        const uint32_t tokenId = 123;
        const uint64_t scheduleId = 1;
        const UserAuth::ExecutorParam executorParam = {
            .tokenId = tokenId,
            .authIntent = 0,
            .scheduleId = scheduleId,
        };
        PinAuthExecutorCallbackHdi callbackHdi1(
            executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH);
        callbackHdi1.OnResult(pair.first, testExtraInfo);
        PinAuthExecutorCallbackHdi callbackHdi2(
            executeCallback, pinAuthAllInOneHdi, executorParam, GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL);
        callbackHdi2.OnResult(pair.first, testExtraInfo);
        std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi = MakeShared<PinAuthCollectorHdi>(nullptr);
        PinAuthExecutorCallbackHdi callbackHdi3(
            executeCallback, pinAuthCollectorHdi, executorParam, GET_DATA_MODE_COLLECTOR_PIN_AUTH);
        callbackHdi2.OnResult(pair.first, testExtraInfo);
    }
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
