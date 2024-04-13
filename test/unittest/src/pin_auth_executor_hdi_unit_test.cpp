/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hdf_base.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_executor_hdi.h"
#include "iam_common_defines.h"
#include "mock_iexecute_callback.h"
#include "mock_iexecutor.h"

#define LOG_TAG "PIN_AUTH_SA"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
using IamExecutorRole = OHOS::UserIam::UserAuth::ExecutorRole;
using IamExecutorInfo = OHOS::UserIam::UserAuth::ExecutorInfo;
using IamAuthType = OHOS::UserIam::UserAuth::AuthType;
using IamExecutorSecureLevel = OHOS::UserIam::UserAuth::ExecutorSecureLevel;
using IamPropertyMode = OHOS::UserIam::UserAuth::PropertyMode;
namespace {
static const std::map<HDF_STATUS, IamResultCode> RESULT_CODE_MAP = {
    {HDF_SUCCESS, IamResultCode::SUCCESS},
    {HDF_FAILURE, IamResultCode::FAIL},
    {HDF_ERR_TIMEOUT, IamResultCode::TIMEOUT},
    {HDF_ERR_QUEUE_FULL, IamResultCode::BUSY},
    {HDF_ERR_DEVICE_BUSY, IamResultCode::BUSY}
};
}

class PinAuthExecutorHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthExecutorHdiUnitTest::SetUpTestCase()
{
}

void PinAuthExecutorHdiUnitTest::TearDownTestCase()
{
}

void PinAuthExecutorHdiUnitTest::SetUp()
{
}

void PinAuthExecutorHdiUnitTest::TearDown()
{
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    EXPECT_CALL(*executorProxy, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([](ExecutorInfo &info) {
        info = {
            .executorRole = ExecutorRole::ALL_IN_ONE,
            .authType = AuthType::PIN,
            .esl = ExecutorSecureLevel::ESL0,
        };
        return HDF_SUCCESS;
    });
    PinAuthExecutorHdi executorHdi(executorProxy);
    IamExecutorInfo info = {};
    auto ret = executorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(info.executorRole == IamExecutorRole::ALL_IN_ONE);
    EXPECT_TRUE(info.authType == IamAuthType::PIN);
    EXPECT_TRUE(info.esl == IamExecutorSecureLevel::ESL0);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_002, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::ALL_IN_ONE,
                    .authType = AuthType::PIN,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return static_cast<int32_t>(pair.first);
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_003, TestSize.Level0)
{
    static const std::map<AuthType, pair<IamAuthType, IamResultCode>> data = {
        {AuthType::PIN, {IamAuthType::PIN, IamResultCode::SUCCESS}},
        {static_cast<AuthType>(AuthType::PIN + 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
        {static_cast<AuthType>(AuthType::PIN - 1),
            {IamAuthType::PIN, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::ALL_IN_ONE,
                    .authType = pair.first,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.authType == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_004, TestSize.Level0)
{
    static const std::map<ExecutorRole, pair<IamExecutorRole, IamResultCode>> data = {
        {ExecutorRole::COLLECTOR, {IamExecutorRole::COLLECTOR, IamResultCode::SUCCESS}},
        {ExecutorRole::VERIFIER, {IamExecutorRole::VERIFIER, IamResultCode::SUCCESS}},
        {ExecutorRole::ALL_IN_ONE, {IamExecutorRole::ALL_IN_ONE, IamResultCode::SUCCESS}},
        {static_cast<ExecutorRole>(ExecutorRole::COLLECTOR - 1),
            {IamExecutorRole::ALL_IN_ONE, IamResultCode::GENERAL_ERROR}},
        {static_cast<ExecutorRole>(ExecutorRole::ALL_IN_ONE + 1),
            {IamExecutorRole::ALL_IN_ONE, IamResultCode::GENERAL_ERROR}},
    };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = pair.first,
                    .authType = AuthType::PIN,
                    .esl = ExecutorSecureLevel::ESL0,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.executorRole == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_005, TestSize.Level0)
{
    static const std::map<ExecutorSecureLevel, pair<IamExecutorSecureLevel, IamResultCode>> data =
        {
            {ExecutorSecureLevel::ESL0, {IamExecutorSecureLevel::ESL0, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL1, {IamExecutorSecureLevel::ESL1, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL2, {IamExecutorSecureLevel::ESL2, IamResultCode::SUCCESS}},
            {ExecutorSecureLevel::ESL3, {IamExecutorSecureLevel::ESL3, IamResultCode::SUCCESS}},
            {static_cast<ExecutorSecureLevel>(ExecutorSecureLevel::ESL0 - 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
            {static_cast<ExecutorSecureLevel>(ExecutorSecureLevel::ESL3 + 1),
                {IamExecutorSecureLevel::ESL3, IamResultCode::GENERAL_ERROR}},
        };
    for (const auto &pair : data) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetExecutorInfo(_))
            .Times(Exactly(1))
            .WillOnce([&pair](ExecutorInfo &info) {
                info = {
                    .executorRole = ExecutorRole::ALL_IN_ONE,
                    .authType = AuthType::PIN,
                    .esl = pair.first,
                };
                return HDF_SUCCESS;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        IamExecutorInfo info = {};
        auto ret = executorHdi.GetExecutorInfo(info);
        EXPECT_TRUE(ret == pair.second.second);
        if (ret == IamResultCode::SUCCESS) {
            EXPECT_TRUE(info.esl == pair.second.first);
        }
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetExecutorInfo_006, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    IamExecutorInfo info = {};
    auto ret = executorHdi.GetExecutorInfo(info);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnRegisterFinish_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, OnRegisterFinish(_, _, _))
            .Times(Exactly(1))
            .WillOnce(
                [&pair](const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey,
                    const std::vector<uint8_t> &extraInfo) { return pair.first; });
        PinAuthExecutorHdi executorHdi(executorProxy);
        auto ret =
            executorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnRegisterFinish_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.OnRegisterFinish(std::vector<uint64_t>(), std::vector<uint8_t>(), std::vector<uint8_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnSetData_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, SetData(_, _, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t>& data,
                int32_t resultCode)
                    { return pair.first; });
        PinAuthExecutorHdi executorHdi(executorProxy);
        auto ret = executorHdi.OnSetData(0, 0, std::vector<uint8_t>(), 0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_OnSetData_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.OnSetData(0, 0, std::vector<uint8_t>(), 0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Enroll(_, _, _))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
                          const sptr<IExecutorCallback> &callbackObj) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        auto ret = executorHdi->Enroll(0, UserAuth::EnrollParam{0, std::vector<uint8_t>()}, executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
    ASSERT_TRUE(executorHdi != nullptr);
    auto ret = executorHdi->Enroll(0, UserAuth::EnrollParam{0, std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Enroll_003, TestSize.Level0)
{
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(nullptr);
    ASSERT_TRUE(executorHdi != nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = executorHdi->Enroll(0, UserAuth::EnrollParam{0, std::vector<uint8_t>()}, executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Authenticate(_, _, _, _)).Times(Exactly(1)).WillOnce([&pair](
            uint64_t scheduleId, const std::vector<uint64_t>& templateIdList, const std::vector<uint8_t> &extraInfo,
            const sptr<IExecutorCallback> &callbackObj) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        const std::vector<uint64_t> templateIdList = {1, 2};
        auto ret = executorHdi->Authenticate(0,
            UserAuth::AuthenticateParam{0, templateIdList, std::vector<uint8_t>()}, executeCallback);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
    auto ret = executorHdi->Authenticate(0,
        UserAuth::AuthenticateParam{0, std::vector<uint64_t>(), std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Authenticate_003, TestSize.Level0)
{
    auto executorHdi = MakeShared<PinAuthExecutorHdi>(nullptr);
    auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
    ASSERT_TRUE(executeCallback != nullptr);
    auto ret = executorHdi->Authenticate(0,
        UserAuth::AuthenticateParam{0, std::vector<uint64_t>(), std::vector<uint8_t>()}, executeCallback);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Identify_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    auto ret = executorHdi.Identify(0, UserAuth::IdentifyParam{0, std::vector<uint8_t>()}, nullptr);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Delete_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Delete(_))
            .Times(Exactly(1))
            .WillOnce([&pair](uint64_t templateId) { return pair.first; });
        auto executorHdi = MakeShared<PinAuthExecutorHdi>(executorProxy);
        ASSERT_TRUE(executorHdi != nullptr);
        const std::vector<uint64_t> templateIdList = {1, 2};
        auto ret = executorHdi->Delete(templateIdList);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Delete_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.Delete(std::vector<uint64_t>());
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Cancel_001, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, Cancel(_)).Times(Exactly(1)).WillOnce([&pair](uint64_t scheduleId) {
            return pair.first;
        });
        PinAuthExecutorHdi executorHdi(executorProxy);
        auto ret = executorHdi.Cancel(0);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_Cancel_002, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    auto ret = executorHdi.Cancel(0);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_SendCommand_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    auto ret = executorHdi.SendCommand(IamPropertyMode::PROPERTY_MODE_FREEZE, std::vector<uint8_t>(), nullptr);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_SendMessage_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    std::vector<uint8_t> data;
    auto ret = executorHdi.SendMessage(1, 1, data);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetProperty_001, TestSize.Level0)
{
    PinAuthExecutorHdi executorHdi(nullptr);
    std::vector<uint64_t> templateIdList;
    std::vector<UserAuth::Attributes::AttributeKey> keys;
    UserAuth::Property property = {};
    auto ret = executorHdi.GetProperty(templateIdList, keys, property);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetProperty_002, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    std::vector<uint64_t> templateIdList;
    std::vector<UserAuth::Attributes::AttributeKey> keys = { UserAuth::Attributes::ATTR_SIGNATURE };
    UserAuth::Property property = {};
    auto ret = executorHdi.GetProperty(templateIdList, keys, property);
    EXPECT_TRUE(ret == IamResultCode::GENERAL_ERROR);
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_GetProperty_003, TestSize.Level0)
{
    for (const auto &pair : RESULT_CODE_MAP) {
        auto executorProxy = new (std::nothrow) MockIExecutor();
        ASSERT_TRUE(executorProxy != nullptr);
        EXPECT_CALL(*executorProxy, GetProperty(_, _, _)).Times(Exactly(1)).WillOnce([&pair](
            const std::vector<uint64_t> &templateIdList,
            const std::vector<int32_t> &propertyTypes, Property &property) {
                return pair.first;
            });
        PinAuthExecutorHdi executorHdi(executorProxy);
        std::vector<uint64_t> templateIdList;
        std::vector<UserAuth::Attributes::AttributeKey> keys;
        if (pair.first != HDF_SUCCESS) {
            keys.push_back(UserAuth::Attributes::ATTR_PIN_SUB_TYPE);
        }
        UserAuth::Property property = {};
        auto ret = executorHdi.GetProperty(templateIdList, keys, property);
        EXPECT_TRUE(ret == pair.second);
    }
}

HWTEST_F(PinAuthExecutorHdiUnitTest, PinAuthExecutorHdi_SetCachedTemplates_001, TestSize.Level0)
{
    auto executorProxy = new (std::nothrow) MockIExecutor();
    ASSERT_TRUE(executorProxy != nullptr);
    PinAuthExecutorHdi executorHdi(executorProxy);
    std::vector<uint64_t> templateIdList;
    auto ret = executorHdi.SetCachedTemplates(templateIdList);
    EXPECT_TRUE(ret == IamResultCode::SUCCESS);
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
