/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "pin_auth_all_in_one_hdi.h"

#include <map>

#include "hdf_base.h"

#include "iam_check.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_executor_hdi_common.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
PinAuthAllInOneHdi::PinAuthAllInOneHdi(const sptr<IAllInOneExecutor> &allInOneProxy)
    : allInOneProxy_(allInOneProxy)
{
}

UserAuth::ResultCode PinAuthAllInOneHdi::GetExecutorInfo(UserAuth::ExecutorInfo &info)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    ExecutorInfo localInfo = { };
    int32_t status = allInOneProxy_->GetExecutorInfo(localInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("GetExecutorInfo fail ret=%{public}d", result);
        return result;
    }
    SetAuthType(localInfo.authType);
    int32_t ret = MoveHdiExecutorInfo(localInfo, info);
    if (ret != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("MoveHdiExecutorInfo fail ret=%{public}d", ret);
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnRegisterFinish fail result %{public}d", result);
        return result;
    }

    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::SendMessage(
    uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->SendMessage(scheduleId, srcRole, msg);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendMessage fail result %{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::OnSetData(uint64_t scheduleId, uint64_t authSubType,
    const std::vector<uint8_t> &data, uint32_t pinLength, int32_t errorCode)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->SetData(scheduleId, authSubType, data, pinLength, errorCode);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("OnSetData fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Enroll(uint64_t scheduleId, const UserAuth::EnrollParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (!GetAuthType().has_value()) {
        IAM_LOGE("authType is error");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    GetDataMode mode = GET_DATA_MODE_NONE;
    if (GetAuthType().value() == AuthType::PIN) {
        mode = GET_DATA_MODE_ALL_IN_ONE_PIN_ENROLL;
    } else if (GetAuthType().value() == AuthType::PRIVATE_PIN) {
        mode = GET_DATA_MODE_ALL_IN_ONE_PRIVATE_PIN_ENROLL;
    } else {
        mode = GET_DATA_MODE_ALL_IN_ONE_RECOVERY_KEY_ENROLL;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .scheduleId = scheduleId,
        .userId = param.userId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), executorParam, mode));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Enroll(scheduleId, param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Enroll fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Authenticate(
    uint64_t scheduleId, const UserAuth::AuthenticateParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (!GetAuthType().has_value()) {
        IAM_LOGE("authType is error");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    GetDataMode mode = GET_DATA_MODE_NONE;
    if (GetAuthType().value() == AuthType::PIN) {
        mode = GET_DATA_MODE_ALL_IN_ONE_PIN_AUTH;
    } else if (GetAuthType().value() == AuthType::PRIVATE_PIN) {
        mode = GET_DATA_MODE_ALL_IN_ONE_PRIVATE_PIN_AUTH;
    } else {
        mode = GET_DATA_MODE_ALL_IN_ONE_RECOVERY_KEY_AUTH;
    }
    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .authIntent = param.authIntent,
        .scheduleId = scheduleId,
        .userId = param.userId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
            shared_from_this(), executorParam, mode));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (param.templateIdList.size() == 0) {
        IAM_LOGE("Error param");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Authenticate(scheduleId, param.templateIdList,
        param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Authenticate fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Delete(templateIdList[0]);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Delete fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Cancel(uint64_t scheduleId)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Cancel(scheduleId);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::GetProperty(const std::vector<uint64_t> &templateIdList,
    const std::vector<UserAuth::Attributes::AttributeKey> &keys, UserAuth::Property &property)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(allInOneProxy_ != nullptr, UserAuth::ResultCode::GENERAL_ERROR);

    std::vector<int32_t> propertyTypes;
    UserAuth::ResultCode result = ConvertAttributeKeyVectorToPropertyType(keys, propertyTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(result == UserAuth::ResultCode::SUCCESS, UserAuth::ResultCode::GENERAL_ERROR);

    Property hdiProperty;
    int32_t status = allInOneProxy_->GetProperty(templateIdList, propertyTypes, hdiProperty);
    result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendCommand fail result %{public}d", result);
        return result;
    }
    MoveHdiProperty(hdiProperty, property);
    return UserAuth::ResultCode::SUCCESS;
}

void PinAuthAllInOneHdi::MoveHdiProperty(Property &in, UserAuth::Property &out)
{
    out.authSubType = in.authSubType;
    out.lockoutDuration = in.lockoutDuration;
    out.remainAttempts = in.remainAttempts;
    out.nextFailLockoutDuration = in.nextFailLockoutDuration;
    out.credentialLength = in.credentialLength;
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertAttributeKeyVectorToPropertyType(
    const std::vector<UserAuth::Attributes::AttributeKey> inItems, std::vector<int32_t> &outItems)
{
    outItems.clear();
    for (auto &inItem : inItems) {
        if (inItem == UserAuth::Attributes::ATTR_ENROLL_PROGRESS ||
            inItem == UserAuth::Attributes::ATTR_SENSOR_INFO) {
            continue;
        }
        int32_t outItem;
        UserAuth::ResultCode result = ConvertAttributeKeyToPropertyType(inItem, outItem);
        IF_FALSE_LOGE_AND_RETURN_VAL(result == UserAuth::ResultCode::SUCCESS, UserAuth::ResultCode::GENERAL_ERROR);
        outItems.push_back(outItem);
    }

    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertAttributeKeyToPropertyType(const UserAuth::Attributes::AttributeKey in,
    int32_t &out)
{
    static const std::map<UserAuth::Attributes::AttributeKey, GetPropertyType> data = {
        { UserAuth::Attributes::ATTR_PIN_SUB_TYPE, GetPropertyType::AUTH_SUB_TYPE },
        { UserAuth::Attributes::ATTR_FREEZING_TIME, GetPropertyType::LOCKOUT_DURATION },
        { UserAuth::Attributes::ATTR_REMAIN_TIMES, GetPropertyType::REMAIN_ATTEMPTS },
        { UserAuth::Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, GetPropertyType::NEXT_FAIL_LOCKOUT_DURATION },
        { UserAuth::Attributes::ATTR_CREDENTIAL_LENGTH, GetPropertyType::CREDENTIAL_LENGTH },
    };

    auto iter = data.find(in);
    if (iter == data.end()) {
        IAM_LOGE("attribute %{public}d is invalid", in);
        return UserAuth::ResultCode::GENERAL_ERROR;
    } else {
        out = static_cast<int32_t>(iter->second);
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return UserAuth::ResultCode::SUCCESS;
}

void PinAuthAllInOneHdi::SetAuthType(int32_t authType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    switch (authType) {
        case AuthType::PIN:
            IAM_LOGI("set authType is pin");
            authType_ = authType;
            break;
        case AuthType::RECOVERY_KEY:
            IAM_LOGI("set authType is recovery key");
            authType_ = authType;
            break;
        case AuthType::PRIVATE_PIN:
            IAM_LOGI("set authType is private pin");
            authType_ = authType;
            break;
        default:
            IAM_LOGE("authType value is error, set failed");
    }
}

std::optional<int32_t> PinAuthAllInOneHdi::GetAuthType()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!authType_.has_value()) {
        IAM_LOGE("authType_ not assigned a value");
        return std::nullopt;
    }

    return authType_;
}

UserAuth::ResultCode PinAuthAllInOneHdi::Abandon(uint64_t scheduleId, const UserAuth::DeleteParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    if (allInOneProxy_ == nullptr) {
        IAM_LOGE("allInOneProxy is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }

    UserAuth::ExecutorParam executorParam = {
        .tokenId = param.tokenId,
        .scheduleId = scheduleId,
        .userId = param.userId,
    };
    auto callback = sptr<IExecutorCallback>(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), executorParam, GET_DATA_MODE_NONE));
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    int32_t status = allInOneProxy_->Abandon(scheduleId, param.templateId, param.extraInfo, callback);
    UserAuth::ResultCode result = ConvertHdiResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("Abandon fail ret=%{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::SendCommand(UserAuth::PropertyMode commandId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(allInOneProxy_ != nullptr, UserAuth::ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(callbackObj != nullptr, UserAuth::ResultCode::GENERAL_ERROR);
    int32_t hdiCommandId;
    UserAuth::ResultCode result = ConvertCommandId(commandId, hdiCommandId);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("ConvertCommandId fail result %{public}d", result);
        return result;
    }
    UserAuth::ExecutorParam executorParam = {};
    sptr<IExecutorCallback> callback(new (std::nothrow) PinAuthExecutorCallbackHdi(callbackObj,
        shared_from_this(), executorParam, GET_DATA_MODE_NONE));
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, UserAuth::ResultCode::GENERAL_ERROR);
    int32_t status = allInOneProxy_->SendCommand(hdiCommandId, extraInfo, callback);
    result = ConvertResultCode(status);
    if (result != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("SendCommand fail result %{public}d", result);
        return result;
    }
    return UserAuth::ResultCode::SUCCESS;
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertCommandId(const UserAuth::PropertyMode in, int32_t &out)
{
    if (static_cast<CommandId>(in) > CommandId::VENDOR_COMMAND_BEGIN) {
        out = static_cast<CommandId>(in);
        IAM_LOGI("vendor command id %{public}d, no covert", out);
        return UserAuth::ResultCode::SUCCESS;
    } else {
        IAM_LOGE("command id %{public}d is invalid", in);
        return UserAuth::ResultCode::INVALID_PARAMETERS;
    }
}

UserAuth::ResultCode PinAuthAllInOneHdi::ConvertResultCode(const int32_t in)
{
    HDF_STATUS hdfIn = static_cast<HDF_STATUS>(in);
    static const std::map<HDF_STATUS, UserAuth::ResultCode> data = {
        { HDF_SUCCESS, UserAuth::ResultCode::SUCCESS },
        { HDF_FAILURE, UserAuth::ResultCode::GENERAL_ERROR },
        { HDF_ERR_TIMEOUT, UserAuth::ResultCode::TIMEOUT },
        { HDF_ERR_QUEUE_FULL, UserAuth::ResultCode::BUSY },
        { HDF_ERR_DEVICE_BUSY, UserAuth::ResultCode::BUSY },
    };

    UserAuth::ResultCode out;
    auto iter = data.find(hdfIn);
    if (iter == data.end()) {
        out = UserAuth::ResultCode::GENERAL_ERROR;
    } else {
        out = iter->second;
    }
    IAM_LOGI("covert hdi result code %{public}d to framework result code %{public}d", in, out);
    return out;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
