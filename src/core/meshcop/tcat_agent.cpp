/*
 *  Copyright (c) 2023, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements the TCAT Agent service.
 */

#include "tcat_agent.hpp"

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#include <stdio.h>

#include "common/array.hpp"
#include "common/as_core_type.hpp"
#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/encoding.hpp"
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "common/string.hpp"
#include "meshcop/meshcop.hpp"
#include "radio/radio.hpp"
#include "thread/thread_netif.hpp"
#include "thread/uri_paths.hpp"
#include "utils/otns.hpp"

namespace ot {
namespace MeshCoP {

RegisterLogModule("TcatAgent");

bool TcatAgent::VendorInfo::IsValid(void) const
{
    if (mProvisioningUrl != nullptr && !IsValidUtf8String(mProvisioningUrl))
        return false;

    return true;
}

TcatAgent::TcatAgent(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mVendorInfo(nullptr)
    , mJoinCallback(nullptr)
    , mEnabled(false)
    , mElevated(false)
{
    mElevationPsk.m8[0] = 0;
}

Error TcatAgent::Start(const char *aElevationPsk, TcatAgent::VendorInfo *aVendorInfo, JoinCallback aHandler)
{
    Error error = kErrorNone;

    LogInfo("TCAT agent starting");

    VerifyOrExit(aElevationPsk != nullptr, error = kErrorInvalidArgs);
    VerifyOrExit(strlen(aElevationPsk) <= OT_TCAT_ELEVATION_PSK_LENGTH, error = kErrorInvalidArgs);

    if (aVendorInfo != nullptr)
    {
        VerifyOrExit(aVendorInfo->IsValid(), error = kErrorInvalidArgs);
    }

    strcpy(mElevationPsk.m8, aElevationPsk);
    mVendorInfo   = aVendorInfo;
    mJoinCallback = aHandler;
    mEnabled      = true;
    mElevated     = false;

exit:
    LogError("start TCAT agent", error);
    return error;
}

void TcatAgent::Stop(void)
{
    mEnabled      = false;
    mElevated     = false;
    mJoinCallback = nullptr;
    LogInfo("TCAT agent stopped");
}

Error TcatAgent::HandleSingleTlv(ot::Message   &aIncommingMessage,
                                 ot::Message   &aOutgoingMessage,
                                 MeshCoP::Dtls &aTlsContext)
{
    Error       error = kErrorNone;
    ot::Tlv     tlv;
    uint16_t    offset = aIncommingMessage.GetOffset();
    CommandType command;

    SuccessOrExit(error = aIncommingMessage.Read(offset, tlv));
    VerifyOrExit(tlv.GetType() != kApplication, error = kErrorNotTmf);
    VerifyOrExit(tlv.IsExtended() == false, error = kErrorParse);
    offset += 2;

    switch (tlv.GetType())
    {
    case TlvType::kCommand:
        SuccessOrExit(error = aIncommingMessage.Read(offset, &command, sizeof(command)));
        error = HandleCommand(command, aOutgoingMessage, aTlsContext);
        break;

    case TlvType::kActiveDataset:
        error = HandleActiveDataset(aIncommingMessage, offset, tlv.GetLength(), aTlsContext);
        break;

    default:
        error = kErrorParse;
    }

exit:
    return error;
}

Error TcatAgent::HandleCommand(CommandType aCommand, ot::Message &aOutgoingMessage, MeshCoP::Dtls &aTlsContext)
{
    OT_UNUSED_VARIABLE(aTlsContext);

    Error        error = kErrorNone;
    ot::Tlv      tlv;
    ResponseType response = ResponseType::kSuccess;

    tlv.SetType(TlvType::kResponse);
    tlv.SetLength(sizeof(response));

    switch (aCommand)
    {
    case CommandType::kTerminate:
        Stop();
        break;

    case CommandType::kThreadStart:

#if OPENTHREAD_CONFIG_LINK_RAW_ENABLE
        if (Get<Mac::LinkRaw>().IsEnabled())
            response = ResponseType::kInvalidState;
#endif
        if (response == ResponseType::kSuccess)
        {
            Get<ThreadNetif>().Up();
            if (Get<Mle::MleRouter>().Start() != kErrorNone)
                response = ResponseType::kInvalidState;
        }

        break;

    case CommandType::kThreadStop:
        Get<Mle::MleRouter>().Stop();
        break;

    default:
        response = ResponseType::kParseError;
    }

    SuccessOrExit(error = aOutgoingMessage.Append(tlv));
    SuccessOrExit(error = aOutgoingMessage.Append(response));

exit:
    return error;
}

Error TcatAgent::HandleActiveDataset(ot::Message   &aIncommingMessage,
                                     uint16_t       aOffset,
                                     uint16_t       aLength,
                                     MeshCoP::Dtls &aTlsContext)
{
    OT_UNUSED_VARIABLE(aTlsContext);

    Dataset                  dataset;
    otOperationalDatasetTlvs datasetTlvs;
    Error                    error = kErrorNone;

    SuccessOrExit(error = dataset.ReadFromMessage(aIncommingMessage, aOffset, aLength));
    dataset.ConvertTo(datasetTlvs);
    Get<ActiveDatasetManager>().Save(datasetTlvs);

exit:
    return error;
}

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE
