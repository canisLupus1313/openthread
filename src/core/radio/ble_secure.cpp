/*
 *  Copyright (c) 2016, The OpenThread Authors.
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

#include "ble_secure.hpp"

#if OPENTHREAD_CONFIG_BLE_SECURE_ENABLE

#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "meshcop/dtls.hpp"
#include <openthread/platform/ble.h>

/**
 * @file
 *   This file implements the secure Ble agent.
 */

namespace ot {
namespace Ble {

RegisterLogModule("BleSecure");

BleSecure::BleSecure(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mTls(aInstance, false, false)
    , mReceiveCallback(nullptr)
    , mReceiveContext(nullptr)
    , mLineMode(0)
    , mConnectedCallback(nullptr)
    , mConnectedContext(nullptr)
    , mTransmitTask(aInstance, BleSecure::HandleTransmit, this)
    , mHandle(0)
{
}

Error BleSecure::Start(ReceiveCallback aHandler, bool aLineMode, void *aContext)
{
    Error error = kErrorNone;

    mReceiveCallback    = aHandler;
    mLineMode           = aLineMode;
    mReceiveContext     = aContext;
    mConnectedCallback  = nullptr;
    mConnectedContext   = nullptr;

    SuccessOrExit(error = otPlatBleEnable(&GetInstance()));
	SuccessOrExit(error = otPlatBleGapAdvStart(&GetInstance(), 0, 0));
    SuccessOrExit(error = mTls.Open(&BleSecure::HandleTlsReceive, &BleSecure::HandleTlsConnected, this));
    SuccessOrExit(error = mTls.Bind(HandleTransport, this));

exit:
    return error;
}

void BleSecure::Stop(void)
{
    otPlatBleGapAdvStop(&GetInstance());
    otPlatBleDisable(&GetInstance());
	
    mTls.Close();

    mTransmitQueue.DequeueAndFreeAll();
}

Error BleSecure::Connect(ConnectedCallback aCallback, void *aContext)
{
    Ip6::SockAddr sockaddr;

    mConnectedCallback = aCallback;
    mConnectedContext  = aContext;

    return mTls.Connect(sockaddr);
}

void BleSecure::SetPsk(const MeshCoP::JoinerPskd &aPskd)
{
    static_assert(static_cast<uint16_t>(MeshCoP::JoinerPskd::kMaxLength) <=
                      static_cast<uint16_t>(MeshCoP::Dtls::kPskMaxLength),
                  "The maximum length of TLS PSK is smaller than joiner PSKd");

    SuccessOrAssert(mTls.SetPsk(reinterpret_cast<const uint8_t *>(aPskd.GetAsCString()), aPskd.GetLength()));
}

Error BleSecure::SendMessage(ot::Message &aMessage)
{
    Error error = kErrorNone;

    VerifyOrExit(IsConnected(), error = kErrorInvalidState);

    mTransmitQueue.Enqueue(aMessage);
    mTransmitTask.Post();

exit:
    return error;
}

Error BleSecure::Send(uint8_t *aBuf, uint16_t aLength)
{
    ot::Message *message = nullptr;

    VerifyOrExit((message = Get<MessagePool>().Allocate(Message::kTypeBle, 0 )) != nullptr);
    SuccessOrExit(message->AppendBytes(aBuf, aLength));

    return SendMessage(*message);

    exit:
        FreeMessage(message);
        return kErrorNoBufs;
}


Error BleSecure::HandleBleReceive(uint8_t *aBuf, uint16_t aLength)
{
    ot::Message *message = nullptr;

    VerifyOrExit((message = Get<MessagePool>().Allocate(Message::kTypeBle, 0 )) != nullptr);
    SuccessOrExit(message->AppendBytes(aBuf, aLength));

    mTls.Receive(*message);
    FreeMessage(message);

    return kErrorNone;

    exit:
        FreeMessage(message);
        return kErrorNoBufs;
}


void BleSecure::HandleTlsConnected(void *aContext, bool aConnected)
{
    return static_cast<BleSecure *>(aContext)->HandleTlsConnected(aConnected);
}

void BleSecure::HandleTlsConnected(bool aConnected)
{
    if (mConnectedCallback != nullptr)
    {
        mConnectedCallback(aConnected, mConnectedContext);
    }
}

void BleSecure::HandleTlsReceive(void *aContext, uint8_t *aBuf, uint16_t aLength)
{
    return static_cast<BleSecure *>(aContext)->HandleTlsReceive(aBuf, aLength);
}

void BleSecure::HandleTlsReceive(uint8_t *aBuf, uint16_t aLength)
{
    ot::Message *message = nullptr;

    VerifyOrExit((message = Get<MessagePool>().Allocate(Message::kTypeBle)) != nullptr);
    SuccessOrExit(message->AppendBytes(aBuf, aLength));

    if (mReceiveCallback != nullptr)
    {
        mReceiveCallback(message, mReceiveContext);
    }

exit:
    FreeMessage(message);
}

void BleSecure::HandleTransmit(Tasklet &aTasklet)
{
    static_cast<BleSecure *>(static_cast<TaskletContext &>(aTasklet).GetContext())->HandleTransmit();
}

void BleSecure::HandleTransmit(void)
{
    Error        error   = kErrorNone;
    ot::Message *message = mTransmitQueue.GetHead();

    VerifyOrExit(message != nullptr);
    mTransmitQueue.Dequeue(*message);

    if (mTransmitQueue.GetHead() != nullptr)
    {
        mTransmitTask.Post();
    }

    SuccessOrExit(error = mTls.Send(*message, message->GetLength()));

exit:
    if (error != kErrorNone)
    {
        LogNote("Transmit: %s", ErrorToString(error));
        message->Free();
    }
    else
    {
        LogDebg("Transmit: %s", ErrorToString(error));
    }
}

Error BleSecure::HandleTransport(void *aContext, ot::Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    OT_UNUSED_VARIABLE(aMessageInfo);
    return static_cast<BleSecure *>(aContext)->HandleTransport(aMessage);
}

Error BleSecure::HandleTransport(ot::Message &aMessage)
{
    otBleRadioPacket packet;
    uint16_t len = aMessage.GetLength();
    uint16_t offset = 0;
    otError error = OT_ERROR_NONE;

    while(len > 0)
    {
        if(len <= kMaxPacketSize) packet.mLength = len;
        else packet.mLength = kMaxPacketSize;

        aMessage.Read(offset, mPacketBuffer, packet.mLength);
        packet.mValue = mPacketBuffer; 
        packet.mPower = 0;

        error = otPlatBleGattServerIndicate(&GetInstance(), mHandle, &packet);
        if(error != OT_ERROR_NONE) break;

        len -= packet.mLength;
        offset += packet.mLength;
    }
    
    // if(error != OT_ERROR_NONE)  --> close connection?  Not free message?

    aMessage.Free();
    return kErrorNone;
}


} // namespace Ble
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_SECURE_ENABLE
