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

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#include <openthread/platform/ble.h>
#include "common/instance.hpp"
#include "common/locator_getters.hpp"
#include "common/log.hpp"
#include "common/tlvs.hpp"
#include "meshcop/dtls.hpp"

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
    , mTcatAgent(aInstance)
    , mConnectCallback(nullptr)
    , mReceiveCallback(nullptr)
    , mContext(nullptr)
    , mTlvMode(0)
    , mReceivedMessage(nullptr)
    , mSentMessage(nullptr)
    , mTransmitTask(aInstance, BleSecure::HandleTransmit, this)
    , mBleConnectionOpen(false)
    , mMtuSize(kInitialMtuSize)
{
}

Error BleSecure::Start(ConnectCallback aConnectHandler, ReceiveCallback aReceiveHandler, bool aTlvMode, void *aContext)
{
    Error error = kErrorNone;

    mConnectCallback = aConnectHandler;
    mReceiveCallback = aReceiveHandler;
    mTlvMode         = aTlvMode;
    mContext         = aContext;

    mMtuSize = kInitialMtuSize;

    SuccessOrExit(error = otPlatBleEnable(&GetInstance()));
    SuccessOrExit(error = otPlatBleGapAdvStart(&GetInstance(), 0, 0));
    SuccessOrExit(error = mTls.Open(&BleSecure::HandleTlsReceive, &BleSecure::HandleTlsConnected, this));
    SuccessOrExit(error = mTls.Bind(HandleTransport, this));

exit:
    return error;
}

Error BleSecure::TcatStart(const char                      *aElevationPsk,
                           MeshCoP::TcatAgent::VendorInfo  *aVendorInfo,
                           MeshCoP::TcatAgent::JoinCallback aHandler)
{
    return mTcatAgent.Start(aElevationPsk, aVendorInfo, aHandler);
}

void BleSecure::Stop(void)
{
    otPlatBleGapAdvStop(&GetInstance());
    otPlatBleDisable(&GetInstance());
    mBleConnectionOpen = false;
    mMtuSize           = kInitialMtuSize;

    if (mTcatAgent.IsEnabled())
        mTcatAgent.Stop();
    mTls.Close();

    mTransmitQueue.DequeueAndFreeAll();

    mConnectCallback = nullptr;
    mReceiveCallback = nullptr;
    mContext         = nullptr;

    FreeMessage(mReceivedMessage);
    mReceivedMessage = nullptr;
    FreeMessage(mSentMessage);
    mSentMessage = nullptr;
}

Error BleSecure::Connect()
{
    Ip6::SockAddr sockaddr;

    return mTls.Connect(sockaddr);
}

void BleSecure::SetPsk(const MeshCoP::JoinerPskd &aPskd)
{
    static_assert(static_cast<uint16_t>(MeshCoP::JoinerPskd::kMaxLength) <=
                      static_cast<uint16_t>(MeshCoP::Dtls::kPskMaxLength),
                  "The maximum length of TLS PSK is smaller than joiner PSKd");

    SuccessOrAssert(mTls.SetPsk(reinterpret_cast<const uint8_t *>(aPskd.GetAsCString()), aPskd.GetLength()));
}

Error BleSecure::SendMessage(ot::Message *aMessage)
{
    Error error = kErrorNone;

    VerifyOrExit(IsConnected(), error = kErrorInvalidState);
    VerifyOrExit(mSentMessage != nullptr, error = kErrorNoBufs);
    VerifyOrExit(aMessage != nullptr, error = kErrorInvalidArgs);
    SuccessOrExit(error = mSentMessage->AppendBytesFromMessage(*aMessage, 0, aMessage->GetLength()));

    if (mSentMessage->GetLength() > kFlushThreshold)
    {
        error = Flush();
    }

    if (error == kErrorNone)
        FreeMessage(aMessage);

exit:
    return error;
}

Error BleSecure::Send(uint8_t *aBuf, uint16_t aLength)
{
    Error error = kErrorNone;

    VerifyOrExit(IsConnected(), error = kErrorInvalidState);
    VerifyOrExit(mSentMessage != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = mSentMessage->AppendBytes(aBuf, aLength));

    if (mSentMessage->GetLength() > kFlushThreshold)
    {
        error = Flush();
    }

exit:
    return error;
}

Error BleSecure::SendApplicationTlv(uint8_t *aBuf, uint16_t aLength)
{
    if (aLength > 254)
    {
        ot::ExtendedTlv tlv;

        tlv.SetType(ot::MeshCoP::TcatAgent::TlvType::kApplication);
        tlv.SetLength(aLength);
        Send(reinterpret_cast<uint8_t *>(&tlv), sizeof(tlv));
    }
    else
    {
        ot::Tlv tlv;

        tlv.SetType(ot::MeshCoP::TcatAgent::TlvType::kApplication);
        tlv.SetLength(aLength);
        Send(reinterpret_cast<uint8_t *>(&tlv), sizeof(tlv));
    }

    return Send(aBuf, aLength);
}

Error BleSecure::Flush()
{
    Error error = kErrorNone;

    VerifyOrExit(IsConnected(), error = kErrorInvalidState);
    VerifyOrExit(mSentMessage != nullptr, error = kErrorNoBufs);
    VerifyOrExit(mSentMessage->GetLength() != 0, error = kErrorNone);

    mTransmitQueue.Enqueue(*mSentMessage);
    mTransmitTask.Post();

    mSentMessage = Get<MessagePool>().Allocate(Message::kTypeBle);
    VerifyOrExit(mSentMessage != nullptr, error = kErrorNoBufs);

exit:
    return error;
}

Error BleSecure::HandleBleReceive(uint8_t *aBuf, uint16_t aLength)
{
    ot::Message     *message = nullptr;
    Ip6::MessageInfo theMessageInfo;

    VerifyOrExit((message = Get<MessagePool>().Allocate(Message::kTypeBle, 0)) != nullptr);
    SuccessOrExit(message->AppendBytes(aBuf, aLength));

    // Cannot call Receive(..) directly because Setup(..) and mState are private
    mTls.HandleUdpReceive(*message, theMessageInfo);

    FreeMessage(message);

    return kErrorNone;

exit:
    FreeMessage(message);
    return kErrorNoBufs;
}

Error BleSecure::HandleBleConnected(uint16_t aConnectionId)
{
    OT_UNUSED_VARIABLE(aConnectionId);

    mBleConnectionOpen = true;

    otPlatBleGattMtuGet(&GetInstance(), &mMtuSize);

    if (mConnectCallback != nullptr)
    {
        mConnectCallback(&GetInstance(), IsConnected(), mBleConnectionOpen, mContext);
    }

    return kErrorNone;
}

Error BleSecure::HandleBleDisconnected(uint16_t aConnectionId)
{
    OT_UNUSED_VARIABLE(aConnectionId);

    mBleConnectionOpen = false;
    mMtuSize           = kInitialMtuSize;

    if (!IsConnected() && mConnectCallback != nullptr)
    {
        mConnectCallback(&GetInstance(), false, mBleConnectionOpen, mContext);
    }

    Disconnect(); // Stop TLS connection attempt from client if still running

    return kErrorNone;
}

void BleSecure::HandleTlsConnected(void *aContext, bool aConnected)
{
    return static_cast<BleSecure *>(aContext)->HandleTlsConnected(aConnected);
}

void BleSecure::HandleTlsConnected(bool aConnected)
{
    if (aConnected)
    {
        if (mReceivedMessage == nullptr)
        {
            mReceivedMessage = Get<MessagePool>().Allocate(Message::kTypeBle);
        }

        if (mSentMessage == nullptr)
        {
            mSentMessage = Get<MessagePool>().Allocate(Message::kTypeBle);
        }
    }
    else
    {
        FreeMessage(mReceivedMessage);
        mReceivedMessage = nullptr;
        FreeMessage(mSentMessage);
        mSentMessage = nullptr;
    }

    if (mConnectCallback != nullptr)
    {
        mConnectCallback(&GetInstance(), aConnected, mBleConnectionOpen, mContext);
    }
}

void BleSecure::HandleTlsReceive(void *aContext, uint8_t *aBuf, uint16_t aLength)
{
    return static_cast<BleSecure *>(aContext)->HandleTlsReceive(aBuf, aLength);
}

void BleSecure::HandleTlsReceive(uint8_t *aBuf, uint16_t aLength)
{
    VerifyOrExit(mReceivedMessage != nullptr);

    if (mTlvMode)
    {
        ot::Tlv  tlv;
        uint32_t requiredBytes = sizeof(Tlv);
        uint32_t offset;

        while (aLength > 0)
        {
            if (mReceivedMessage->GetLength() < requiredBytes)
            {
                uint32_t missingBytes = requiredBytes - mReceivedMessage->GetLength();

                if (missingBytes > aLength)
                {
                    SuccessOrExit(mReceivedMessage->AppendBytes(aBuf, aLength));
                    break;
                }
                else
                {
                    SuccessOrExit(mReceivedMessage->AppendBytes(aBuf, missingBytes));
                    aLength -= missingBytes;
                    aBuf += missingBytes;
                }
            }

            mReceivedMessage->Read(0, tlv);

            if (tlv.IsExtended())
            {
                ot::ExtendedTlv extTlv;
                requiredBytes = sizeof(extTlv);

                if (mReceivedMessage->GetLength() < requiredBytes)
                    continue;

                mReceivedMessage->Read(0, extTlv);
                requiredBytes = extTlv.GetSize();
                offset        = sizeof(extTlv);
            }
            else
            {
                requiredBytes = tlv.GetSize();
                offset        = sizeof(tlv);
            }

            if (mReceivedMessage->GetLength() < requiredBytes)
                continue;

            // TLV fully loaded

            if (mTcatAgent.IsEnabled() && mSentMessage != nullptr)
            {
                if (mSentMessage != nullptr)
                {
                    Error error = mTcatAgent.HandleSingleTlv(*mReceivedMessage, *mSentMessage, mTls);
                    Flush();

                    if (error == kErrorNotTmf && mReceiveCallback != nullptr)
                    {
                        mReceivedMessage->SetOffset(offset);
                        mReceiveCallback(&GetInstance(), mReceivedMessage, mContext);
                    }
                }
            }
            else if (mReceiveCallback != nullptr)
            {
                mReceivedMessage->SetOffset(offset);
                mReceiveCallback(&GetInstance(), mReceivedMessage, mContext);
            }

            SuccessOrExit(mReceivedMessage->SetLength(0)); // also sets the offset to 0
            requiredBytes = sizeof(Tlv);
        }
    }
    else
    {
        SuccessOrExit(mReceivedMessage->AppendBytes(aBuf, aLength));

        if (mReceiveCallback != nullptr)
        {
            mReceiveCallback(&GetInstance(), mReceivedMessage, mContext);
        }

        mReceivedMessage->SetLength(0);
    }

exit:;
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
    uint16_t         len    = aMessage.GetLength();
    uint16_t         offset = 0;
    otError          error  = OT_ERROR_NONE;

    while (len > 0)
    {
        if (len <= mMtuSize - kGattOverhead)
            packet.mLength = len;
        else
            packet.mLength = mMtuSize - kGattOverhead;

        if (packet.mLength > kPacketBufferSize)
            packet.mLength = kPacketBufferSize;

        aMessage.Read(offset, mPacketBuffer, packet.mLength);
        packet.mValue = mPacketBuffer;
        packet.mPower = 0;

        error = otPlatBleGattServerIndicate(&GetInstance(), kTxBleHandle, &packet);
        if (error != OT_ERROR_NONE)
            break;

        len -= packet.mLength;
        offset += packet.mLength;
    }

    // if(error != OT_ERROR_NONE)  --> close connection?  Not free message?

    aMessage.Free();
    return kErrorNone;
}

} // namespace Ble
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE
