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
 *  This file implements the TCAT Agent service.
 */

#ifndef TCAT_AGENT_HPP_
#define TCAT_AGENT_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#include <openthread/ble_secure.h>

#include "common/as_core_type.hpp"
#include "common/locator.hpp"
#include "common/log.hpp"
#include "common/message.hpp"
#include "common/non_copyable.hpp"
#include "mac/mac_types.hpp"
#include "meshcop/dtls.hpp"
#include "meshcop/meshcop.hpp"
#include "meshcop/meshcop_tlvs.hpp"

namespace ot {

namespace MeshCoP {

class TcatAgent : public InstanceLocator, private NonCopyable
{
public:
    /**
     * This function pointer is called to notify the completion of a join operation.
     *
     * Please see otHandleTcatJoin for details.
     *
     */
    typedef otHandleTcatJoin JoinCallback;

    /**
     * This structure represents a TCAT elevation PSK.
     *
     * Please see otTcatElevationPsk for details.
     *
     */
    typedef otTcatElevationPsk ElevationPsk;

    /**
     * This structure represents the TCAT vendor information.
     *
     */
    class VendorInfo : public otTcatVendorInfo
    {
    public:
        /**
         * This method validates whether the TCAT vendor information is valid.
         *
         * @returns Whether the parameters are valid.
         *
         */
        bool IsValid(void) const;
    };

    /**
     * TCAT TLV Types.
     *
     */
    enum TlvType : uint8_t
    {
        kCommand       = OT_TCAT_TLV_COMMAND,        ///< Command TLV
        kResponse      = OT_TCAT_TLV_RESPONSE,       ///< Response TLV
        kActiveDataset = OT_TCAT_TLV_ACTIVE_DATASET, ///< Active Dataset TLV
        kApplication   = OT_TCAT_TLV_APPLICATION,    ///< Application TLV
    };

    /**
     * TCAT Command Types.
     *
     */
    enum CommandType : uint8_t
    {
        kTerminate   = OT_TCAT_COMMAND_TERMINATE,    ///< Terminate connection
        kThreadStart = OT_TCAT_COMMAND_THREAD_START, ///< Start Thread Interface
        kThreadStop  = OT_TCAT_COMMAND_THREAD_STOP,  ///< Stop Thread Interface
    };

    /**
     * TCAT Response Types.
     *
     */
    enum ResponseType : uint8_t
    {
        kSuccess      = OT_TCAT_RESPONSE_SUCCESS,       ///< Success
        kInvalidState = OT_TCAT_RESPONSE_INVALID_STATE, ///< Invalid State
        kParseError   = OT_TCAT_RESPONSE_PARSE_ERROR,   ///< Invalid State
    };

    /**
     * This constructor initializes the Joiner object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     *
     */
    explicit TcatAgent(Instance &aInstance);

    /**
     * Enables the TCAT protocol.
     *
     * @retval kErrorNone           Successfully started the TCAT agent.
     * @retval kErrorInvalidArgs    The aElevationPsk or the aVendorInfo is invalid.
     *
     */
    Error Start(const char *aElevationPsk, VendorInfo *aVendorInfo, JoinCallback aHandler);

    /**
     * This method stops the TCAT protocol.
     *
     */
    void Stop(void);

    /**
     * This method indicates whether or not the TCAT agent is enabled.
     *
     * @retval TRUE   The TCAT agent is enabled.
     * @retval FALSE  The TCAT agent is not enabled.
     *
     */
    bool IsEnabled(void) const { return mEnabled; }

    /**
     * This method indicates whether or not the TCAT session has elevated rights.
     *
     * @retval TRUE   The TCAT session has elevated rights.
     * @retval FALSE  The TCAT session does not have elevated rights.
     *
     */
    bool IsElevated(void) const { return mElevated; }

    /**
     * This method processes an incoming TCAT TLV.
     *
     * @retval kErrorNone           Successfully processed.
     * @retval kErrorInvalidArgs    The invalid argument value.
     * @retval kErrorParse          The incoming meassge could not be parsed.
     * @retval kErrorNotTmf         The incoming message was an application TLV.
     *
     */
    Error HandleSingleTlv(ot::Message &aIncommingMessage, ot::Message &aOutgoingMessage, MeshCoP::Dtls &aTlsContext);

private:
    Error HandleCommand(CommandType aCommand, ot::Message &aOutgoingMessage, MeshCoP::Dtls &aTlsContext);
    Error HandleActiveDataset(ot::Message   &aIncommingMessage,
                              uint16_t       aOffset,
                              uint16_t       aLength,
                              MeshCoP::Dtls &aTlsContext);

    static constexpr uint16_t kJoinerUdpPort = OPENTHREAD_CONFIG_JOINER_UDP_PORT;

    ElevationPsk mElevationPsk;
    VendorInfo  *mVendorInfo;
    JoinCallback mJoinCallback;
    bool         mEnabled;
    bool         mElevated;
};

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#endif // TCAT_AGENT_HPP_
