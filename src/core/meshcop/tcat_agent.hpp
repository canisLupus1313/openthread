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

#include <openthread/tcat.h>

#include "common/as_core_type.hpp"
#include "common/callback.hpp"
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
     * This function pointer is called when application data was received over the TLS connection.
     *
     *  Please see otHandleTcatApplicationDataReceive for details.
     *
     */
    typedef otHandleTcatApplicationDataReceive AppDataReceiveCallback;

    /**
     * This function pointer is called to notify the completion of a join operation.
     *
     * Please see otHandleTcatJoin for details.
     *
     */
    typedef otHandleTcatJoin JoinCallback;

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
        // Command Class General
        kCommand                        = OT_TCAT_TLV_COMMAND,                          ///< TCAT command TLV   -->  !!!! OBSOLETE!!!!
        kResponseWithStatus             = OT_TCAT_TLV_RESPONSE_WITH_STATUS,             ///< TCAT response with status value TLV
        kResponseWithPayload            = OT_TCAT_TLV_RESPONSE_WITH_PAYLOAD,            ///< TCAT response with payload TLV
        kResponseEvent                  = OT_TCAT_TLV_RESPONSE_EVENT,                   ///< TCAT response event TLV (reserved)
        kGetNetworkName                 = OT_TCAT_TLV_GET_NETWORK_NAME,                 ///< TCAT network name query TLV
        kDisconnect                     = OT_TCAT_TLV_DISCONNECT,                       ///< TCAT disconnect request TLV
        kPing                           = OT_TCAT_TLV_PING,                             ///< TCAT ping request TLV
        kGetDeviceId                    = OT_TCAT_TLV_GET_DEVICE_ID,                    ///< TCAT device ID query TLV
        kGetExtendedPanID               = OT_TCAT_TLV_GET_EXTENDED_PAN_ID,              ///< TCAT extended PAN ID query TLV
        kPresentPskdHash                = OT_TCAT_TLV_PRESENT_PSKD_HASH,                ///< TCAT commissioner rights elevation request TLV using PSKd hash
        kPresentPskcHash                = OT_TCAT_TLV_PRESENT_PSKC_HASH,                ///< TCAT commissioner rights elevation request TLV using PSKc hash
        kPresentInstallCodeHash         = OT_TCAT_TLV_PRESENT_INSTALL_CODE_HASH,        ///< TCAT commissioner rights elevation request TLV using install code
        kRequestRandomNumChallenge      = OT_TCAT_TLV_REQUEST_RANDOM_NUM_CHALLENGE,     ///< TCAT random number challenge query TLV
        kRequestPskdHash                = OT_TCAT_TLV_REQUEST_PSKD_HASH,                ///< TCAT PSKd hash request TLV

        // Command Class Commissioning
        kSetActiveOperationalDataset    = OT_TCAT_TLV_SET_ACTIVE_OPERATIONAL_DATASET,   ///< TCAT active operational dataset TLV
        kSetActiveOperationalDataset1   = OT_TCAT_TLV_SET_ACTIVE_OPERATIONAL_DATASET1,  ///< TCAT active operational dataset alterative #1 TLV
        kGetProvissioningTlvs           = OT_TCAT_TLV_GET_PROVISIONING_TLVS,            ///< TCAT provisioning TLVs query TLV
        kGetCommissionerCertificate     = OT_TCAT_TLV_GET_COMMISSIONER_CERTIFICATE,     ///< TCAT commissioner certificate query TLV
        kGetDiagnosticTlvs              = OT_TCAT_TLV_GET_DIAGNOSTIC_TLVS,              ///< TCAT diagnostics TLVs query TLV
        kStartThreadInterface           = OT_TCAT_TLV_START_THREAD_INTERFACE,           ///< TCAT start thread interface request TLV
        kStopThreadInterface            = OT_TCAT_TLV_STOP_THREAD_INTERFACE,            ///< TCAT stop thread interface request TLV

        // Command Class Extraction
        kGetActiveOperationalDataset    = OT_TCAT_TLV_GET_ACTIVE_OPERATIONAL_DATASET,   ///< TCAT active oerational dataset query TLV
        kGetActiveOperationalDataset1   = OT_TCAT_TLV_GET_ACTIVE_OPERATIONAL_DATASET1,  ///< TCAT active oerational dataset alterative #1 query TLV

        // Command Class Decommissioning
        kDecommission                   = OT_TCAT_TLV_DECOMMISSION,                     ///< TCAT decommission request TLV

        // Command Class Application
        kSelectApplicationLayerUdp      = OT_TCAT_TLV_SELECT_APPLICATION_LAYER_UDP,     ///< TCAT select UDP protocol application layer request TLV
        kSelectApplicationLayerTcp      = OT_TCAT_TLV_SELECT_APPLICATION_LAYER_TCP,     ///< TCAT select TCP protocol application layer request TLV
        kSendApplicationData            = OT_TCAT_TLV_SEND_APPLICATION_DATA,            ///< TCAT send application data TLV
        kSendVendorSpecificData         = OT_TCAT_TLV_SEND_VENDOR_SPECIFIC_DATA,        ///< TCAT send vendor specific command or data TLV

        // Command Class CCM
        kSetLDevIdOperationalCert       = OT_TCAT_TLV_SET_LDEVID_OPERATIONAL_CERT,      ///< TCAT LDevID operational certificate TLV
        kSetLDevIdPrivateKey            = OT_TCAT_TLV_SET_LDEVID_PRIVATE_KEY,           ///< TCAT LDevID operational certificate pricate key TLV
        kSetDomainCaCert                = OT_TCAT_TLV_SET_DOMAIN_CA_CERT,               ///< TCAT domain CA certificate TLV
    };

    /**
     * TCAT Command Types.   --> OBSOLTE
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
    enum StatusCode: uint8_t
    {
        kSuccess      = OT_TCAT_STATUS_SUCCESS,         ///< Command or request was successfully processed
        kUnsupported  = OT_TCAT_STATUS_UNSUPPORTED,     ///< Requested command or received TLV is not supported
        kParseError   = OT_TCAT_STATUS_PARSE_ERROR,     ///< Request / command could not be parsed correctly
        kValueError   = OT_TCAT_STATUS_VALUE_ERROR,     ///< The value of the transmitted TLV has an error
        kGeneralError = OT_TCAT_STATUS_GENERAL_ERROR,   ///< An error not matching any other category occurred
        kBusy         = OT_TCAT_STATUS_BUSY,            ///< Command cannot be executed because the resource is busy
        kUndefined    = OT_TCAT_STATUS_UNDEFINED,       ///< The requested value, data or service is not defined (currently) or not present
        kHashError    = OT_TCAT_STATUS_HASH_ERROR,      ///< The hash value presented by the commissioner was incorrect
        kUnauthorized = OT_TCAT_STATUS_UNAUTHORIZED,    ///< Sender does not have sufficient authorization for the given command
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
     * @retval kErrorInvalidArgs    The aJoinerPsk or the aVendorInfo is invalid.
     *
     */
    Error Start(VendorInfo *aVendorInfo, AppDataReceiveCallback aAppDataReceiveCallback, JoinCallback aHandler, void* aContext);

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
     * This method indicates whether or not the TCAT session has verified the commissioner is in possesion of PSKd.
     *
     * @retval TRUE   The TCAT session has verified PSKd.
     * @retval FALSE  The TCAT session does not verified PSKd.
     *
     */
    bool IsPskdVerified(void) const { return mPskdVerified; }

    /**
     * This method indicates whether or not the TCAT session has verified the commissioner is in possesion of PSKc.
     *
     * @retval TRUE   The TCAT session has verified PSKc.
     * @retval FALSE  The TCAT session does not verified PSKc.
     *
     */
    bool IsPskcVerified(void) const { return mPskcVerified; }

    /**
     * This method processes an incoming TCAT TLV.
     *
     * @retval kErrorNone           Successfully processed.
     * @retval kErrorInvalidArgs    The invalid argument value.
     * @retval kErrorParse          The incoming meassge could not be parsed.
     * @retval kErrorAbort          The incoming message was a request for terminating the TCAT link.
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

    JoinerPskd                        mJoinerPskd;
    VendorInfo*                       mVendorInfo;   
    Callback<JoinCallback>            mJoinCallback;
    Callback<AppDataReceiveCallback>  mAppDataReceiveCallback; 
    bool                              mEnabled : 1;
    bool                              mPskdVerified : 1;
    bool                              mPskcVerified : 1;
};

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#endif // TCAT_AGENT_HPP_
