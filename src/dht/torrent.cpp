// Copyright (c) 2020-present Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dht/torrent.h"

#include "bdap/domainentry.h"
#include "bdap/domainentrydb.h"
#include "bdap/utils.h"
#include "dht/ed25519.h"
#include "dht/vgp.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "utfcore.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <libtorrent/bencode.hpp>
#include <libtorrent/ed25519.hpp>
#include <libtorrent/entry.hpp>

#include <list>

bool CBdapTorrent::CreateDirectMessage(libtorrent::entry& dm, const std::vector<unsigned char>& vchSharedPubKey, const std::vector<unsigned char>& vchMessage)
{
    std::vector<std::vector<unsigned char>> vvchPubKeys;
    vvchPubKeys.push_back(vchSharedPubKey);
    std::vector<unsigned char> vchEncryptedMessage;
    if (VgpEncrypt(vvchPubKeys, vchMessage, vchEncryptedMessage, strErrorMessage))
        return false;

    dm["key"] = stringFromVch(vchSharedPubKey);
    dm["orig"] = vchMessage.size();
    dm["body"] = stringFromVch(vchEncryptedMessage);

    return true;
}

bool CBdapTorrent::NewDirectMessage(const std::vector<unsigned char>& vchFrom, const std::vector<unsigned char>& vchTo, const std::vector<unsigned char>& vchMessage)
{
    // EnsureWalletIsUnlocked();
    std::list<libtorrent::entry *> dmsToSend;
    libtorrent::entry payloadNewFormat;
    std::string strMsg = stringFromVch(vchMessage);
    payloadNewFormat["msg"] = strMsg;
    payloadNewFormat["to"]  = stringFromVch(vchTo);
    std::vector<char> payloadbuf;

    bencode(std::back_inserter(payloadbuf), payloadNewFormat);
    std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

    libtorrent::entry dmRcpt;
    if(!CreateDirectMessage(dmRcpt, vchTo, vchMessage)) {
        strErrorMessage = "CBdapTorrent::NewDirectMessage -- dmRcpt CreateDirectMessage falied: " + strErrorMessage;
        return false;
    }

    libtorrent::entry dmSelf;
    if(!CreateDirectMessage(dmSelf, vchFrom, vchMessage)) {
        strErrorMessage = "CBdapTorrent::NewDirectMessage -- dmSelf CreateDirectMessage falied: " + strErrorMessage;
        return false;
    }

    if(GetRandInt(9) % 2) {
        dmsToSend.push_back(&dmRcpt);
        dmsToSend.push_back(&dmSelf);
    } else {
        dmsToSend.push_back(&dmSelf);
        dmsToSend.push_back(&dmRcpt);
    }

    CDomainEntry fromDomainEntry;
    if (!GetDomainEntry(vchFrom, fromDomainEntry)) {
        strErrorMessage = strprintf("CBdapTorrent::%s -- %s account not found.", __func__, stringFromVch(vchFrom));
        return false;
    }
    for (libtorrent::entry *dm : dmsToSend) {
        libtorrent::entry v;
        if(!CreateSignedMessage(v, vchFrom, fromDomainEntry.DHTPublicKey, strMsg, dm)) {
            strErrorMessage = strprintf("CBdapTorrent::%s -- CreateSignedMessage failed. %s", __func__, strErrorMessage);
            return false;
        }
        std::vector<char> buf;
        bencode(std::back_inserter(buf), v);
        /*
        std::string errmsg;
        if(!AcceptSignedMessage(buf.data(), buf.size(), strFrom, k, errmsg, NULL)) {
            strErrorMessage = strprintf("CBdapTorrent::%s -- CreateSignedMessage failed. %s", __func__, errmsg);
            return false;
        }
        torrent_handle h = startTorrentUser(strFrom, true);
        if(h.is_valid()) {
            h.add_piece(k++,buf.data(),buf.size());
        }
        */
    }

    return true;
}

bool CBdapTorrent::CreateSignedMessage(libtorrent::entry& v, const std::vector<unsigned char>& vchUserFQDN, 
                        const std::vector<unsigned char>& vchPubKey,
                        const std::string& msg, const libtorrent::entry* ent)
{
    std::string username = stringFromVch(vchUserFQDN);
    CKeyEd25519 privKey;
    CKeyID pubKeyID = GetIdFromCharVector(vchPubKey);
    if (!pwalletMain->GetDHTKey(pubKeyID, privKey)) {
        strErrorMessage = strprintf("CBdapTorrent::%s GetDHTKey falied for account %s", __func__, username);
        return false;
    }

    libtorrent::entry& directmessage = v["usermessage"];

    directmessage["n"] = username;
    directmessage["k"] = k;
    directmessage["time"] = GetAdjustedTime();
    directmessage["height"] = chainActive.Height() - 1; // be conservative

    int msgUtf8Chars = utf8::num_characters(msg.begin(), msg.end());
    if(msgUtf8Chars < 0) {
        return false; // invalid utf8
    } else if (msgUtf8Chars && msgUtf8Chars <= 140) {
        directmessage["msg"] = msg;
    } else {
        // break into msg and msg2 fields to overcome 140ch checks
        std::string::const_iterator it = msg.begin();
        std::string::const_iterator end = msg.end();
        std::string msgOut, msg2Out;
        int count = 0;
        while (it!= end) {
            std::string::const_iterator itPrev = it;
            utf8::internal::utf_error err_code = utf8::internal::validate_next(it, end);
            assert(err_code == utf8::internal::UTF8_OK); // string must have been validated already
            count++;
            if(count <= 140) {
                msgOut.append(itPrev, it);
            } else {
                msg2Out.append(itPrev, it);
            }
        }
        directmessage["msg"] = msgOut;
        directmessage["msg2"] = msg2Out;
    }

    directmessage["dm"] = *ent;

    std::vector<char> buf;
    bencode(std::back_inserter(buf), directmessage);
    std::string sig = CreateTorrentSignature(std::string(buf.data(),buf.size()), privKey.GetPubKeyBytes(), privKey.GetPrivKeyBytes());
    if(sig.size()) {
        v["sig_directmessage"] = sig;
    } else {
        return false;
    }

    return true;
}

std::string CBdapTorrent::CreateTorrentSignature(const std::string& strMessage, const std::vector<unsigned char>& vchPubKey, const std::vector<unsigned char>& vchPrivKey) const
{
    std::vector<unsigned char> vchMsg = vchFromString(strMessage);
    std::vector<unsigned char> sig(64);
    libtorrent::ed25519_sign(&sig[0], &vchMsg[0], vchMsg.size(), &vchPubKey[0], &vchPrivKey[0]);
    return stringFromVch(sig);
}

bool CBdapTorrent::VerifyTorrentSignature(const std::string& strMessage, const std::string& strPubKey, const std::string& strSign) const
{
    std::vector<unsigned char> msg = vchFromString(strMessage);
    std::vector<unsigned char> sig = vchFromString(strSign);
    std::vector<unsigned char> vchPubKey = vchFromString(strPubKey);
    if (!libtorrent::ed25519_verify(&sig[0], &msg[0], msg.size(), &vchPubKey[0]))
        return false;

    return true;
}