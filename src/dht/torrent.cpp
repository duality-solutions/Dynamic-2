// Copyright (c) 2020-present Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dht/torrent.h"

#include "bdap/utils.h"
#include "dht/vgp.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "utfcore.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <libtorrent/bencode.hpp>
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
    payloadNewFormat["msg"] = stringFromVch(vchMessage);
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
    int k = 0;
    for (libtorrent::entry *dm : dmsToSend) {
        libtorrent::entry v;
        if(!CreateSignedMessage(v, vchFrom, k, "", dm, nullptr, std::string(""), 0)) {
            strErrorMessage = "CBdapTorrent::NewDirectMessage -- CreateSignedMessage failed." + strErrorMessage;
            return false;
        }
    }

    return true;
}

bool CBdapTorrent::CreateSignedMessage(libtorrent::entry& v, const std::vector<unsigned char>& vchUserFQDN, int k,
                          const std::string& msg,
                          const libtorrent::entry* ent, const libtorrent::entry* sig_rtfav,
                          const std::string& reply_n, int reply_k)
{
    std::string username = stringFromVch(vchUserFQDN);

    libtorrent::entry& directmessage = v["userpost"];

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

    if(reply_n.size()) {
        libtorrent::entry &reply = directmessage["reply"];
        reply["n"]=reply_n;
        reply["k"]=reply_k;
    }
    return true;
    //
    /*
    std::vector<char> buf;
    bencode(std::back_inserter(buf), directmessage);
    std::string sig = CreateSignature(std::string(buf.data(),buf.size()), username);
    if(sig.size()) {
        v["sig_directmessage"] = sig;
        return true;
    } else {
        return false;
    }

    
    // TODO: Add startTorrentUser
    torrent_handle h = startTorrentUser(strFrom, true);
    if( h.is_valid() ) {
        h.add_piece(k++,buf.data(),buf.size());
    }
    */
    
}
/*
std::string CBdapTorrent::CreateSignature(const std::string& strMessage, CKeyID& keyID)
{
    if (pwalletMain->IsLocked()) {
        printf("createSignature: Error please enter the wallet passphrase with walletpassphrase first.\n");
        return std::string();
    }

    CKey key;
    if (!pwalletMain->GetKey(keyID, key)) {
        printf("createSignature: private key not available for given keyid.\n");
        return std::string();
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        LogPrintf("CBdapTorrent::%s: sign failed.\n", __func__);
        return std::string();
    }

    return std::string((const char *)&vchSig[0], vchSig.size());
}


bool CBdapTorrent::VerifySignature(const std::string& strMessage, const std::string& strUserFQDN, const std::string& strSign, int maxHeight)
{
    CPubKey pubkey;
    if(!getUserPubKey(strUsername, pubkey, maxHeight) ) {
      printf("verifySignature: no pubkey for user '%s'\n", strUsername.c_str());
      return false;
    }

    vector<unsigned char> vchSig((const unsigned char*)strSign.data(),
                                 (const unsigned char*)strSign.data() + strSign.size());

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkeyRec;
    if (!pubkeyRec.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkeyRec.GetID() == pubkey.GetID());
}
*/