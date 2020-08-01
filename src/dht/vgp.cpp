// Copyright (c) 2020-present Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dht/vgp.h"

#include "bdap/vgp/include/encryption.h" // for VGP E2E encryption
#include "util.h"

bool VgpEncrypt(const std::vector<std::vector<unsigned char>>& vvchPubKeys, const std::vector<unsigned char>& vchValue, std::vector<unsigned char>& vchEncrypted, std::string& strErrorMessage) 
{
    try {
        if (!EncryptBDAPData(vvchPubKeys, vchValue, vchEncrypted, strErrorMessage))
            return false;

        return true;
    }
    catch (std::bad_alloc const&) {
        LogPrintf("%s -- catch std::bad_alloc\n", __func__);
        return false;
    }
}

bool VgpDecrypt(const std::vector<unsigned char>& vchPrivSeedBytes, const std::vector<unsigned char>& vchData, std::vector<unsigned char>& vchDecrypted, std::string& strErrorMessage)
{
    try {
        if (!DecryptBDAPData(vchPrivSeedBytes, vchData, vchDecrypted, strErrorMessage))
            return false;

        return true;
    }
    catch (std::bad_alloc const&) {
        LogPrintf("%s -- catch std::bad_alloc\n", __func__);
        return false;
    }
}