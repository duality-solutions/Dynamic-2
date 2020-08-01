// Copyright (c) 2020-present Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>

namespace libtorrent {
    class entry;
}
class CKeyID;

class CBdapTorrent
{
public:
    std::string strErrorMessage;

    CBdapTorrent() {}

    bool CreateDirectMessage(libtorrent::entry& dm, const std::vector<unsigned char>& vchSharedPubKey, const std::vector<unsigned char>& vchMessage);
    bool NewDirectMessage(const std::vector<unsigned char>& vchFrom, const std::vector<unsigned char>& vchTo, const std::vector<unsigned char>& vchMessage);
    bool CreateSignedMessage(libtorrent::entry& v, const std::vector<unsigned char>& vchUserFQDN, int k,
                          const std::string& msg,
                          const libtorrent::entry* ent, const libtorrent::entry* sig_rtfav,
                          const std::string& reply_n = "", int reply_k = 0);
    std::string CreateSignature(const std::string& strMessage, CKeyID& keyID);
    bool VerifySignature(const std::string& strMessage, const std::string& strUserFQDN, const std::string& strSign, int maxHeight);
};
